import logging
import re
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger("docker_patch_tool")


def _resolve_variable(value: str, args: Optional[Dict[str, str]]) -> str:
    """
    Resolve Docker ARG variables in a string using provided argument values.

    Handles format: $VAR_NAME or ${VAR_NAME}

    Args:
        value: String potentially containing variable references
        args: Dict mapping ARG names to their values, or None

    Returns:
        String with variables resolved to their values, or original if not found
    """
    if not args:
        return value

    # Handle ${VAR_NAME} format
    def replace_braced(match):
        var_name = match.group(1)
        return args.get(var_name, match.group(0))

    value = re.sub(r'\$\{([A-Za-z_][A-Za-z0-9_]*)\}', replace_braced, value)

    # Handle $VAR_NAME format (word boundary)
    def replace_unbraced(match):
        var_name = match.group(1)
        return args.get(var_name, match.group(0))

    value = re.sub(r'\$([A-Za-z_][A-Za-z0-9_]*)\b', replace_unbraced, value)

    return value


def _extract_copy_from_references(lines: List[str]) -> Set[str]:
    """
    Extract all stage names referenced by COPY --from= instructions.

    Args:
        lines: List of Dockerfile lines

    Returns:
        Set of stage names referenced in COPY --from= directives
    """
    copy_from_refs = set()

    for line in lines:
        # Skip empty lines and comments
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue

        # Handle continuation lines (backslash)
        # For now, simple regex to find --from= anywhere in COPY lines
        if stripped.upper().startswith('COPY'):
            # Match --from=stage_name or --from="stage_name"
            matches = re.findall(r'--from=([^\s"]+)(?:\s|$|")', stripped, re.IGNORECASE)
            for match in matches:
                copy_from_refs.add(match)

    return copy_from_refs


def _is_continuation_line(line: str) -> bool:
    """
    Check if a line ends with a backslash continuation.

    Args:
        line: A Dockerfile line

    Returns:
        True if the line ends with a backslash continuation
    """
    # Remove trailing whitespace but check for backslash before it
    stripped = line.rstrip()
    return stripped.endswith('\\')


def _split_from_line(line: str) -> Tuple[str, str]:
    """
    Split a FROM line into the instruction part and any trailing comment.

    Handles inline comments (text after #) and preserves the comment.
    Does not split if # appears within quotes.

    Args:
        line: A FROM instruction line

    Returns:
        Tuple of (line_without_comment, comment_with_hash)
    """
    # Simple approach: find first # not in quotes
    in_double = False
    in_single = False
    for i, char in enumerate(line):
        if char == '"' and not in_single:
            in_double = not in_double
        elif char == "'" and not in_double:
            in_single = not in_single
        elif char == '#' and not in_double and not in_single:
            return line[:i].rstrip(), line[i:]

    return line.rstrip(), ""


def parse_dockerfile_stages(
    dockerfile_text: str,
    args: Optional[Dict[str, str]] = None
) -> List[Dict]:
    """
    Parse a Dockerfile into a list of build stages.

    Handles:
    - FROM image:tag
    - FROM image@sha256:digest
    - FROM scratch
    - FROM $ARG_VAR (resolves using provided args dict)
    - Multi-stage builds with stage aliases
    - COPY --from= references
    - Inline comments and continuation lines
    - Preserves all lines including blank lines and comments between stages

    Args:
        dockerfile_text: The complete Dockerfile content as a string
        args: Optional dict mapping ARG names to their values for resolving $VAR references

    Returns:
        List of stage dicts, each containing:
        - 'from_line': The original FROM line (with any inline comment)
        - 'base_image': Base image reference as written (may include $VAR before resolution)
        - 'base_name': Resolved base image name/repository or stage alias
        - 'base_tag': Tag string, 'latest' for untagged, None for digest or scratch
        - 'is_scratch': True if FROM scratch
        - 'alias': Stage alias name if "AS alias" present, else None
        - 'is_stage_alias': True if base_image references a previous stage
        - 'copy_from_refs': Set of stage names referenced by COPY --from= in this stage
        - 'start_index': Line index of FROM instruction
        - 'end_index': Line index of last line in this stage
        - 'lines': List of all non-FROM lines in this stage (preserves blanks, comments)
        - 'comment': Trailing comment on FROM line (including the '#'), or empty string
    """
    lines = dockerfile_text.splitlines()
    stages = []
    known_aliases: Set[str] = set()
    current_stage: Optional[Dict] = None

    for i, line in enumerate(lines):
        stripped = line.strip()

        # Look for FROM instruction (case-insensitive)
        if not stripped.lower().startswith("from"):
            continue

        # Finalize the previous stage if one exists
        if current_stage is not None:
            current_stage['end_index'] = i - 1
            # Capture all lines between FROM and next FROM (or end of file)
            if current_stage['start_index'] + 1 <= current_stage['end_index']:
                current_stage['lines'] = lines[current_stage['start_index'] + 1 : current_stage['end_index'] + 1]
            else:
                current_stage['lines'] = []
            stages.append(current_stage)
            current_stage = None

        # Parse this FROM line
        line_no_comment, comment = _split_from_line(line)
        parts = line_no_comment.split()

        # Validate FROM instruction
        if len(parts) < 2 or parts[0].lower() != "from":
            continue

        image_ref = parts[1]

        # Resolve variables in image reference
        resolved_image_ref = _resolve_variable(image_ref, args)

        # Extract alias if present
        alias_name: Optional[str] = None
        if len(parts) >= 4 and parts[2].lower() == "as":
            alias_name = parts[3]

        # Determine if this is a scratch image
        is_scratch = resolved_image_ref.lower() == "scratch"

        # Determine if base refers to a previous stage
        is_stage_alias = resolved_image_ref in known_aliases

        # Parse base image name and tag
        base_name = resolved_image_ref
        base_tag: Optional[str] = None

        if is_scratch:
            base_name = "scratch"
            base_tag = None
        elif is_stage_alias:
            # Reference to a previous stage
            base_name = resolved_image_ref
            base_tag = None
        else:
            # External image reference
            if "@" in resolved_image_ref:
                # Digest format: image@sha256:...
                base_name = resolved_image_ref.split("@")[0].strip()
                base_tag = None
            elif ":" in resolved_image_ref:
                # Tag format: image:tag
                base_name, base_tag = resolved_image_ref.split(":", 1)
                base_name = base_name.strip()
                base_tag = base_tag.strip()
            else:
                # No tag or digest specified
                base_name = resolved_image_ref.strip()
                base_tag = "latest"

        # Extract COPY --from= references from this stage's lines
        # (we'll update this after capturing the stage's lines)
        copy_from_refs: Set[str] = set()

        # Create stage entry
        current_stage = {
            'from_line': line,
            'base_image': image_ref,  # Keep original (may have $VAR)
            'base_name': base_name,
            'base_tag': base_tag,
            'is_scratch': is_scratch,
            'alias': alias_name,
            'is_stage_alias': is_stage_alias,
            'copy_from_refs': copy_from_refs,
            'start_index': i,
            'comment': comment
        }

        # Track this stage's alias for future references
        if alias_name:
            known_aliases.add(alias_name)

    # Finalize the last stage
    if current_stage is not None:
        current_stage['end_index'] = len(lines) - 1
        if current_stage['start_index'] + 1 <= current_stage['end_index']:
            current_stage['lines'] = lines[current_stage['start_index'] + 1 : current_stage['end_index'] + 1]
        else:
            current_stage['lines'] = []
        stages.append(current_stage)

    # Post-process: extract COPY --from= references for each stage
    for stage in stages:
        stage['copy_from_refs'] = _extract_copy_from_references(stage['lines'])

    return stages
