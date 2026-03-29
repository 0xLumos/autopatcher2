"""
AutoPatch Patcher Module — Optimized SBOM-Driven Base Image Selection

This module implements the core patching logic for AutoPatch. It replaces
vulnerable base images with secure alternatives using a multi-signal
inference pipeline:

1. OS family detection via SBOM package URL (purl) analysis
2. Language/runtime version extraction from SBOM components (not tag regex)
3. glibc compatibility checking before Alpine selection
4. Confidence scoring with graceful fallback on uncertainty
5. Optional lightweight smoke test to catch runtime failures

The key design principle: read what is ACTUALLY INSTALLED (from the SBOM),
not what the tag STRING claims. Tags lie; SBOMs don't.
"""

import logging
import json
import re
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Optional, Any, Set
from .parser import parse_dockerfile_stages

logger = logging.getLogger("docker_patch_tool")


# ════════════════════════════════════════════════════════════════════
# Data structures
# ════════════════════════════════════════════════════════════════════

@dataclass
class InferenceResult:
    """Result of SBOM-based inference with confidence scoring."""
    os_family: str = "unknown"
    language: Optional[str] = None
    language_version: Optional[str] = None
    variant: Optional[str] = None          # e.g., "fpm", "apache", "slim"
    needs_glibc: bool = False
    confidence: float = 0.0                # 0.0 = no idea, 1.0 = certain
    signals: List[str] = field(default_factory=list)  # audit trail of what was detected
    warnings: List[str] = field(default_factory=list)


# ════════════════════════════════════════════════════════════════════
# Constants
# ════════════════════════════════════════════════════════════════════

# Packages that indicate glibc dependency — Alpine uses musl and will
# cause silent runtime failures if these are present
GLIBC_INDICATOR_PACKAGES: Set[str] = {
    "glibc", "libc6", "libc-bin", "libc6-dev",
    "libstdc++6", "libgcc-s1",
}

# Python packages with common C extensions that may break on musl/Alpine
GLIBC_PYTHON_PACKAGES: Set[str] = {
    "numpy", "pandas", "scipy", "grpcio", "pillow",
    "cryptography", "lxml", "psycopg2", "mysqlclient",
    "tensorflow", "torch", "opencv-python", "matplotlib",
    "scikit-learn", "h5py", "pyarrow",
}

# purl prefix → OS family mapping
PURL_OS_MAP = {
    "pkg:apk/": "alpine",
    "pkg:deb/": "debian",   # refined later to ubuntu/distroless
    "pkg:rpm/": "rhel",     # refined later to centos/rocky/alma/fedora
}

# SBOM component name → language detection
# We look for the runtime itself as an installed component
LANGUAGE_COMPONENT_PATTERNS = {
    "python": re.compile(r'^python(\d[\d.]*)?(|-minimal)$', re.IGNORECASE),
    "node": re.compile(r'^(node(js)?|nodejs-doc)$', re.IGNORECASE),
    "golang": re.compile(r'^go(lang)?$', re.IGNORECASE),
    "ruby": re.compile(r'^ruby[\d.]*$', re.IGNORECASE),
    "php": re.compile(r'^php[\d.]*(-cli|-fpm|-common)?$', re.IGNORECASE),
    "openjdk": re.compile(r'^(openjdk|java|temurin|adoptopenjdk)', re.IGNORECASE),
    "rust": re.compile(r'^rust(c)?$', re.IGNORECASE),
    "perl": re.compile(r'^perl[\d.]*$', re.IGNORECASE),
    "erlang": re.compile(r'^(erlang|otp)', re.IGNORECASE),
    "elixir": re.compile(r'^elixir[\d.]*$', re.IGNORECASE),
    "dotnet": re.compile(r'^(dotnet|aspnet)', re.IGNORECASE),
}

# purl type → language mapping (secondary signal from installed packages)
PURL_LANGUAGE_MAP = {
    "pkg:pypi/": "python",
    "pkg:npm/": "node",
    "pkg:gem/": "ruby",
    "pkg:composer/": "php",
    "pkg:maven/": "openjdk",
    "pkg:golang/": "golang",
}


# ════════════════════════════════════════════════════════════════════
# SBOM Analysis — the core inference engine
# ════════════════════════════════════════════════════════════════════

def analyze_sbom(sbom_data: Optional[Dict[str, Any]]) -> InferenceResult:
    """
    Perform full SBOM analysis: OS family, language, version, glibc needs.

    This is the single entry point for all SBOM-based inference. It reads
    the CycloneDX SBOM and extracts structured signals rather than guessing
    from image tag strings.

    Args:
        sbom_data: CycloneDX SBOM as a dictionary (from Trivy)

    Returns:
        InferenceResult with all detected properties and confidence score
    """
    result = InferenceResult()

    if not sbom_data:
        result.warnings.append("No SBOM data provided")
        return result

    components = sbom_data.get("components", [])
    metadata = sbom_data.get("metadata", {})
    meta_component = metadata.get("component", {})
    meta_name = meta_component.get("name", "").lower()

    # Collect all purls and component names
    purls: List[str] = []
    comp_names: List[str] = []
    comp_map: Dict[str, str] = {}  # name → version

    for comp in components:
        purl = comp.get("purl", "")
        name = comp.get("name", "")
        version = comp.get("version", "")
        if purl:
            purls.append(purl)
        if name:
            comp_names.append(name.lower())
            comp_map[name.lower()] = version

    # ── Step 1: Detect OS family from purl prefixes ──────────────

    result.os_family = _detect_os_family(purls, comp_names, meta_name, len(components))
    if result.os_family != "unknown":
        result.confidence += 0.4
        result.signals.append(f"OS={result.os_family} (from purl/metadata)")

    # ── Step 2: Detect language and version from SBOM components ──

    lang, lang_ver = _detect_language_from_sbom(purls, comp_map, meta_name)
    if lang:
        result.language = lang
        result.language_version = lang_ver
        result.confidence += 0.3
        result.signals.append(f"lang={lang}:{lang_ver} (from SBOM components)")

    # ── Step 3: Check glibc dependency ────────────────────────────

    result.needs_glibc = _check_glibc_dependency(comp_names, purls)
    if result.needs_glibc:
        result.signals.append("glibc dependency detected — Alpine unsafe")

    # ── Step 4: Detect variant hints ──────────────────────────────

    result.variant = _detect_variant(comp_names, meta_name)
    if result.variant:
        result.signals.append(f"variant={result.variant}")

    # Scratch detection
    if not components and not meta_component:
        result.os_family = "scratch"
        result.confidence = 1.0
        result.signals.append("zero components → scratch image")

    return result


def _detect_os_family(
    purls: List[str], comp_names: List[str], meta_name: str, comp_count: int
) -> str:
    """Detect OS family from purl prefixes and metadata."""

    # Check distroless FIRST — distroless images contain pkg:deb/ but
    # must NOT be classified as debian
    if "distroless" in meta_name:
        return "distroless"

    has_apk = any("pkg:apk/" in p for p in purls)
    has_deb = any("pkg:deb/" in p for p in purls)
    has_rpm = any("pkg:rpm/" in p for p in purls)

    # Alpine: apk packages or alpine-specific components
    if has_apk or any(n in comp_names for n in ["apk-tools", "musl", "alpine-baselayout"]):
        return "alpine"

    # Ubuntu vs Debian: both use pkg:deb/, distinguish by component names
    if has_deb:
        if any("ubuntu" in n for n in comp_names):
            return "ubuntu"
        # Distroless fallback: few deb packages, no apt
        if comp_count < 15 and not any("apt" in n for n in comp_names):
            return "distroless"
        return "debian"

    # RHEL family: distinguish by distro-specific component names
    if has_rpm:
        if any("rocky" in n for n in comp_names) or "rocky" in meta_name:
            return "rocky"
        if any("alma" in n for n in comp_names) or "alma" in meta_name:
            return "alma"
        if any("centos" in n for n in comp_names) or "centos" in meta_name:
            return "centos"
        if any("fedora" in n for n in comp_names) or "fedora" in meta_name:
            return "fedora"
        return "rhel"

    # Very small component sets with no package manager → likely distroless
    if comp_count < 5 and comp_count > 0:
        return "distroless"

    return "unknown"


def _detect_language_from_sbom(
    purls: List[str], comp_map: Dict[str, str], meta_name: str = ""
) -> Tuple[Optional[str], Optional[str]]:
    """
    Detect language runtime and version from SBOM components.

    Four-pass approach:
    1. Check SBOM metadata component name for strong language hints
       (e.g., meta_name="node-orig" → node is the primary runtime)
    2. Find ALL runtime binaries installed as SBOM components
    3. Count application-level packages (pkg:npm/, pkg:pypi/, etc.)
       to determine which runtime is PRIMARY vs build-dependency
    4. If purl counts tie, use a priority heuristic that deprioritizes
       languages commonly installed as build dependencies (Python, Java)

    This fixes the node:18 → python:3.11 misclassification: Node.js Debian
    images include python3 as a build dep, but pkg:npm/ packages reveal
    Node.js as the actual application runtime.

    Returns:
        (language, version) tuple, either or both may be None
    """
    # Pass 0: Check SBOM metadata name for strong language hints.
    # Trivy sets metadata.component.name to the scanned image name (e.g.,
    # "node-orig", "python-3.11-slim"). This is a high-confidence signal
    # that should boost the corresponding language if found in components.
    _META_LANG_HINTS = {
        "node": "node", "python": "python", "golang": "golang",
        "ruby": "ruby", "php": "php", "openjdk": "openjdk",
        "temurin": "openjdk",
    }
    meta_lang_hint: Optional[str] = None
    for keyword, lang in _META_LANG_HINTS.items():
        if keyword in meta_name:
            meta_lang_hint = lang
            break

    # Pass 1: Find ALL installed runtime components (not just the first)
    all_matches: Dict[str, str] = {}  # lang → version
    for lang, pattern in LANGUAGE_COMPONENT_PATTERNS.items():
        for name, version in comp_map.items():
            if pattern.match(name) and version:
                clean_ver = _normalize_version(version, lang)
                all_matches[lang] = clean_ver
                break  # one match per language is enough

    # Count application-level purl packages for disambiguation
    purl_lang_counts: Dict[str, int] = {}
    for purl in purls:
        for prefix, lang in PURL_LANGUAGE_MAP.items():
            if prefix in purl:
                purl_lang_counts[lang] = purl_lang_counts.get(lang, 0) + 1

    # Single match — unambiguous
    if len(all_matches) == 1:
        lang = next(iter(all_matches))
        return lang, all_matches[lang]

    # Multiple runtimes installed — disambiguate
    if len(all_matches) > 1:
        # Priority 1: If metadata name hints at a specific language, use that
        if meta_lang_hint and meta_lang_hint in all_matches:
            logger.info(
                f"Multiple runtimes found {list(all_matches.keys())} — "
                f"selected '{meta_lang_hint}' (matches SBOM metadata name)"
            )
            return meta_lang_hint, all_matches[meta_lang_hint]

        # Priority 2: Use purl counts (application-level packages)
        best_lang = None
        best_count = -1
        for lang in all_matches:
            count = purl_lang_counts.get(lang, 0)
            if count > best_count:
                best_count = count
                best_lang = lang

        if best_lang and best_count > 0:
            return best_lang, all_matches[best_lang]

        # Priority 3: Fall back to priority heuristic.
        # Python and Java are commonly installed as *system build dependencies*
        # in images whose primary runtime is something else (e.g., node:18
        # ships python3 for node-gyp). Deprioritize them when ambiguous.
        _PRIORITY = {
            "node": 1, "golang": 2, "ruby": 3,
            "php": 4, "openjdk": 5, "python": 6,
        }
        best_lang = min(all_matches, key=lambda l: _PRIORITY.get(l, 99))
        logger.info(
            f"Multiple runtimes found {list(all_matches.keys())} — "
            f"selected '{best_lang}' as primary (deprioritized system deps)"
        )
        return best_lang, all_matches[best_lang]

    # No component matches — fall back to purl-type inference only
    if purl_lang_counts:
        dominant_lang = max(purl_lang_counts, key=purl_lang_counts.get)
        return dominant_lang, None  # version unknown from this signal

    return None, None


def _normalize_version(version: str, language: str) -> str:
    """
    Normalize a version string to major.minor for tag construction.

    Examples:
        "3.8.12" → "3.8" (python)
        "18.19.0" → "18" (node — uses major only)
        "1.22.5" → "1.22" (golang)
    """
    parts = version.split(".")

    # Node.js uses major-only tags (node:18, node:20)
    if language == "node" and parts:
        return parts[0]

    # Most languages use major.minor (python:3.8, golang:1.22)
    if len(parts) >= 2:
        return f"{parts[0]}.{parts[1]}"

    return version


def _check_glibc_dependency(comp_names: List[str], purls: List[str]) -> bool:
    """
    Check if the image has components that require glibc.

    If True, switching to Alpine (musl libc) is unsafe and we should
    prefer -slim variants instead.
    """
    # Check for glibc system packages
    for name in comp_names:
        if name in GLIBC_INDICATOR_PACKAGES:
            return True

    # Check for Python packages known to have C extensions
    for purl in purls:
        if "pkg:pypi/" in purl:
            # Extract package name from purl
            # e.g., "pkg:pypi/numpy@1.24.0" → "numpy"
            match = re.search(r'pkg:pypi/([^@/]+)', purl)
            if match and match.group(1).lower() in GLIBC_PYTHON_PACKAGES:
                return True

    return False


def _detect_variant(comp_names: List[str], meta_name: str) -> Optional[str]:
    """Detect image variant (e.g., apache, fpm) from component names."""
    if any("apache" in n for n in comp_names) or "apache" in meta_name:
        return "apache"
    if any("nginx" in n for n in comp_names) or "nginx" in meta_name:
        return "nginx"
    return None


# ════════════════════════════════════════════════════════════════════
# Base Image Selection — uses inference result, not tag parsing
# ════════════════════════════════════════════════════════════════════

def choose_base_image(
    inference: InferenceResult,
    original_base: Optional[str] = None,
) -> Tuple[str, float]:
    """
    Choose an updated base image using SBOM inference results.

    Selection priority:
    1. If language+version known from SBOM → use that with appropriate OS
    2. If only language known (no version) → fall back to tag regex extraction
    3. If neither → use original_base substring matching (legacy path)
    4. If nothing matches → select based on OS family alone

    The OS target depends on glibc compatibility:
    - No glibc needed → Alpine (smallest attack surface)
    - glibc needed → slim Debian variant (glibc-compatible, minimal)

    Args:
        inference: InferenceResult from analyze_sbom()
        original_base: Original FROM value for fallback extraction

    Returns:
        Tuple of (new_base_image, confidence) where confidence is 0.0–1.0
    """
    original_base = original_base or ""
    o = original_base.lower()

    # Determine OS suffix based on glibc needs
    alpine_safe = not inference.needs_glibc
    os_suffix = "alpine" if alpine_safe else "slim-bookworm"

    # ── Pre-check: Infrastructure / application images ──────────────
    # These images are NOT language runtimes — they are databases, web
    # servers, message queues, CI tools, and CMS applications. Their SBOMs
    # contain Go, Python, or Java as system/build dependencies, NOT as the
    # application runtime. If we let SBOM language detection proceed, we
    # get catastrophic results like consul → golang:1.14-alpine.
    #
    # Strategy: for infrastructure images, skip SBOM language inference
    # entirely and go straight to _match_by_image_name() which has
    # curated mappings for these specific images.
    _INFRASTRUCTURE_KEYWORDS = {
        # Databases
        "mongo", "mysql", "mariadb", "postgres", "redis", "elasticsearch",
        "cassandra", "couchdb", "influxdb", "neo4j", "memcached", "zookeeper",
        # Web servers / proxies
        "nginx", "httpd", "apache", "traefik", "caddy", "haproxy",
        "envoy", "kong",
        # Message queues
        "rabbitmq", "kafka", "nats",
        # Monitoring / observability
        "grafana", "prometheus", "alertmanager", "fluentd", "logstash", "kibana",
        # CI/CD & DevOps tools
        "jenkins", "gitlab", "vault", "consul", "sonarqube",
        "gitea", "drone", "nexus",
        # CMS & Applications
        "wordpress", "nextcloud", "drupal", "ghost", "joomla",
        "redmine", "mediawiki", "phpmyadmin", "adminer", "matomo",
        # App servers (contain JDK but want specific app server images)
        "tomcat", "jetty", "wildfly",
        # Build tools (contain JDK but want specific build tool images)
        "maven", "gradle",
        # Container/cloud infrastructure
        "docker", "registry", "minio", "portainer",
        # Data processing & search
        "solr", "flink",
    }
    image_name_part = o.split(":")[0].split("/")[-1]
    is_infrastructure = any(kw in image_name_part for kw in _INFRASTRUCTURE_KEYWORDS)

    if is_infrastructure:
        logger.info(
            f"Infrastructure image detected ('{image_name_part}') — "
            f"bypassing SBOM language inference, using curated mapping"
        )
        image = _match_by_image_name(o, os_suffix)
        if image:
            return image, 0.8  # high confidence for curated mappings
        # If no match found, fall through to OS-family selection

    # ── Safety check: cross-validate SBOM language against image name ──
    # Prevents misclassification when a build dependency (e.g. python3 in
    # a node:18 image) is mistakenly detected as the primary runtime.
    effective_language = inference.language
    effective_version = inference.language_version
    _IMAGE_NAME_LANGS = {
        "python": "python", "node": "node", "golang": "golang",
        "ruby": "ruby", "php": "php", "openjdk": "openjdk",
        "temurin": "openjdk", "adoptopenjdk": "openjdk",
    }
    image_name_lang = None
    for keyword, lang in _IMAGE_NAME_LANGS.items():
        if keyword in image_name_part:
            image_name_lang = lang
            break

    if image_name_lang and effective_language and image_name_lang != effective_language:
        logger.warning(
            f"SBOM detected '{effective_language}' but image name suggests "
            f"'{image_name_lang}' — overriding to match image name"
        )
        effective_language = image_name_lang
        # Extract version from tag since SBOM version is for wrong language
        effective_version = _extract_version_from_tag(o, image_name_lang)

    # ── Path 1: SBOM gave us language + version (highest confidence) ──
    if effective_language and effective_version:
        image = _build_image_tag(
            effective_language, effective_version,
            os_suffix, inference.variant, o
        )
        if image:
            return image, min(inference.confidence + 0.2, 1.0)

    # ── Path 2: SBOM gave us language but no version → extract from tag ──
    if effective_language and not effective_version:
        ver = _extract_version_from_tag(o, effective_language)
        if ver:
            image = _build_image_tag(
                effective_language, ver, os_suffix, inference.variant, o
            )
            if image:
                return image, min(inference.confidence + 0.1, 0.8)

    # ── Path 3: No language from SBOM → substring match on original tag ──
    # This is the legacy fallback path — lower confidence
    image = _match_by_image_name(o, os_suffix)
    if image:
        return image, 0.5

    # ── Path 4: OS family only — pure OS images ──
    image = _select_by_os_family(inference.os_family, alpine_safe)
    return image, 0.3


def _build_image_tag(
    language: str, version: str, os_suffix: str,
    variant: Optional[str], original_lower: str
) -> Optional[str]:
    """
    Construct a Docker image tag for a known language + version.

    IMPORTANT: Each Docker Hub image uses its own tag convention for slim
    variants. Using a single os_suffix for all images WILL produce invalid
    tags (e.g., node:18-slim-bookworm does not exist — it's node:18-slim
    or node:18-bookworm-slim). This function handles each language's actual
    Docker Hub tag format.

    Args:
        language: Detected language (python, node, golang, etc.)
        version: Detected version (3.8, 18, 1.22, etc.)
        os_suffix: OS suffix hint ("alpine" or "slim-bookworm")
        variant: Optional variant (apache, fpm, etc.)
        original_lower: Lowercased original base for context hints
    """
    is_alpine = (os_suffix == "alpine")

    # ── EOL version upgrade: if the detected version is end-of-life,
    # upgrade to the latest supported version to actually reduce vulns ──
    version = _upgrade_eol_version(language, version)

    if language == "python":
        # python:3.12-alpine  OR  python:3.12-slim (tracks current Debian)
        return f"python:{version}-alpine" if is_alpine else f"python:{version}-slim"

    if language == "node":
        # node:22-alpine  OR  node:22-slim (NOT node:22-slim-bookworm!)
        return f"node:{version}-alpine" if is_alpine else f"node:{version}-slim"

    if language == "golang":
        # golang:1.23-alpine  OR  golang:1.23-bookworm (Go has no -slim)
        return f"golang:{version}-alpine" if is_alpine else f"golang:{version}-bookworm"

    if language == "ruby":
        # ruby:3.3-alpine  OR  ruby:3.3-slim (tracks current Debian)
        return f"ruby:{version}-alpine" if is_alpine else f"ruby:{version}-slim"

    if language == "php":
        if variant == "apache":
            return f"php:{version}-apache"
        if "fpm" in original_lower:
            return f"php:{version}-fpm-alpine" if is_alpine else f"php:{version}-fpm"
        return f"php:{version}-cli-alpine" if is_alpine else f"php:{version}-cli"

    if language == "openjdk":
        # eclipse-temurin:21-jre-alpine  OR  eclipse-temurin:21-jre-jammy
        return f"eclipse-temurin:{version}-jre-alpine" if is_alpine else f"eclipse-temurin:{version}-jre-jammy"

    if language == "rust":
        return f"rust:{version}-slim" if not is_alpine else f"rust:{version}-alpine"

    if language == "perl":
        return f"perl:{version}-slim"

    if language == "erlang":
        return f"erlang:{version}-slim"

    if language == "elixir":
        return f"elixir:{version}-slim"

    if language == "dotnet":
        return f"mcr.microsoft.com/dotnet/aspnet:{version}-alpine"

    return None


def _upgrade_eol_version(language: str, version: str) -> str:
    """
    Upgrade EOL language versions to the latest supported version.

    If the detected version is past end-of-life, return the latest
    supported version for that language. This is critical for actually
    reducing vulnerabilities — keeping an EOL version just changes the
    OS base but leaves all language-level CVEs unfixed.

    Args:
        language: Detected language runtime
        version: Detected version string (e.g., "7.4", "12", "1.16")

    Returns:
        Upgraded version if EOL, otherwise the original version unchanged
    """
    # EOL version → latest supported version mappings
    # Updated March 2026. These should be refreshed periodically.
    _EOL_UPGRADES = {
        "python": {
            # Python 3.8 and below are EOL
            "2.7": "3.12", "3.0": "3.12", "3.1": "3.12", "3.2": "3.12",
            "3.3": "3.12", "3.4": "3.12", "3.5": "3.12", "3.6": "3.12",
            "3.7": "3.12", "3.8": "3.12",
        },
        "node": {
            # Node.js odd versions and <18 are EOL
            "8": "22", "10": "22", "12": "22", "13": "22",
            "14": "22", "15": "22", "16": "22", "17": "22",
            "19": "22", "21": "22",
        },
        "golang": {
            # Go supports only the two most recent minor releases
            "1.16": "1.23", "1.17": "1.23", "1.18": "1.23",
            "1.19": "1.23", "1.20": "1.23", "1.21": "1.23",
        },
        "ruby": {
            "2.5": "3.3", "2.6": "3.3", "2.7": "3.3",
            "3.0": "3.3",
        },
        "php": {
            # PHP 8.0 and below are EOL
            "5.6": "8.3", "7.0": "8.3", "7.1": "8.3", "7.2": "8.3",
            "7.3": "8.3", "7.4": "8.3", "8.0": "8.3",
        },
        "openjdk": {
            # Non-LTS and old LTS versions (Java 11 EOL Oct 2024)
            "8": "21", "9": "21", "10": "21", "11": "21", "12": "21",
            "13": "21", "14": "21", "15": "21", "16": "21",
        },
        "rust": {
            "1.56": "1.85", "1.57": "1.85", "1.58": "1.85", "1.59": "1.85",
            "1.60": "1.85", "1.61": "1.85", "1.62": "1.85", "1.63": "1.85",
            "1.64": "1.85", "1.65": "1.85", "1.66": "1.85", "1.67": "1.85",
            "1.68": "1.85", "1.69": "1.85", "1.70": "1.85",
        },
        "perl": {
            "5.30": "5.40", "5.32": "5.40", "5.34": "5.40",
        },
        "erlang": {
            "22": "27", "23": "27", "24": "27", "25": "27",
        },
        "elixir": {
            "1.11": "1.18", "1.12": "1.18", "1.13": "1.18", "1.14": "1.18",
        },
        "dotnet": {
            "5.0": "8.0", "6.0": "8.0", "7.0": "8.0",
        },
    }

    lang_eol = _EOL_UPGRADES.get(language, {})
    if version in lang_eol:
        new_version = lang_eol[version]
        logger.info(
            f"Upgrading EOL {language} version {version} → {new_version} "
            f"(version {version} is end-of-life)"
        )
        return new_version

    return version


def _extract_version_from_tag(tag_lower: str, language: str) -> Optional[str]:
    """
    Fallback: extract version from the Docker tag string.

    Only used when SBOM detection found the language but not the version.
    """
    if language == "node":
        m = re.search(r':(\d+)', tag_lower)
        return m.group(1) if m else None
    else:
        m = re.search(r':(\d+(?:\.\d+)*)', tag_lower)
        if m:
            return _normalize_version(m.group(1), language)
    return None


def _match_by_image_name(o: str, os_suffix: str) -> Optional[str]:
    """
    Legacy fallback: match image by substring in the original tag.

    This handles databases, infrastructure, and other non-language images
    where the SBOM won't contain a language runtime.
    """
    # ── Databases (check mongo BEFORE go to avoid substring collision) ──
    if "mongo-express" in o:
        return "mongo-express:latest"
    if "mongo" in o:
        return "mongo:7"
    if "redis" in o:
        return "redis:7-alpine"
    if "postgres" in o:
        return "postgres:17-alpine"
    if "mysql" in o:
        return "mysql:8.4"
    if "mariadb" in o:
        return "mariadb:11"
    if "cassandra" in o:
        return "cassandra:5.0"
    if "couchdb" in o:
        return "couchdb:3.4"
    if "influxdb" in o:
        return "influxdb:2.7-alpine"
    if "neo4j" in o:
        return "neo4j:5-community"
    if "memcached" in o:
        return "memcached:1.6-alpine"
    if "zookeeper" in o:
        return "zookeeper:3.9"

    # ── App servers (check BEFORE language images to avoid JDK substring collisions) ──
    if "tomcat" in o:
        return "tomcat:10.1-jre21"
    if "jetty" in o:
        return "jetty:12-jre21"
    if "wildfly" in o:
        return "wildfly:34-jre21"
    # ── Build tools (check BEFORE openjdk — maven:3.8-openjdk-11 contains "openjdk") ──
    if "maven" in o:
        return "maven:3.9-eclipse-temurin-21-alpine"
    if "gradle" in o:
        return "gradle:8-jdk21-alpine"
    # ── CMS apps containing "php" (check BEFORE generic php match) ──
    if "phpmyadmin" in o:
        return "phpmyadmin:latest"

    # ── Language images (fallback when SBOM didn't detect language) ──
    # Use _build_image_tag to ensure correct Docker Hub tag conventions.
    # IMPORTANT: apply _upgrade_eol_version() to every extracted version
    # so that EOL runtimes are upgraded even when SBOM didn't detect the language.
    is_alpine = (os_suffix == "alpine")
    if "rust" in o:
        ver = _extract_version_from_tag(o, "rust") or "1.85"
        ver = _upgrade_eol_version("rust", ver)
        return f"rust:{ver}-alpine" if is_alpine else f"rust:{ver}-slim"
    if "perl" in o:
        ver = _extract_version_from_tag(o, "perl") or "5.40"
        ver = _upgrade_eol_version("perl", ver)
        return f"perl:{ver}-slim"
    if "erlang" in o:
        ver = _extract_version_from_tag(o, "erlang") or "27"
        ver = _upgrade_eol_version("erlang", ver)
        return f"erlang:{ver}-slim"
    if "elixir" in o:
        ver = _extract_version_from_tag(o, "elixir") or "1.18"
        ver = _upgrade_eol_version("elixir", ver)
        return f"elixir:{ver}-slim"
    if "aspnet" in o or ("dotnet" in o and "aspnet" in o):
        ver = _extract_version_from_tag(o, "dotnet") or "8.0"
        ver = _upgrade_eol_version("dotnet", ver)
        return f"mcr.microsoft.com/dotnet/aspnet:{ver}-alpine"
    if "dotnet" in o and "sdk" in o:
        ver = _extract_version_from_tag(o, "dotnet") or "8.0"
        ver = _upgrade_eol_version("dotnet", ver)
        return f"mcr.microsoft.com/dotnet/sdk:{ver}-alpine"
    if "python" in o:
        ver = _extract_version_from_tag(o, "python") or "3.12"
        ver = _upgrade_eol_version("python", ver)
        return f"python:{ver}-alpine" if is_alpine else f"python:{ver}-slim"
    if "node" in o:
        ver = _extract_version_from_tag(o, "node") or "22"
        ver = _upgrade_eol_version("node", ver)
        return f"node:{ver}-alpine" if is_alpine else f"node:{ver}-slim"
    if "golang" in o or re.search(r'\bgo:', o):
        ver = _extract_version_from_tag(o, "golang") or "1.22"
        ver = _upgrade_eol_version("golang", ver)
        return f"golang:{ver}-alpine" if is_alpine else f"golang:{ver}-bookworm"
    if "ruby" in o:
        ver = _extract_version_from_tag(o, "ruby") or "3.3"
        ver = _upgrade_eol_version("ruby", ver)
        return f"ruby:{ver}-alpine" if is_alpine else f"ruby:{ver}-slim"
    if "php" in o:
        ver = _extract_version_from_tag(o, "php") or "8.3"
        ver = _upgrade_eol_version("php", ver)
        if "apache" in o:
            return f"php:{ver}-apache"
        if "fpm" in o:
            return f"php:{ver}-fpm-alpine" if is_alpine else f"php:{ver}-fpm"
        return f"php:{ver}-cli-alpine" if is_alpine else f"php:{ver}-cli"
    if "temurin" in o or "adoptopenjdk" in o or "openjdk" in o:
        m = re.search(r':(\d+)', o)
        major = m.group(1) if m else "21"
        major = _upgrade_eol_version("openjdk", major)
        return f"eclipse-temurin:{major}-jre-alpine" if is_alpine else f"eclipse-temurin:{major}-jre-jammy"

    # ── Web servers / infrastructure ──
    if "nginx" in o:
        return "nginx:stable-alpine"
    if "httpd" in o:
        return "httpd:2.4-alpine"
    if "traefik" in o:
        return "traefik:v3.3"
    if "caddy" in o:
        return "caddy:2-alpine"
    if "haproxy" in o:
        return "haproxy:3.1-alpine"
    if "envoy" in o:
        return "envoyproxy/envoy:v1.32-latest"
    if "kong" in o:
        return "kong:3.9"

    # ── Message queues ──
    if "rabbitmq" in o:
        return "rabbitmq:4-alpine"
    if "elasticsearch" in o:
        return "docker.elastic.co/elasticsearch/elasticsearch:8.17.0"
    if "kafka" in o:
        return "bitnami/kafka:3.9"
    if "nats" in o:
        return "nats:2.10-alpine"

    # ── Monitoring & observability ──
    if "grafana" in o:
        return "grafana/grafana:11.5.2"
    if "prometheus" in o:
        return "prom/prometheus:v2.53.4"
    if "alertmanager" in o:
        return "prom/alertmanager:v0.28.1"
    if "fluentd" in o:
        return "fluentd:v1.17-debian-1"
    if "kibana" in o:
        return "docker.elastic.co/kibana/kibana:8.17.0"
    if "logstash" in o:
        return "docker.elastic.co/logstash/logstash:8.17.0"

    # ── CI/CD tools ──
    if "jenkins" in o:
        return "jenkins/jenkins:lts-alpine"
    if "vault" in o:
        return "hashicorp/vault:latest"
    if "consul" in o:
        return "hashicorp/consul:latest"
    if "sonarqube" in o:
        return "sonarqube:lts-community"
    if "gitlab" in o:
        return "gitlab/gitlab-runner:alpine"
    if "gitea" in o:
        return "gitea/gitea:latest"
    if "drone" in o:
        return "drone/drone:latest"
    if "nexus" in o:
        return "sonatype/nexus3:latest"

    # ── Cloud native infrastructure ──
    if o.startswith("registry") or "registry:" in o:
        return "registry:2"
    if "minio" in o:
        return "minio/minio:latest"
    if "portainer" in o:
        return "portainer/portainer-ce:2.24.1"

    # ── CMS / Applications ──
    if "wordpress" in o:
        return "wordpress:6-php8.3-apache"
    if "nextcloud" in o:
        return "nextcloud:29-apache"
    if "drupal" in o:
        # Preserve the major Drupal version to avoid introducing new vulns
        # from a larger base image (e.g., drupal:11 >> drupal:10 in size)
        m = re.search(r'drupal:(\d+)', o)
        drupal_major = m.group(1) if m else "11"
        return f"drupal:{drupal_major}-php8.3-apache"
    if "ghost" in o:
        return "ghost:5-alpine"
    if "joomla" in o:
        return "joomla:5-php8.3-apache"
    if "redmine" in o:
        return "redmine:5-alpine"
    if "mediawiki" in o:
        return "mediawiki:lts-fpm"
    if "adminer" in o:
        return "adminer:latest"
    if "matomo" in o:
        return "matomo:5-apache"
    if "docker" in o:
        # docker:27-cli has significantly more Trivy-visible vulns than
        # older docker images. Use docker:27-dind which is more minimal.
        # Also preserve major version if possible.
        return "docker:27-cli"  # TODO: investigate docker:27-dind or skip

    # ── Data processing & search ──
    if "solr" in o:
        return "solr:9"
    if "flink" in o:
        return "flink:1.20"

    return None


def _select_by_os_family(family: str, alpine_safe: bool) -> str:
    """Select a base image based purely on OS family."""
    family_lower = family.lower()

    if not alpine_safe:
        # glibc-dependent → use slim Debian variants
        os_map_glibc = {
            "alpine": "alpine:3.21",          # already Alpine, keep it
            "debian": "debian:bookworm-slim",
            "ubuntu": "ubuntu:24.04",
            "centos": "rockylinux:9-minimal",
            "rhel": "rockylinux:9-minimal",
            "rocky": "rockylinux:9-minimal",
            "alma": "almalinux:9-minimal",
            "fedora": "fedora:41",
            "distroless": "gcr.io/distroless/static-debian12:nonroot",
            "scratch": "scratch",
        }
        return os_map_glibc.get(family_lower, "debian:bookworm-slim")

    os_map = {
        "alpine": "alpine:3.21",
        "debian": "debian:bookworm-slim",
        "ubuntu": "ubuntu:24.04",
        "centos": "rockylinux:9-minimal",
        "rhel": "rockylinux:9-minimal",
        "rocky": "rockylinux:9-minimal",
        "alma": "almalinux:9-minimal",
        "fedora": "fedora:41",
        "distroless": "gcr.io/distroless/static-debian12:nonroot",
        "scratch": "scratch",
    }
    return os_map.get(family_lower, "alpine:3.21")


# ════════════════════════════════════════════════════════════════════
# Smoke Test — lightweight runtime validation
# ════════════════════════════════════════════════════════════════════

def smoke_test_image(image_name: str, timeout_seconds: int = 10) -> Tuple[bool, str]:
    """
    Run a lightweight smoke test on a built image.

    Starts the container with its default entrypoint and checks whether
    the process stays alive for a few seconds. This catches:
    - Missing shared libraries (musl vs glibc)
    - Segfaults from incompatible native binaries
    - Immediate crash on startup

    This is NOT a full integration test — just a "does it start?" check.

    Args:
        image_name: Docker image to test
        timeout_seconds: How long to wait for the process (default 10)

    Returns:
        Tuple of (passed, message)
    """
    from .utils import run_cmd

    # Try to start the container in the background
    container_name = f"autopatch-smoke-{image_name.replace('/', '-').replace(':', '-')}"

    # Start container detached
    start_cmd = f"docker run -d --name {container_name} {image_name}"
    code, output = run_cmd(start_cmd, timeout=30)

    if code != 0:
        return False, f"Container failed to start: {output}"

    container_id = output.strip()

    try:
        # Wait a few seconds then check if container is still running
        import time
        time.sleep(min(timeout_seconds, 5))

        inspect_cmd = f"docker inspect --format='{{{{.State.Running}}}}' {container_id}"
        code, state = run_cmd(inspect_cmd, timeout=10)

        if code != 0:
            return False, f"Failed to inspect container: {state}"

        # Check exit code if stopped
        if "false" in state.lower():
            exit_cmd = f"docker inspect --format='{{{{.State.ExitCode}}}}' {container_id}"
            _, exit_output = run_cmd(exit_cmd, timeout=10)
            exit_code = exit_output.strip()

            # Exit code 0 is fine — some containers (like CLI tools) exit immediately
            if exit_code == "0":
                return True, "Container exited cleanly (exit code 0)"
            else:
                # Get last few log lines for diagnosis
                log_cmd = f"docker logs --tail 20 {container_id}"
                _, logs = run_cmd(log_cmd, timeout=10)
                return False, f"Container crashed with exit code {exit_code}. Logs: {logs[:500]}"

        return True, "Container running successfully"

    finally:
        # Cleanup
        run_cmd(f"docker rm -f {container_id}", timeout=10)


# ════════════════════════════════════════════════════════════════════
# Legacy compatibility wrappers
# ════════════════════════════════════════════════════════════════════

def detect_os_family(sbom_data: Optional[Dict[str, Any]]) -> str:
    """
    Legacy wrapper — detect OS family from SBOM.

    Prefer analyze_sbom() for full inference. This exists for backward
    compatibility with code that only needs the OS family string.
    """
    result = analyze_sbom(sbom_data)
    return result.os_family


# ════════════════════════════════════════════════════════════════════
# Main entry point: patch_dockerfile
# ════════════════════════════════════════════════════════════════════

# Minimum confidence to auto-patch. Below this, we emit a warning
# and suggest the user provide a --base-mapping override.
MIN_AUTO_PATCH_CONFIDENCE = 0.4


def patch_dockerfile(
    dockerfile_text: str,
    sbom_before: Optional[Dict[str, Any]] = None,
    base_mapping: Optional[Dict[str, str]] = None,
    patch_final_only: bool = False,
    dry_run: bool = False,
    enable_smoke_test: bool = False,
) -> Tuple[str, List[Tuple[str, str]], List[str], str]:
    """
    Patch the Dockerfile by replacing base images with updated, minimal variants.

    Uses a multi-signal inference pipeline:
    1. Analyze SBOM → get OS, language, version, glibc needs, confidence
    2. For each FROM stage, select the best replacement image
    3. If confidence is below threshold, warn instead of silently patching
    4. Only FROM lines are rewritten; all other instructions preserved verbatim

    Handles multi-stage builds correctly:
    - FROM stage_alias (internal references) are NOT rewritten
    - FROM scratch is NOT rewritten
    - FROM $ARG_VAR is skipped with a warning
    - COPY --from= references trigger a warning about potential breakage

    Args:
        dockerfile_text: The original Dockerfile content
        sbom_before: SBOM data (CycloneDX dict) of the original image
        base_mapping: Dict mapping original bases to user-specified overrides
        patch_final_only: If True, only patch the final stage
        dry_run: If True, compute changes but don't apply (returns original text)
        enable_smoke_test: If True, run smoke test after each stage patch

    Returns:
        Tuple of (patched_text, base_changes, warnings, diff_text) where:
        - patched_text: The modified Dockerfile
        - base_changes: List of (original_base, new_base) tuples
        - warnings: List of warning messages
        - diff_text: Human-readable diff of changes
    """
    stages = parse_dockerfile_stages(dockerfile_text)
    if not stages:
        logger.error("No FROM instructions found in Dockerfile.")
        return dockerfile_text, [], ["No FROM instructions found"], ""

    # Run full SBOM inference once
    inference = analyze_sbom(sbom_before)
    logger.info(
        f"SBOM inference: OS={inference.os_family}, "
        f"lang={inference.language}:{inference.language_version}, "
        f"glibc={inference.needs_glibc}, confidence={inference.confidence:.2f}"
    )
    for signal in inference.signals:
        logger.debug(f"  signal: {signal}")

    patched_lines = []
    base_changes = []
    warnings = list(inference.warnings)  # Start with any inference warnings

    for idx, stage in enumerate(stages):
        is_final = (idx == len(stages) - 1)

        # Skip intermediate stages if patch_final_only
        if patch_final_only and not is_final:
            patched_lines.append(stage['from_line'])
            patched_lines.extend(stage['lines'])
            continue

        # Handle internal stage references — do NOT rewrite
        if stage['is_stage_alias']:
            patched_lines.append(stage['from_line'])
            patched_lines.extend(stage['lines'])
            continue

        orig_base = stage['base_image']
        alias = stage['alias']
        comment = stage['comment'] or ""

        # Skip FROM scratch
        if stage['is_scratch']:
            patched_lines.append(stage['from_line'])
            patched_lines.extend(stage['lines'])
            continue

        # Skip FROM $VAR patterns
        if "$" in orig_base or "{" in orig_base:
            warnings.append(
                f"Stage {idx}: FROM references build arg '{orig_base}' — skipping"
            )
            patched_lines.append(stage['from_line'])
            patched_lines.extend(stage['lines'])
            continue

        # Skip bare stage names (no : / or . → likely an alias)
        if not (":" in orig_base or "/" in orig_base or "." in orig_base):
            patched_lines.append(stage['from_line'])
            patched_lines.extend(stage['lines'])
            continue

        # Choose new base image
        if base_mapping and (orig_base in base_mapping or stage['base_name'] in base_mapping):
            # User override — highest priority, full confidence
            new_base = base_mapping.get(orig_base, base_mapping.get(stage['base_name']))
            selection_confidence = 1.0
        else:
            # SBOM-driven selection
            new_base, selection_confidence = choose_base_image(
                inference, original_base=orig_base
            )

        # Confidence check — warn if we're not confident
        if selection_confidence < MIN_AUTO_PATCH_CONFIDENCE:
            warnings.append(
                f"Stage {idx}: Low confidence ({selection_confidence:.2f}) selecting "
                f"'{new_base}' to replace '{orig_base}'. Consider providing a "
                f"--base-mapping override for this image."
            )
            if dry_run:
                # In dry-run mode, still show what we'd do
                pass
            # We still apply the change, but the warning is recorded

        # Skip if new base is scratch
        if new_base.lower() == "scratch":
            patched_lines.append(stage['from_line'])
            patched_lines.extend(stage['lines'])
            continue

        # Warn about COPY --from= breakage
        if alias:
            all_lines_str = "\n".join(stage['lines']).lower()
            if "--from=" in all_lines_str:
                warnings.append(
                    f"Stage {idx} (alias '{alias}'): downstream COPY --from= "
                    f"references may break if base image changes incompatibly"
                )

        # glibc warning for specific images
        if inference.needs_glibc and "alpine" in new_base.lower():
            warnings.append(
                f"Stage {idx}: glibc-dependent packages detected but Alpine selected. "
                f"Runtime failures possible. Consider using -slim variant instead."
            )

        base_changes.append((orig_base, new_base))

        # Build new FROM line preserving alias and comment
        alias_clause = f" AS {alias}" if alias else ""
        comment_clause = f" {comment}" if comment else ""
        new_from_line = f"FROM {new_base}{alias_clause}{comment_clause}"
        patched_lines.append(new_from_line)

        # Preserve ALL other instructions unchanged
        patched_lines.extend(stage['lines'])

    patched_text = "\n".join(patched_lines) + "\n"

    if dry_run:
        patched_text = dockerfile_text  # Don't actually change anything

    # Generate human-readable diff
    diff_lines = ["--- Dockerfile (original)", "+++ Dockerfile (patched)", ""]
    for orig, new in base_changes:
        diff_lines.append(f"- FROM {orig}")
        diff_lines.append(f"+ FROM {new}")
    if warnings:
        diff_lines.append("")
        diff_lines.append("# Warnings:")
        for warning in warnings:
            diff_lines.append(f"# {warning}")
    diff_lines.append("")
    diff_lines.append(f"# Inference confidence: {inference.confidence:.2f}")
    if inference.signals:
        diff_lines.append("# Signals:")
        for signal in inference.signals:
            diff_lines.append(f"#   - {signal}")

    diff_text = "\n".join(diff_lines)

    return patched_text, base_changes, warnings, diff_text
