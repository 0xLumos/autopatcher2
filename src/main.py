import argparse
import logging
import json
import os
import sys
import tempfile
import shutil
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any

# Configure the logger (console output format)
logger = logging.getLogger("docker_patch_tool")
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
logger.addHandler(handler)
logger.setLevel(logging.INFO)

# Import functions from other modules
from .utils import (
    run_cmd, load_base_mapping, load_json, save_json, save_csv,
    generate_diff, compute_reduction_percentage
)
from .parser import parse_dockerfile_stages
from .builder import build_image, tag_image, push_image, get_image_digest, measure_image_size
from .scanner import (
    scan_image, scan_image_detailed, generate_sbom, summarize_vulnerabilities,
    ScanError, NetworkError, DBUpdateError, ScanExecutionError
)
from .patcher import patch_dockerfile, analyze_sbom, smoke_test_image
from .signer import (
    sign_image, verify_image, attach_sbom, get_signing_log,
    SigningError, KeyGenerationError, VerificationError
)
from .comparer import (
    diff_vulnerabilities, diff_sbom, compute_metrics, check_acceptance_criteria
)


def _clone_github_repo(repo_url: str) -> str:
    """
    Clone a GitHub repository to a temporary directory.

    Args:
        repo_url: GitHub URL (e.g., https://github.com/user/repo)

    Returns:
        Path to the cloned directory

    Raises:
        Exception on clone failure
    """
    temp_dir = tempfile.mkdtemp(prefix="autopatch-github-")
    logger.info(f"Cloning repository {repo_url} to {temp_dir}...")

    code, output = run_cmd(["git", "clone", repo_url, temp_dir])
    if code != 0:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise Exception(f"Failed to clone repository: {output}")

    return temp_dir


def _find_dockerfile(repo_path: str) -> str:
    """
    Find Dockerfile in a directory (searches recursively).

    Args:
        repo_path: Directory path to search

    Returns:
        Path to Dockerfile

    Raises:
        FileNotFoundError if no Dockerfile found
    """
    # First check root
    root_dockerfile = os.path.join(repo_path, "Dockerfile")
    if os.path.exists(root_dockerfile):
        return root_dockerfile

    # Search recursively
    for root, dirs, files in os.walk(repo_path):
        if "Dockerfile" in files:
            return os.path.join(root, "Dockerfile")

    raise FileNotFoundError(f"No Dockerfile found in {repo_path}")


def _generate_json_report(
    metrics: Dict[str, Any],
    base_changes: list,
    before_summary: Dict[str, int],
    after_summary: Dict[str, int],
    vulns_diff: Dict[str, Any],
    sbom_diff: Dict[str, Any],
    signing_logs: list
) -> str:
    """Generate JSON format report."""
    report = {
        "timestamp": datetime.now().isoformat(),
        "base_image_changes": [{"original": o, "new": n} for o, n in base_changes],
        "vulnerabilities_before": before_summary,
        "vulnerabilities_after": after_summary,
        "resolved_vulnerabilities": vulns_diff["resolved"],
        "remaining_vulnerabilities": vulns_diff["remaining"],
        "new_vulnerabilities": vulns_diff["new"],
        "sbom_diff": sbom_diff,
        "metrics": metrics,
        "signing_operations": signing_logs
    }
    return json.dumps(report, indent=2)


def _generate_markdown_report(
    metrics: Dict[str, Any],
    base_changes: list,
    before_summary: Dict[str, int],
    after_summary: Dict[str, int],
    vulns_diff: Dict[str, Any],
    sbom_diff: Dict[str, Any],
    acceptance_status: bool,
    acceptance_reasons: list,
    patched_dockerfile_path: Optional[str] = None,
    diff_text: Optional[str] = None
) -> str:
    """Generate Markdown format report."""
    lines = ["# AutoPatch Report\n"]

    lines.append(f"**Generated:** {datetime.now().isoformat()}\n")

    lines.append("## Summary\n")
    lines.append(f"- **Acceptance Status:** {'ACCEPTED' if acceptance_status else 'REJECTED'}\n")
    if acceptance_reasons:
        lines.append("- **Rejection Reasons:**\n")
        for reason in acceptance_reasons:
            lines.append(f"  - {reason}\n")

    lines.append("## Base Image Changes\n")
    if base_changes:
        for orig, new in base_changes:
            lines.append(f"- `{orig}` -> `{new}`\n")
    else:
        lines.append("- None\n")

    lines.append("## Vulnerabilities\n")
    lines.append(f"### Before: {before_summary.get('total', 0)} total\n")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
        if sev in before_summary:
            lines.append(f"- {sev}: {before_summary[sev]}\n")

    lines.append(f"### After: {after_summary.get('total', 0)} total\n")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
        if sev in after_summary:
            lines.append(f"- {sev}: {after_summary[sev]}\n")

    reduction = before_summary.get('total', 0) - after_summary.get('total', 0)
    reduction_pct = compute_reduction_percentage(
        before_summary.get('total', 0), after_summary.get('total', 0)
    )
    lines.append(f"### Reduction: {reduction} CVEs ({reduction_pct:.1f}%)\n")

    lines.append("## CVE Details\n")
    lines.append(f"### Resolved ({len(vulns_diff['resolved'])})\n")
    for v in vulns_diff["resolved"][:10]:  # Limit to 10 for brevity
        lines.append(f"- {v['id']} in {v['package']}\n")
    if len(vulns_diff["resolved"]) > 10:
        lines.append(f"- ... and {len(vulns_diff['resolved']) - 10} more\n")

    lines.append(f"### Remaining ({len(vulns_diff['remaining'])})\n")
    for v in vulns_diff["remaining"][:5]:
        lines.append(f"- {v['id']} in {v['package']} ({v['severity']})\n")
    if len(vulns_diff["remaining"]) > 5:
        lines.append(f"- ... and {len(vulns_diff['remaining']) - 5} more\n")

    if vulns_diff["new"]:
        lines.append(f"### New ({len(vulns_diff['new'])})\n")
        for v in vulns_diff["new"][:5]:
            lines.append(f"- {v['id']} in {v['package']} ({v['severity']})\n")
        if len(vulns_diff["new"]) > 5:
            lines.append(f"- ... and {len(vulns_diff['new']) - 5} more\n")

    lines.append("## SBOM Changes\n")
    lines.append(f"- Added: {len(sbom_diff['added'])} components\n")
    lines.append(f"- Removed: {len(sbom_diff['removed'])} components\n")
    lines.append(f"- Updated: {len(sbom_diff['updated'])} components\n")

    if metrics:
        lines.append("## Metrics\n")
        lines.append(f"- Vulnerability Reduction: {metrics.get('vulnerability_reduction_pct', 0):.1f}%\n")
        lines.append(f"- CVE Resolution Rate: {metrics.get('cve_resolution_rate', 0):.1f}%\n")
        if 'build_time_seconds' in metrics:
            lines.append(f"- Build Time: {metrics['build_time_seconds']:.2f}s\n")
        if 'image_size_delta_mb' in metrics:
            lines.append(f"- Image Size Delta: {metrics['image_size_delta_mb']:+.2f}MB\n")

    if diff_text:
        lines.append("## Dockerfile Changes\n")
        lines.append("```diff\n")
        lines.append(diff_text)
        lines.append("\n```\n")

    return "".join(lines)


def _generate_html_report(
    metrics: Dict[str, Any],
    base_changes: list,
    before_summary: Dict[str, int],
    after_summary: Dict[str, int],
    vulns_diff: Dict[str, Any],
    sbom_diff: Dict[str, Any],
    acceptance_status: bool,
    acceptance_reasons: list
) -> str:
    """Generate HTML format report."""
    html_lines = [
        "<!DOCTYPE html>",
        "<html>",
        "<head>",
        "<title>AutoPatch Report</title>",
        "<style>",
        "body { font-family: Arial, sans-serif; margin: 20px; }",
        "h1 { color: #333; }",
        "h2 { color: #555; border-bottom: 2px solid #ddd; padding-bottom: 5px; }",
        ".summary { background: #f9f9f9; padding: 10px; border-left: 4px solid #007bff; }",
        ".accepted { color: green; font-weight: bold; }",
        ".rejected { color: red; font-weight: bold; }",
        ".metric { display: inline-block; margin: 10px 20px 10px 0; }",
        "table { border-collapse: collapse; width: 100%; margin: 10px 0; }",
        "th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }",
        "th { background: #f0f0f0; }",
        ".critical { color: red; }",
        ".high { color: orange; }",
        "</style>",
        "</head>",
        "<body>",
        "<h1>AutoPatch Report</h1>",
        f"<p><strong>Generated:</strong> {datetime.now().isoformat()}</p>",
    ]

    # Summary
    html_lines.append('<div class="summary">')
    status_class = "accepted" if acceptance_status else "rejected"
    status_text = "ACCEPTED" if acceptance_status else "REJECTED"
    html_lines.append(f'<p><strong>Status:</strong> <span class="{status_class}">{status_text}</span></p>')
    if acceptance_reasons:
        html_lines.append("<p><strong>Rejection Reasons:</strong></p><ul>")
        for reason in acceptance_reasons:
            html_lines.append(f"<li>{reason}</li>")
        html_lines.append("</ul>")
    html_lines.append("</div>")

    # Base Changes
    html_lines.append("<h2>Base Image Changes</h2>")
    if base_changes:
        html_lines.append("<ul>")
        for orig, new in base_changes:
            html_lines.append(f"<li><code>{orig}</code> -> <code>{new}</code></li>")
        html_lines.append("</ul>")
    else:
        html_lines.append("<p>None</p>")

    # Vulnerabilities
    html_lines.append("<h2>Vulnerabilities</h2>")
    html_lines.append("<table>")
    html_lines.append("<tr><th>Severity</th><th>Before</th><th>After</th></tr>")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
        before = before_summary.get(sev, 0)
        after = after_summary.get(sev, 0)
        sev_class = "critical" if sev == "CRITICAL" else "high" if sev == "HIGH" else ""
        html_lines.append(
            f'<tr><td class="{sev_class}"><strong>{sev}</strong></td>'
            f'<td>{before}</td><td>{after}</td></tr>'
        )
    html_lines.append("</table>")

    # CVE Summary
    total_before = before_summary.get('total', 0)
    total_after = after_summary.get('total', 0)
    reduction = total_before - total_after
    reduction_pct = compute_reduction_percentage(total_before, total_after)
    html_lines.append(
        f"<p><strong>Total Reduction:</strong> {reduction} CVEs ({reduction_pct:.1f}%)</p>"
    )

    # CVE Details
    html_lines.append("<h2>CVE Details</h2>")
    html_lines.append(f"<p><strong>Resolved:</strong> {len(vulns_diff['resolved'])}</p>")
    html_lines.append(f"<p><strong>Remaining:</strong> {len(vulns_diff['remaining'])}</p>")
    html_lines.append(f"<p><strong>New:</strong> {len(vulns_diff['new'])}</p>")

    # SBOM Changes
    html_lines.append("<h2>SBOM Changes</h2>")
    html_lines.append("<ul>")
    html_lines.append(f"<li>Added: {len(sbom_diff['added'])} components</li>")
    html_lines.append(f"<li>Removed: {len(sbom_diff['removed'])} components</li>")
    html_lines.append(f"<li>Updated: {len(sbom_diff['updated'])} components</li>")
    html_lines.append("</ul>")

    # Metrics
    if metrics:
        html_lines.append("<h2>Metrics</h2>")
        html_lines.append(f'<div class="metric">Vulnerability Reduction: <strong>{metrics.get("vulnerability_reduction_pct", 0):.1f}%</strong></div>')
        html_lines.append(f'<div class="metric">CVE Resolution Rate: <strong>{metrics.get("cve_resolution_rate", 0):.1f}%</strong></div>')
        if 'build_time_seconds' in metrics:
            html_lines.append(f'<div class="metric">Build Time: <strong>{metrics["build_time_seconds"]:.2f}s</strong></div>')
        if 'image_size_delta_mb' in metrics:
            sign = "+" if metrics['image_size_delta_mb'] >= 0 else ""
            html_lines.append(f'<div class="metric">Image Size Delta: <strong>{sign}{metrics["image_size_delta_mb"]:.2f}MB</strong></div>')

    html_lines.extend(["</body>", "</html>"])
    return "\n".join(html_lines)


def main():
    parser = argparse.ArgumentParser(description="Docker Image Auto-Patching Tool")

    # Required flags (one of these two)
    parser.add_argument("--dockerfile", help="Path to the Dockerfile to patch")
    parser.add_argument("--github-url", help="GitHub repository URL (auto-clones and finds Dockerfile)")

    # Registry and signing
    parser.add_argument("--registry", default="localhost:5000", help="Target registry (default: localhost:5000)")
    parser.add_argument(
        "--signing-mode", "--signing",
        choices=["keyless", "key-based", "key", "disabled", "none"],
        default="key",
        help="Signing mode: keyless, key-based/key (default), disabled/none"
    )

    # Patching options
    parser.add_argument("--base-mapping", help="JSON/YAML file with base image overrides")
    parser.add_argument("--patch-final-only", action="store_true", help="Only patch final stage")
    parser.add_argument("--accept-threshold",
                       choices=["strict", "moderate", "permissive"],
                       default="strict",
                       help="Acceptance criteria threshold (default: strict)")

    # Logging and output
    parser.add_argument("--verbose", "-v", action="count", default=0, help="Increase verbosity")
    parser.add_argument("--dry-run", action="store_true", help="Generate patched Dockerfile but don't build/push/sign")
    parser.add_argument("--output-dir", default="./autopatch-output", help="Output directory for reports (default: ./autopatch-output)")
    parser.add_argument("--report-format",
                       choices=["json", "markdown", "html"],
                       default="json",
                       help="Report format (default: json)")
    parser.add_argument("--test-cmd", help="Command to test inside patched image")
    parser.add_argument("--smoke-test", action="store_true",
                       help="Run a lightweight smoke test after build to catch runtime crashes (musl/glibc, missing libs)")
    parser.add_argument("--ci-mode", action="store_true", help="Output GitHub Actions annotations and appropriate exit codes")

    # Backward compat aliases
    parser.add_argument("--output-file", help="[DEPRECATED] Use --output-dir instead")

    args = parser.parse_args()

    # Adjust logging level based on verbosity
    if args.verbose >= 2:
        logger.setLevel(logging.DEBUG)
    elif args.verbose == 1:
        logger.setLevel(logging.INFO)
    else:
        logger.setLevel(logging.INFO if args.report_format in ("markdown", "html") else logging.WARNING)

    # Normalize signing mode (handle aliases)
    signing_mode = args.signing_mode
    if signing_mode in ("key-based",):
        signing_mode = "key"
    elif signing_mode in ("disabled",):
        signing_mode = "none"

    # Handle backward compat flags
    report_format = args.report_format or "json"
    output_file = args.output_file

    # Resolve Dockerfile path
    dockerfile_path: Optional[str] = None
    temp_repo_dir: Optional[str] = None

    try:
        if args.github_url:
            logger.info(f"Cloning GitHub repository: {args.github_url}")
            temp_repo_dir = _clone_github_repo(args.github_url)
            dockerfile_path = _find_dockerfile(temp_repo_dir)
            logger.info(f"Found Dockerfile at: {dockerfile_path}")
        elif args.dockerfile:
            dockerfile_path = args.dockerfile
        else:
            logger.error("Either --dockerfile or --github-url must be provided")
            if args.ci_mode:
                print("::error::Either --dockerfile or --github-url must be provided")
            return 1

        # Read original Dockerfile
        try:
            with open(dockerfile_path, "r", encoding="utf-8") as f:
                original_dockerfile = f.read()
        except Exception as e:
            logger.error(f"Could not read Dockerfile: {e}")
            if args.ci_mode:
                print(f"::error::Could not read Dockerfile: {e}")
            return 1

        # Create output directory
        output_dir = os.path.abspath(args.output_dir)
        os.makedirs(output_dir, exist_ok=True)
        logger.info(f"Output directory: {output_dir}")

        # Parse stages
        stages = parse_dockerfile_stages(original_dockerfile)
        if not stages:
            logger.error("No valid FROM line found in Dockerfile")
            if args.ci_mode:
                print("::error::No valid FROM line found in Dockerfile")
            return 1

        base_image_name = stages[0]['base_name'].split("/")[-1].lower() or "image"
        local_orig = f"{base_image_name}-orig"
        local_patched = f"{base_image_name}-patched"
        registry = args.registry.rstrip("/")
        registry_patched = f"{registry}/{base_image_name}-patched:latest"

        logger.info(f"Base image: {stages[0]['base_image']}")

        # PIPELINE STEP 1: Build original image
        logger.info("[1/22] Building original image...")
        success, error_cat = build_image(local_orig, dockerfile_path)
        if not success:
            logger.error(f"Failed to build original image ({error_cat})")
            if args.ci_mode:
                print(f"::error::Failed to build original image: {error_cat}")
            return 1

        # PIPELINE STEP 2-3: Scan original image
        logger.info("[2/22] Scanning original image for vulnerabilities...")
        try:
            before_scan = scan_image(local_orig, os.path.join(output_dir, "trivy-before.json"))
        except ScanError as e:
            logger.error(f"Scan failed: {e}")
            if args.ci_mode:
                print(f"::error::Scan failed: {e}")
            return 1

        before_summary = summarize_vulnerabilities(before_scan)
        logger.info(f"Vulnerabilities BEFORE: {before_summary}")

        # PIPELINE STEP 4: Generate SBOM
        logger.info("[3/22] Generating SBOM for original image...")
        try:
            sbom_before = generate_sbom(local_orig, os.path.join(output_dir, "sbom-before.json"))
        except ScanError as e:
            logger.warning(f"SBOM generation failed (non-critical): {e}")
            sbom_before = {}

        # PIPELINE STEP 5: SBOM inference
        logger.info("[4/22] Analyzing SBOM for OS, language, and compatibility...")
        inference = analyze_sbom(sbom_before)
        logger.info(
            f"Inference result: OS={inference.os_family}, "
            f"lang={inference.language}:{inference.language_version}, "
            f"glibc_needed={inference.needs_glibc}, "
            f"confidence={inference.confidence:.2f}"
        )
        if inference.needs_glibc:
            logger.info("glibc dependency detected — will prefer -slim variants over Alpine")

        # PIPELINE STEP 6: Parse and patch Dockerfile
        logger.info("[5/22] Patching Dockerfile using SBOM inference...")
        base_map = load_base_mapping(args.base_mapping) if args.base_mapping else None
        patched_text, base_changes, patch_warnings, diff_text = patch_dockerfile(
            original_dockerfile,
            sbom_before,
            base_mapping=base_map,
            patch_final_only=args.patch_final_only
        )

        for warning in patch_warnings:
            logger.warning(f"Patch warning: {warning}")

        # PIPELINE STEP 7: Save patched Dockerfile
        patched_dockerfile_path = os.path.join(output_dir, "Dockerfile.patched")
        try:
            with open(patched_dockerfile_path, "w", encoding="utf-8") as f:
                f.write(patched_text)
            logger.info(f"Patched Dockerfile saved to {patched_dockerfile_path}")
        except Exception as e:
            logger.error(f"Failed to write patched Dockerfile: {e}")
            if args.ci_mode:
                print(f"::error::Failed to write patched Dockerfile: {e}")
            return 1

        # Save diff
        diff_path = os.path.join(output_dir, "dockerfile.diff")
        try:
            with open(diff_path, "w", encoding="utf-8") as f:
                f.write(diff_text)
        except Exception as e:
            logger.warning(f"Failed to save diff: {e}")

        if base_changes:
            logger.info("Base image changes:")
            for orig, new in base_changes:
                logger.info(f"  {orig} -> {new}")

        # PIPELINE STEP 8: Dry-run check
        if args.dry_run:
            logger.info("[DRY-RUN] Skipping build, push, sign, and scan")
            logger.info(f"Patched Dockerfile available at: {patched_dockerfile_path}")

            # Generate dry-run report
            report_text = _generate_markdown_report(
                {},
                base_changes,
                before_summary,
                {},
                {"resolved": [], "remaining": [], "new": []},
                {"added": [], "removed": [], "updated": []},
                True,
                [],
                patched_dockerfile_path,
                diff_text
            )
            report_file = os.path.join(output_dir, "report.md")
            with open(report_file, "w") as f:
                f.write(report_text)
            logger.info(f"Report saved to {report_file}")
            return 0

        # PIPELINE STEP 9: Build patched image
        logger.info("[6/22] Building patched image...")
        success, error_cat = build_image(local_patched, patched_dockerfile_path)
        if not success:
            logger.error(f"Failed to build patched image ({error_cat})")
            if args.ci_mode:
                print(f"::error::Failed to build patched image: {error_cat}")
            return 1

        # PIPELINE STEP 9b: Smoke test if enabled
        if args.smoke_test:
            logger.info("[6b/22] Running smoke test on patched image...")
            smoke_passed, smoke_msg = smoke_test_image(local_patched)
            if not smoke_passed:
                logger.error(f"Smoke test FAILED: {smoke_msg}")
                logger.error("The patched image crashes at runtime. This often means "
                           "the base image switch introduced a libc incompatibility. "
                           "Try using --base-mapping to select a -slim variant instead of Alpine.")
                if args.ci_mode:
                    print(f"::error::Smoke test failed: {smoke_msg}")
                return 1
            logger.info(f"Smoke test passed: {smoke_msg}")

        # PIPELINE STEP 10: Test if --test-cmd provided
        if args.test_cmd:
            logger.info(f"[7/22] Running test command: {args.test_cmd}")
            code, output = run_cmd(["docker", "run", "--rm", "--entrypoint", "", local_patched, "sh", "-c", args.test_cmd])
            if code != 0:
                logger.error(f"Test command failed: {output}")
                if args.ci_mode:
                    print(f"::error::Test command failed with exit code {code}")
                return 1
            logger.info("Test command passed")

        # PIPELINE STEP 11: Tag and push
        logger.info("[8/22] Tagging and pushing patched image...")
        if not tag_image(local_patched, registry_patched):
            logger.error("Failed to tag image")
            if args.ci_mode:
                print("::error::Failed to tag image")
            return 1

        if not push_image(registry_patched):
            logger.error("Failed to push image")
            if args.ci_mode:
                print("::error::Failed to push image")
            return 1

        # PIPELINE STEP 12: Get digest
        logger.info("[9/22] Retrieving image digest...")
        run_cmd(["docker", "rmi", "-f", local_patched])
        code, output = run_cmd(["docker", "pull", registry_patched])
        if code != 0:
            logger.error(f"Failed to pull image from registry: {output}")
            if args.ci_mode:
                print(f"::error::Failed to pull image from registry")
            return 1

        digest_ref = get_image_digest(registry_patched)
        if not digest_ref:
            logger.error("Could not retrieve image digest")
            if args.ci_mode:
                print("::error::Could not retrieve image digest")
            return 1
        logger.info(f"Image digest: {digest_ref}")

        # PIPELINE STEP 13-14: Sign and verify
        if signing_mode != "none":
            logger.info(f"[10/22] Signing image ({signing_mode})...")
            try:
                sign_image(digest_ref, signing_mode)
                verify_image(digest_ref, signing_mode)
                logger.info("Image signed and verified")
            except (SigningError, VerificationError) as e:
                logger.error(f"Signing/verification failed: {e}")
                if args.ci_mode:
                    print(f"::error::Signing failed: {e}")
                return 1

        # PIPELINE STEP 15: Generate post-patch SBOM
        logger.info("[11/22] Generating SBOM for patched image...")
        try:
            sbom_after = generate_sbom(registry_patched, os.path.join(output_dir, "sbom-after.json"))
        except ScanError as e:
            logger.warning(f"SBOM generation failed (non-critical): {e}")
            sbom_after = {}

        # PIPELINE STEP 16: Attach SBOM
        if sbom_after and signing_mode != "none":
            logger.info("[12/22] Attaching SBOM to image...")
            try:
                attach_sbom(digest_ref, os.path.join(output_dir, "sbom-after.json"), signing_mode)
                logger.info("SBOM attached")
            except Exception as e:
                logger.warning(f"SBOM attachment failed (non-critical): {e}")

        # PIPELINE STEP 17: Scan patched image
        logger.info("[13/22] Scanning patched image for vulnerabilities...")
        try:
            after_scan = scan_image(registry_patched, os.path.join(output_dir, "trivy-after.json"))
        except ScanError as e:
            logger.error(f"Scan failed: {e}")
            if args.ci_mode:
                print(f"::error::Scan of patched image failed: {e}")
            return 1

        after_summary = summarize_vulnerabilities(after_scan)
        logger.info(f"Vulnerabilities AFTER: {after_summary}")

        # PIPELINE STEP 18: Check acceptance criteria
        logger.info("[14/22] Checking acceptance criteria...")
        accepted, acceptance_reasons = check_acceptance_criteria(before_scan, after_scan)
        if accepted:
            logger.info("ACCEPTANCE CHECK PASSED")
        else:
            logger.error("ACCEPTANCE CHECK FAILED")
            for reason in acceptance_reasons:
                logger.error(f"  - {reason}")
            if args.ci_mode:
                for reason in acceptance_reasons:
                    print(f"::error::{reason}")

        # PIPELINE STEP 19: Compute diffs and metrics
        logger.info("[15/22] Computing metrics...")
        vulns_diff = diff_vulnerabilities(before_scan, after_scan)
        sbom_diff = diff_sbom(sbom_before or {}, sbom_after or {})

        before_size = measure_image_size(local_orig)
        after_size = measure_image_size(registry_patched)

        metrics = compute_metrics(
            before_scan, after_scan,
            sbom_before or {}, sbom_after or {},
            before_size=before_size,
            after_size=after_size
        )

        # PIPELINE STEP 20: Generate report
        logger.info("[16/22] Generating report...")
        if report_format == "json":
            report_text = _generate_json_report(
                metrics, base_changes, before_summary, after_summary,
                vulns_diff, sbom_diff, get_signing_log()
            )
        elif report_format == "markdown":
            report_text = _generate_markdown_report(
                metrics, base_changes, before_summary, after_summary,
                vulns_diff, sbom_diff, accepted, acceptance_reasons,
                patched_dockerfile_path, diff_text
            )
        else:  # html
            report_text = _generate_html_report(
                metrics, base_changes, before_summary, after_summary,
                vulns_diff, sbom_diff, accepted, acceptance_reasons
            )

        # PIPELINE STEP 21: Export reports
        logger.info("[17/22] Exporting reports...")
        report_ext = {"json": "json", "markdown": "md", "html": "html"}[report_format]
        report_file = os.path.join(output_dir, f"report.{report_ext}")
        try:
            with open(report_file, "w") as f:
                f.write(report_text)
            logger.info(f"Report saved to {report_file}")
        except Exception as e:
            logger.error(f"Failed to save report: {e}")

        # Print report to stdout
        print(report_text)

        # PIPELINE STEP 22: Export metrics as JSON and CSV
        logger.info("[18/22] Exporting metrics...")
        metrics_json = os.path.join(output_dir, "metrics.json")
        metrics_csv = os.path.join(output_dir, "metrics.csv")

        try:
            save_json(metrics, metrics_json)
            save_csv([metrics], metrics_csv)
            logger.info(f"Metrics saved to {metrics_json} and {metrics_csv}")
        except Exception as e:
            logger.warning(f"Failed to save metrics: {e}")

        # Output GitHub Actions annotations if in CI mode
        if args.ci_mode:
            logger.info("[19/22] Outputting GitHub Actions annotations...")
            if not accepted:
                print("::error::Patched image failed acceptance criteria")
            else:
                print(f"::notice::Patched image accepted. Vulnerabilities reduced by {metrics.get('vulnerability_reduction_pct', 0):.1f}%")

        logger.info("[20/22] Cleanup...")
        run_cmd(["docker", "rmi", "-f", local_orig])

        logger.info("[21/22] Pipeline complete")
        logger.info(f"All artifacts saved to: {output_dir}")

        # Exit code: 0 if accepted, 1 if rejected
        exit_code = 0 if accepted else 1
        if args.ci_mode:
            sys.exit(exit_code)
        return exit_code

    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        if args.ci_mode:
            print(f"::error::Unexpected error: {e}")
        return 1

    finally:
        # Cleanup temp repo if cloned
        if temp_repo_dir and os.path.exists(temp_repo_dir):
            logger.debug(f"Cleaning up temporary directory: {temp_repo_dir}")
            shutil.rmtree(temp_repo_dir, ignore_errors=True)


if __name__ == "__main__":
    exit(main())
