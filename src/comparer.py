import logging
import json
import csv
from typing import Dict, List, Tuple, Optional, Any

logger = logging.getLogger("docker_patch_tool")

SEVERITY_LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]


def diff_vulnerabilities(before_scan: Dict[str, Any], after_scan: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    """
    Compare vulnerabilities between before and after scans.

    Args:
        before_scan: Vulnerability scan result before patching
        after_scan: Vulnerability scan result after patching

    Returns:
        Dict with keys 'resolved', 'remaining', 'new' containing vulnerability lists.
        Each vulnerability has: id, package, severity, version, fix_version.
    """
    def extract_vulns(scan: Dict[str, Any]) -> List[Dict[str, Any]]:
        vulns = []
        for result in scan.get("Results", []):
            for v in result.get("Vulnerabilities", []):
                vulns.append({
                    "id": v.get("VulnerabilityID"),
                    "package": v.get("PkgName"),
                    "version": v.get("InstalledVersion"),
                    "severity": v.get("Severity"),
                    "fix_version": v.get("FixedVersion", "")
                })
        return vulns

    before_list = extract_vulns(before_scan)
    after_list = extract_vulns(after_scan)
    before_keys = {(v['id'], v['package']) for v in before_list}
    after_keys = {(v['id'], v['package']) for v in after_list}
    resolved = [v for v in before_list if (v['id'], v['package']) not in after_keys]
    remaining = [v for v in after_list if (v['id'], v['package']) in before_keys]
    new = [v for v in after_list if (v['id'], v['package']) not in before_keys]
    return {"resolved": resolved, "remaining": remaining, "new": new}


def diff_sbom(before_sbom: Dict[str, Any], after_sbom: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    """
    Compare SBOM components of original and patched images.

    Args:
        before_sbom: Software Bill of Materials before patching
        after_sbom: Software Bill of Materials after patching

    Returns:
        Dict with keys 'added', 'removed', 'updated' containing component lists.
        Each component has: name, type, old_version (removed/updated), new_version (added/updated).
    """
    before_components = {}
    after_components = {}

    def load_components(sbom: Dict[str, Any], comp_dict: Dict[Tuple[str, str], str]) -> None:
        comps = sbom.get("components") or sbom.get("Components") or []
        for comp in comps:
            name = comp.get("name") or comp.get("Name")
            comp_type = comp.get("type") or comp.get("Type") or "library"
            version = comp.get("version") or comp.get("Version")
            if name:
                comp_dict[(name, comp_type)] = version

    load_components(before_sbom, before_components)
    load_components(after_sbom, after_components)

    added = []
    removed = []
    updated = []

    for (name, comp_type), old_ver in before_components.items():
        if (name, comp_type) not in after_components:
            removed.append({"name": name, "type": comp_type, "old_version": old_ver})
        else:
            new_ver = after_components[(name, comp_type)]
            if old_ver != new_ver:
                updated.append({"name": name, "type": comp_type, "old_version": old_ver, "new_version": new_ver})

    for (name, comp_type), new_ver in after_components.items():
        if (name, comp_type) not in before_components:
            added.append({"name": name, "type": comp_type, "new_version": new_ver})

    return {"added": added, "removed": removed, "updated": updated}


def compare(before_summary: Dict[str, int], after_summary: Dict[str, int]) -> Dict[str, int]:
    """
    Compute simple vulnerability count reduction from before_summary to after_summary.

    Args:
        before_summary: Dict mapping severity to vulnerability count before patching
        after_summary: Dict mapping severity to vulnerability count after patching

    Returns:
        Dict with count reduction (before - after) for each severity.
    """
    diff = {}
    for severity, before_count in before_summary.items():
        after_count = after_summary.get(severity, 0)
        diff[severity] = before_count - after_count
    return diff


def _count_vulnerabilities_by_severity(scan: Dict[str, Any]) -> Dict[str, int]:
    """
    Count vulnerabilities grouped by severity level.

    Args:
        scan: Vulnerability scan result

    Returns:
        Dict mapping severity levels to counts. Missing levels default to 0.
    """
    counts = {sev: 0 for sev in SEVERITY_LEVELS}
    for result in scan.get("Results", []):
        for v in result.get("Vulnerabilities", []):
            severity = v.get("Severity", "UNKNOWN")
            if severity in counts:
                counts[severity] += 1
            else:
                counts["UNKNOWN"] += 1
    return counts


def compute_metrics(
    before_scan: Dict[str, Any],
    after_scan: Dict[str, Any],
    before_sbom: Dict[str, Any],
    after_sbom: Dict[str, Any],
    build_time: Optional[float] = None,
    before_size: Optional[float] = None,
    after_size: Optional[float] = None
) -> Dict[str, Any]:
    """
    Compute comprehensive metrics comparing before and after patches.

    Args:
        before_scan: Vulnerability scan before patching
        after_scan: Vulnerability scan after patching
        before_sbom: SBOM before patching
        after_sbom: SBOM after patching
        build_time: Build time in seconds (optional)
        before_size: Image size before patching in MB (optional)
        after_size: Image size after patching in MB (optional)

    Returns:
        Dict containing:
            - total_before, total_after: Total vulnerability counts
            - per_severity_before, per_severity_after: Counts by severity
            - vulnerability_reduction_pct: Percentage reduction
            - cve_resolution_rate: (resolved / total_original)
            - new_vulnerabilities_count: Count of new vulnerabilities
            - sbom_components_added/removed/updated: SBOM change counts
            - build_time_seconds: Build duration
            - image_size_before_mb, image_size_after_mb, image_size_delta_mb: Size metrics
    """
    # Get vulnerability diffs
    vuln_diff = diff_vulnerabilities(before_scan, after_scan)

    # Count by severity
    per_severity_before = _count_vulnerabilities_by_severity(before_scan)
    per_severity_after = _count_vulnerabilities_by_severity(after_scan)

    total_before = sum(per_severity_before.values())
    total_after = sum(per_severity_after.values())

    # Compute reduction percentage
    vulnerability_reduction_pct = 0.0
    if total_before > 0:
        vulnerability_reduction_pct = ((total_before - total_after) / total_before) * 100

    # Compute CVE resolution rate
    resolved_count = len(vuln_diff.get("resolved", []))
    cve_resolution_rate = 0.0
    if total_before > 0:
        cve_resolution_rate = (resolved_count / total_before) * 100

    new_vuln_count = len(vuln_diff.get("new", []))

    # Get SBOM diffs
    sbom_diff = diff_sbom(before_sbom, after_sbom)

    metrics = {
        "total_before": total_before,
        "total_after": total_after,
        "per_severity_before": per_severity_before,
        "per_severity_after": per_severity_after,
        "vulnerability_reduction_pct": round(vulnerability_reduction_pct, 2),
        "cve_resolution_rate": round(cve_resolution_rate, 2),
        "new_vulnerabilities_count": new_vuln_count,
        "sbom_components_added": len(sbom_diff.get("added", [])),
        "sbom_components_removed": len(sbom_diff.get("removed", [])),
        "sbom_components_updated": len(sbom_diff.get("updated", [])),
    }

    if build_time is not None:
        metrics["build_time_seconds"] = round(build_time, 2)

    if before_size is not None:
        metrics["image_size_before_mb"] = round(before_size, 2)

    if after_size is not None:
        metrics["image_size_after_mb"] = round(after_size, 2)

    if before_size is not None and after_size is not None:
        metrics["image_size_delta_mb"] = round(after_size - before_size, 2)

    return metrics


def check_acceptance_criteria(
    before_scan: Dict[str, Any],
    after_scan: Dict[str, Any]
) -> Tuple[bool, List[str]]:
    """
    Check if patched image meets formal acceptance criteria.

    Acceptance predicate:
        Accept(I') iff:
            - build_success = True (checked by caller) AND
            - |CVE_critical(I')| <= |CVE_critical(I)| AND
            - |CVE_high(I')| <= |CVE_high(I)| AND
            - |CVE_total(I')| < |CVE_total(I)|

    Note: New CVE IDs may appear when switching OS families (e.g., Ubuntu to
    Alpine), even when total vulnerability count drops significantly. The
    acceptance criteria therefore focus on severity-level counts rather than
    individual CVE identity, which is the scientifically sound approach for
    cross-OS remediation.

    Args:
        before_scan: Vulnerability scan before patching
        after_scan: Vulnerability scan after patching

    Returns:
        Tuple of (accepted: bool, reasons: list of rejection reasons if any)
    """
    reasons = []

    # Count by severity
    before_counts = _count_vulnerabilities_by_severity(before_scan)
    after_counts = _count_vulnerabilities_by_severity(after_scan)

    # Check CRITICAL constraint
    if after_counts["CRITICAL"] > before_counts["CRITICAL"]:
        reasons.append(
            f"CRITICAL vulnerabilities increased: {before_counts['CRITICAL']} -> {after_counts['CRITICAL']}"
        )

    # Check HIGH constraint
    if after_counts["HIGH"] > before_counts["HIGH"]:
        reasons.append(
            f"HIGH vulnerabilities increased: {before_counts['HIGH']} -> {after_counts['HIGH']}"
        )

    # Check total reduction constraint
    total_before = sum(before_counts.values())
    total_after = sum(after_counts.values())
    if total_after >= total_before:
        reasons.append(
            f"Total vulnerabilities did not decrease: {total_before} -> {total_after}"
        )

    accepted = len(reasons) == 0
    return accepted, reasons


def export_metrics_json(metrics: Dict[str, Any], filepath: str) -> None:
    """
    Save metrics dict to JSON file.

    Args:
        metrics: Metrics dictionary from compute_metrics()
        filepath: Output JSON file path
    """
    with open(filepath, 'w') as f:
        json.dump(metrics, f, indent=2)
    logger.info(f"Metrics exported to {filepath}")


def export_metrics_csv(metrics_list: List[Dict[str, Any]], filepath: str) -> None:
    """
    Save list of metrics dicts to CSV file.

    Args:
        metrics_list: List of metrics dictionaries
        filepath: Output CSV file path
    """
    if not metrics_list:
        logger.warning("No metrics to export")
        return

    # Flatten nested dicts for CSV
    flattened = []
    for metrics in metrics_list:
        flat = {}
        for key, value in metrics.items():
            if isinstance(value, dict):
                # Flatten nested dict with dot notation
                for nested_key, nested_val in value.items():
                    flat[f"{key}.{nested_key}"] = nested_val
            else:
                flat[key] = value
        flattened.append(flat)

    fieldnames = set()
    for row in flattened:
        fieldnames.update(row.keys())
    fieldnames = sorted(list(fieldnames))

    with open(filepath, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(flattened)

    logger.info(f"Metrics exported to {filepath}")
