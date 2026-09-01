#!/usr/bin/env python3
"""Enforce Semgrep SAST and OWASP ZAP DAST policy thresholds.

Usage:
    python3 scripts/security-gate.py REPORT_DIRECTORY

Environment variables:
    FAIL_ON_SAST: NONE, INFO, WARNING, or ERROR (default: ERROR)
    FAIL_ON_ZAP_RISK: NONE, INFORMATIONAL, INFO, LOW, MEDIUM, or HIGH
                      (default: HIGH)

Exit codes:
    0: Policy passed
    1: Policy failed because blocking findings were detected
    2: Usage, configuration, missing mandatory report, or parsing error
"""

from __future__ import annotations

import json
import os
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterator

SAST_LEVELS: dict[str, int] = {
    "INFO": 1,
    "WARNING": 2,
    "ERROR": 3,
    "NONE": 10_000,
}

ZAP_LEVELS: dict[str, int] = {
    "INFORMATIONAL": 0,
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "NONE": 10_000,
}


def normalize(value: Any) -> str:
    """Return an uppercase, trimmed string for policy comparisons."""
    return str(value or "").strip().upper()


def find_report(root: Path, filename: str) -> Path | None:
    """Find a report directly under root or recursively below root."""
    direct = root / filename
    if direct.is_file():
        return direct

    matches = sorted(path for path in root.rglob(filename) if path.is_file())
    return matches[0] if matches else None


def load_json(path: Path) -> dict[str, Any]:
    """Load a JSON object and return a useful error for invalid input."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise RuntimeError(f"Unable to read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"Invalid JSON in {path} at line {exc.lineno}, "
            f"column {exc.colno}: {exc.msg}"
        ) from exc

    if not isinstance(data, dict):
        raise RuntimeError(f"Expected a JSON object in {path}")

    return data


def workflow_command_escape(value: Any) -> str:
    """Escape a GitHub Actions workflow-command message."""
    return (
        str(value)
        .replace("%", "%25")
        .replace("\r", "%0D")
        .replace("\n", "%0A")
    )


def workflow_property_escape(value: Any) -> str:
    """Escape a GitHub Actions workflow-command property."""
    return (
        workflow_command_escape(value)
        .replace(":", "%3A")
        .replace(",", "%2C")
    )


def emit_annotation(
    level: str,
    message: str,
    *,
    file: str = "",
    line: Any = "",
    title: str = "OWASP security policy gate",
) -> None:
    """Emit a GitHub Actions error or warning annotation."""
    properties = [f"title={workflow_property_escape(title)}"]

    if file:
        properties.append(f"file={workflow_property_escape(file)}")

    line_text = str(line)
    if line_text.isdigit() and int(line_text) > 0:
        properties.append(f"line={line_text}")

    print(
        f"::{level} {','.join(properties)}::"
        f"{workflow_command_escape(message)}"
    )


def semgrep_severity(result: dict[str, Any]) -> str:
    """Extract a supported severity from a Semgrep result."""
    extra = result.get("extra", {})
    if not isinstance(extra, dict):
        return "INFO"

    severity = normalize(extra.get("severity", "INFO"))
    return severity if severity in {"INFO", "WARNING", "ERROR"} else "INFO"


def evaluate_sast(
    root: Path,
    threshold_name: str,
) -> tuple[list[dict[str, Any]], Counter[str], Path]:
    """Evaluate Semgrep findings against the configured threshold."""
    report_path = find_report(root, "semgrep.json")
    if report_path is None:
        raise RuntimeError(
            "Mandatory SAST report semgrep.json was not found under "
            f"{root}"
        )

    report = load_json(report_path)
    results = report.get("results", [])
    if not isinstance(results, list):
        raise RuntimeError(f"{report_path}: 'results' must be a JSON array")

    threshold = SAST_LEVELS[threshold_name]
    counts: Counter[str] = Counter()
    blocking: list[dict[str, Any]] = []

    for result in results:
        if not isinstance(result, dict):
            continue

        severity = semgrep_severity(result)
        counts[severity] += 1

        if threshold_name == "NONE" or SAST_LEVELS[severity] < threshold:
            continue

        extra = result.get("extra", {})
        if not isinstance(extra, dict):
            extra = {}

        start = result.get("start", {})
        if not isinstance(start, dict):
            start = {}

        metadata = extra.get("metadata", {})
        if not isinstance(metadata, dict):
            metadata = {}

        cwe = metadata.get("cwe", "")
        if isinstance(cwe, list):
            cwe = ", ".join(str(item) for item in cwe)
        elif cwe is None:
            cwe = ""
        else:
            cwe = str(cwe)

        blocking.append(
            {
                "severity": severity,
                "rule": str(result.get("check_id", "unknown-rule")),
                "file": str(result.get("path", "unknown-file")),
                "line": start.get("line", ""),
                "message": str(
                    extra.get("message", "Semgrep policy violation")
                ),
                "cwe": cwe,
            }
        )

    return blocking, counts, report_path


def iter_zap_alerts(
    report: dict[str, Any],
) -> Iterator[tuple[str, dict[str, Any]]]:
    """Yield site name and alert pairs from a traditional ZAP JSON report."""
    sites = report.get("site", [])
    if not isinstance(sites, list):
        return

    for site in sites:
        if not isinstance(site, dict):
            continue

        site_name = str(
            site.get("@name") or site.get("name") or "unknown-site"
        )
        alerts = site.get("alerts", [])
        if not isinstance(alerts, list):
            continue

        for alert in alerts:
            if isinstance(alert, dict):
                yield site_name, alert


def canonical_zap_risk(alert: dict[str, Any]) -> str:
    """Normalize textual or numeric ZAP risk values."""
    raw_risk = normalize(
        alert.get("riskdesc")
        or alert.get("risk")
        or alert.get("riskcode")
    )

    if "HIGH" in raw_risk or raw_risk == "3":
        return "HIGH"
    if "MEDIUM" in raw_risk or raw_risk == "2":
        return "MEDIUM"
    if "LOW" in raw_risk or raw_risk == "1":
        return "LOW"
    return "INFORMATIONAL"


def evaluate_dast(
    root: Path,
    threshold_name: str,
) -> tuple[list[dict[str, Any]], Counter[str], Path | None]:
    """Evaluate a ZAP report. A missing report means DAST was skipped."""
    report_path = find_report(root, "zap.json")
    if report_path is None:
        return [], Counter(), None

    report = load_json(report_path)
    threshold = ZAP_LEVELS[threshold_name]
    counts: Counter[str] = Counter()
    blocking: list[dict[str, Any]] = []

    for site_name, alert in iter_zap_alerts(report):
        risk = canonical_zap_risk(alert)
        counts[risk] += 1

        if threshold_name == "NONE" or ZAP_LEVELS[risk] < threshold:
            continue

        blocking.append(
            {
                "risk": risk,
                "name": str(
                    alert.get("alert")
                    or alert.get("name")
                    or "Unknown ZAP alert"
                ),
                "site": site_name,
                "plugin_id": str(
                    alert.get("pluginid") or alert.get("pluginId") or ""
                ),
            }
        )

    return blocking, counts, report_path


def append_job_summary(
    *,
    sast_threshold: str,
    sast_counts: Counter[str],
    sast_blocking: list[dict[str, Any]],
    sast_report: Path,
    zap_threshold: str,
    zap_counts: Counter[str],
    zap_blocking: list[dict[str, Any]],
    zap_report: Path | None,
    passed: bool,
) -> None:
    """Append a concise Markdown report to the GitHub Actions job summary."""
    summary_file = os.getenv("GITHUB_STEP_SUMMARY")
    if not summary_file:
        return

    lines = [
        "## OWASP security policy gate",
        "",
        f"**Result:** {'Passed' if passed else 'Failed'}",
        "",
        f"- SAST threshold: `{sast_threshold}`",
        f"- ZAP threshold: `{zap_threshold}`",
        f"- Semgrep report: `{sast_report}`",
        f"- ZAP report: `{zap_report}`" if zap_report else "- ZAP report: not present",
        "",
        "### SAST results",
        "",
        f"- ERROR: {sast_counts.get('ERROR', 0)}",
        f"- WARNING: {sast_counts.get('WARNING', 0)}",
        f"- INFO: {sast_counts.get('INFO', 0)}",
        f"- Blocking findings: {len(sast_blocking)}",
        "",
        "### DAST results",
        "",
    ]

    if zap_report:
        lines.extend(
            [
                f"- High: {zap_counts.get('HIGH', 0)}",
                f"- Medium: {zap_counts.get('MEDIUM', 0)}",
                f"- Low: {zap_counts.get('LOW', 0)}",
                f"- Informational: {zap_counts.get('INFORMATIONAL', 0)}",
                f"- Blocking findings: {len(zap_blocking)}",
            ]
        )
    else:
        lines.append("- DAST was skipped or disabled; no ZAP report was found.")

    if sast_blocking:
        lines.extend(["", "### Blocking SAST findings", ""])
        for finding in sast_blocking[:100]:
            lines.append(
                f"- **{finding['severity']}** `{finding['rule']}` at "
                f"`{finding['file']}:{finding['line']}`: "
                f"{finding['message']}"
            )

    if zap_blocking:
        lines.extend(["", "### Blocking DAST findings", ""])
        for finding in zap_blocking[:100]:
            plugin = (
                f" (plugin `{finding['plugin_id']}`)"
                if finding["plugin_id"]
                else ""
            )
            lines.append(
                f"- **{finding['risk']}** {finding['name']} on "
                f"`{finding['site']}`{plugin}"
            )

    lines.append("")

    try:
        with Path(summary_file).open("a", encoding="utf-8") as handle:
            handle.write("\n".join(lines))
    except OSError as exc:
        print(f"Warning: unable to write GitHub job summary: {exc}", file=sys.stderr)


def validate_threshold(name: str, value: str, allowed: dict[str, int]) -> None:
    if value not in allowed:
        valid_values = ", ".join(allowed)
        raise RuntimeError(
            f"Invalid {name} value '{value}'. Allowed values: {valid_values}"
        )


def main() -> int:
    if len(sys.argv) != 2:
        print(
            f"Usage: {Path(sys.argv[0]).name} REPORT_DIRECTORY",
            file=sys.stderr,
        )
        return 2

    root = Path(sys.argv[1])
    if not root.is_dir():
        message = f"Report directory does not exist: {root}"
        emit_annotation("error", message)
        print(message, file=sys.stderr)
        return 2

    sast_threshold = normalize(os.getenv("FAIL_ON_SAST", "ERROR"))
    zap_threshold = normalize(os.getenv("FAIL_ON_ZAP_RISK", "HIGH"))

    try:
        validate_threshold("FAIL_ON_SAST", sast_threshold, SAST_LEVELS)
        validate_threshold("FAIL_ON_ZAP_RISK", zap_threshold, ZAP_LEVELS)

        sast_blocking, sast_counts, sast_report = evaluate_sast(
            root, sast_threshold
        )
        zap_blocking, zap_counts, zap_report = evaluate_dast(
            root, zap_threshold
        )
    except RuntimeError as exc:
        emit_annotation("error", str(exc))
        print(f"Security gate configuration error: {exc}", file=sys.stderr)
        return 2

    print("OWASP security policy gate")
    print(f"Report directory: {root}")
    print(f"Semgrep report: {sast_report}")
    print(f"SAST threshold: {sast_threshold}")
    print(f"ZAP threshold: {zap_threshold}")
    print()

    print("SAST severity counts:")
    print(f"  ERROR: {sast_counts.get('ERROR', 0)}")
    print(f"  WARNING: {sast_counts.get('WARNING', 0)}")
    print(f"  INFO: {sast_counts.get('INFO', 0)}")

    if zap_report:
        print(f"ZAP report: {zap_report}")
        print("ZAP risk counts:")
        print(f"  High: {zap_counts.get('HIGH', 0)}")
        print(f"  Medium: {zap_counts.get('MEDIUM', 0)}")
        print(f"  Low: {zap_counts.get('LOW', 0)}")
        print(f"  Informational: {zap_counts.get('INFORMATIONAL', 0)}")
    else:
        print("ZAP report: not present; DAST treated as skipped or disabled")

    if sast_blocking:
        print("\nBlocking SAST findings:")
        for finding in sast_blocking:
            print(
                f"  [{finding['severity']}] {finding['rule']} at "
                f"{finding['file']}:{finding['line']}"
            )
            print(f"    {finding['message']}")
            if finding["cwe"]:
                print(f"    CWE: {finding['cwe']}")

            emit_annotation(
                "error",
                f"[{finding['severity']}] {finding['rule']}: "
                f"{finding['message']}",
                file=finding["file"],
                line=finding["line"],
                title="Blocking Semgrep finding",
            )

    if zap_blocking:
        print("\nBlocking DAST findings:")
        for finding in zap_blocking:
            plugin = (
                f" (plugin {finding['plugin_id']})"
                if finding["plugin_id"]
                else ""
            )
            print(
                f"  [{finding['risk']}] {finding['name']} on "
                f"{finding['site']}{plugin}"
            )
            emit_annotation(
                "error",
                f"[{finding['risk']}] ZAP {finding['name']} on "
                f"{finding['site']}{plugin}",
                title="Blocking OWASP ZAP finding",
            )

    passed = not sast_blocking and not zap_blocking

    append_job_summary(
        sast_threshold=sast_threshold,
        sast_counts=sast_counts,
        sast_blocking=sast_blocking,
        sast_report=sast_report,
        zap_threshold=zap_threshold,
        zap_counts=zap_counts,
        zap_blocking=zap_blocking,
        zap_report=zap_report,
        passed=passed,
    )

    if not passed:
        print(
            "\nSecurity gate failed: "
            f"{len(sast_blocking)} blocking SAST finding(s), "
            f"{len(zap_blocking)} blocking DAST finding(s)."
        )
        return 1

    print("\nSecurity gate passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

