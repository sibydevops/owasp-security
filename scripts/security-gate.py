#!/usr/bin/env python3
"""Apply security policy thresholds to Semgrep and OWASP ZAP reports.

Usage:
    python3 scripts/security-gate.py REPORT_DIRECTORY

Environment variables:
    FAIL_ON_SAST:
        NONE, INFO, WARNING, or ERROR

    FAIL_ON_ZAP_RISK:
        NONE, INFORMATIONAL, INFO, LOW, MEDIUM, or HIGH

Exit codes:
    0: Security policy passed
    1: Blocking security findings were detected
    2: Configuration, invocation, or report error
"""

from __future__ import annotations

import json
import os
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterator

SAST_LEVELS = {
    "INFO": 1,
    "WARNING": 2,
    "ERROR": 3,
    "NONE": 10_000,
}

ZAP_LEVELS = {
    "INFORMATIONAL": 0,
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "NONE": 10_000,
}


def normalize(value: Any) -> str:
    """Normalize a policy value for comparison."""
    return str(value or "").strip().upper()


def find_report(
    root: Path,
    filename: str,
) -> Path | None:
    """Find a report directly or recursively under the report directory."""
    direct_path = root / filename

    if direct_path.is_file():
        return direct_path

    matches = sorted(
        path
        for path in root.rglob(filename)
        if path.is_file()
    )

    return matches[0] if matches else None


def load_json(path: Path) -> dict[str, Any]:
    """Load and validate a JSON report."""
    try:
        report = json.loads(
            path.read_text(encoding="utf-8")
        )
    except OSError as exc:
        raise RuntimeError(
            f"Unable to read {path}: {exc}"
        ) from exc
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"Invalid JSON in {path} at line "
            f"{exc.lineno}, column {exc.colno}: "
            f"{exc.msg}"
        ) from exc

    if not isinstance(report, dict):
        raise RuntimeError(
            f"{path} must contain a JSON object"
        )

    return report


def command_escape(value: Any) -> str:
    """Escape text used in a GitHub Actions command message."""
    return (
        str(value)
        .replace("%", "%25")
        .replace("\r", "%0D")
        .replace("\n", "%0A")
    )


def property_escape(value: Any) -> str:
    """Escape a property used in a GitHub Actions command."""
    return (
        command_escape(value)
        .replace(":", "%3A")
        .replace(",", "%2C")
    )


def emit_error(
    message: str,
    *,
    file: str = "",
    line: Any = "",
    title: str = "OWASP security policy gate",
) -> None:
    """Create a GitHub Actions error annotation."""
    properties = [
        f"title={property_escape(title)}"
    ]

    if file:
        properties.append(
            f"file={property_escape(file)}"
        )

    line_text = str(line)

    if line_text.isdigit() and int(line_text) > 0:
        properties.append(f"line={line_text}")

    print(
        f"::error {','.join(properties)}::"
        f"{command_escape(message)}"
    )


def validate_threshold(
    variable_name: str,
    value: str,
    allowed_values: dict[str, int],
) -> None:
    """Validate a configured security threshold."""
    if value in allowed_values:
        return

    allowed = ", ".join(allowed_values)

    raise RuntimeError(
        f"Invalid {variable_name} value '{value}'. "
        f"Allowed values: {allowed}"
    )


def extract_semgrep_severity(
    result: dict[str, Any],
) -> str:
    """Extract a normalized Semgrep severity."""
    extra = result.get("extra", {})

    if not isinstance(extra, dict):
        return "INFO"

    severity = normalize(
        extra.get("severity", "INFO")
    )

    if severity not in {
        "INFO",
        "WARNING",
        "ERROR",
    }:
        return "INFO"

    return severity


def extract_cwe(
    metadata: dict[str, Any],
) -> str:
    """Extract CWE information from Semgrep metadata."""
    cwe = metadata.get("cwe", "")

    if isinstance(cwe, list):
        return ", ".join(
            str(item)
            for item in cwe
        )

    if cwe is None:
        return ""

    return str(cwe)


def evaluate_sast(
    report_root: Path,
    threshold_name: str,
) -> tuple[
    list[dict[str, Any]],
    Counter[str],
    Path,
]:
    """Evaluate Semgrep findings against the SAST threshold."""
    report_path = find_report(
        report_root,
        "semgrep.json",
    )

    if report_path is None:
        raise RuntimeError(
            "Mandatory Semgrep report semgrep.json "
            f"was not found under {report_root}"
        )

    report = load_json(report_path)
    results = report.get("results", [])

    if not isinstance(results, list):
        raise RuntimeError(
            f"{report_path}: 'results' must be an array"
        )

    threshold = SAST_LEVELS[threshold_name]

    severity_counts: Counter[str] = Counter()
    blocking_findings: list[dict[str, Any]] = []

    for result in results:
        if not isinstance(result, dict):
            continue

        severity = extract_semgrep_severity(
            result
        )

        severity_counts[severity] += 1

        if threshold_name == "NONE":
            continue

        if SAST_LEVELS[severity] < threshold:
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

        finding = {
            "severity": severity,
            "rule": str(
                result.get(
                    "check_id",
                    "unknown-rule",
                )
            ),
            "file": str(
                result.get(
                    "path",
                    "unknown-file",
                )
            ),
            "line": start.get("line", ""),
            "message": str(
                extra.get(
                    "message",
                    "Semgrep security finding",
                )
            ),
            "cwe": extract_cwe(metadata),
        }

        blocking_findings.append(finding)

    return (
        blocking_findings,
        severity_counts,
        report_path,
    )


def iter_zap_alerts(
    report: dict[str, Any],
) -> Iterator[
    tuple[str, dict[str, Any]]
]:
    """Yield site and alert pairs from a ZAP JSON report."""
    sites = report.get("site", [])

    if not isinstance(sites, list):
        return

    for site in sites:
        if not isinstance(site, dict):
            continue

        site_name = str(
            site.get("@name")
            or site.get("name")
            or "unknown-site"
        )

        alerts = site.get("alerts", [])

        if not isinstance(alerts, list):
            continue

        for alert in alerts:
            if isinstance(alert, dict):
                yield site_name, alert


def canonical_zap_risk(
    alert: dict[str, Any],
) -> str:
    """Normalize a textual or numeric ZAP risk."""
    raw_risk = normalize(
        alert.get("riskdesc")
        or alert.get("risk")
        or alert.get("riskcode")
    )

    if "HIGH" in raw_risk or raw_risk == "3":
        return "HIGH"

    if (
        "MEDIUM" in raw_risk
        or raw_risk == "2"
    ):
        return "MEDIUM"

    if "LOW" in raw_risk or raw_risk == "1":
        return "LOW"

    return "INFORMATIONAL"


def evaluate_dast(
    report_root: Path,
    threshold_name: str,
) -> tuple[
    list[dict[str, Any]],
    Counter[str],
    Path | None,
]:
    """Evaluate ZAP findings against the DAST threshold."""
    report_path = find_report(
        report_root,
        "zap.json",
    )

    if report_path is None:
        return [], Counter(), None

    report = load_json(report_path)
    threshold = ZAP_LEVELS[threshold_name]

    risk_counts: Counter[str] = Counter()
    blocking_findings: list[dict[str, Any]] = []

    for site_name, alert in iter_zap_alerts(
        report
    ):
        risk = canonical_zap_risk(alert)
        risk_counts[risk] += 1

        if threshold_name == "NONE":
            continue

        if ZAP_LEVELS[risk] < threshold:
            continue

        finding = {
            "risk": risk,
            "name": str(
                alert.get("alert")
                or alert.get("name")
                or "Unknown ZAP alert"
            ),
            "site": site_name,
            "plugin_id": str(
                alert.get("pluginid")
                or alert.get("pluginId")
                or ""
            ),
        }

        blocking_findings.append(finding)

    return (
        blocking_findings,
        risk_counts,
        report_path,
    )


def write_job_summary(
    *,
    sast_threshold: str,
    sast_counts: Counter[str],
    sast_blocking: list[dict[str, Any]],
    zap_threshold: str,
    zap_counts: Counter[str],
    zap_blocking: list[dict[str, Any]],
    zap_report: Path | None,
    passed: bool,
) -> None:
    """Write the gate result to the GitHub Actions job summary."""
    summary_path = os.getenv(
        "GITHUB_STEP_SUMMARY"
    )

    if not summary_path:
        return

    lines = [
        "## OWASP security policy gate",
        "",
        (
            "**Result:** "
            + ("Passed" if passed else "Failed")
        ),
        "",
        f"- SAST threshold: `{sast_threshold}`",
        f"- ZAP threshold: `{zap_threshold}`",
        "",
        "### SAST results",
        "",
        f"- ERROR: {sast_counts.get('ERROR', 0)}",
        (
            "- WARNING: "
            f"{sast_counts.get('WARNING', 0)}"
        ),
        f"- INFO: {sast_counts.get('INFO', 0)}",
        (
            "- Blocking findings: "
            f"{len(sast_blocking)}"
        ),
        "",
        "### DAST results",
        "",
    ]

    if zap_report is None:
        lines.append(
            "- ZAP report was not present"
        )
    else:
        lines.extend(
            [
                (
                    "- High: "
                    f"{zap_counts.get('HIGH', 0)}"
                ),
                (
                    "- Medium: "
                    f"{zap_counts.get('MEDIUM', 0)}"
                ),
                (
                    "- Low: "
                    f"{zap_counts.get('LOW', 0)}"
                ),
                (
                    "- Informational: "
                    f"{zap_counts.get('INFORMATIONAL', 0)}"
                ),
                (
                    "- Blocking findings: "
                    f"{len(zap_blocking)}"
                ),
            ]
        )

    if sast_blocking:
        lines.extend(
            [
                "",
                "### Blocking SAST findings",
                "",
            ]
        )

        for finding in sast_blocking[:100]:
            lines.append(
                f"- **{finding['severity']}** "
                f"`{finding['rule']}` at "
                f"`{finding['file']}:{finding['line']}`"
            )

    if zap_blocking:
        lines.extend(
            [
                "",
                "### Blocking DAST findings",
                "",
            ]
        )

        for finding in zap_blocking[:100]:
            lines.append(
                f"- **{finding['risk']}** "
                f"{finding['name']} on "
                f"`{finding['site']}`"
            )

    lines.append("")

    try:
        with Path(summary_path).open(
            "a",
            encoding="utf-8",
        ) as handle:
            handle.write("\n".join(lines))
    except OSError as exc:
        print(
            "Warning: unable to write GitHub "
            f"job summary: {exc}",
            file=sys.stderr,
        )


def main() -> int:
    """Run the OWASP security policy gate."""
    if len(sys.argv) != 2:
        print(
            f"Usage: {Path(sys.argv[0]).name} "
            "REPORT_DIRECTORY",
            file=sys.stderr,
        )

        return 2

    report_root = Path(sys.argv[1])

    if not report_root.is_dir():
        message = (
            "Report directory does not exist: "
            f"{report_root}"
        )

        emit_error(message)
        print(message, file=sys.stderr)

        return 2

    sast_threshold = normalize(
        os.getenv(
            "FAIL_ON_SAST",
            "ERROR",
        )
    )

    zap_threshold = normalize(
        os.getenv(
            "FAIL_ON_ZAP_RISK",
            "HIGH",
        )
    )

    try:
        validate_threshold(
            "FAIL_ON_SAST",
            sast_threshold,
            SAST_LEVELS,
        )

        validate_threshold(
            "FAIL_ON_ZAP_RISK",
            zap_threshold,
            ZAP_LEVELS,
        )

        (
            sast_blocking,
            sast_counts,
            sast_report,
        ) = evaluate_sast(
            report_root,
            sast_threshold,
        )

        (
            zap_blocking,
            zap_counts,
            zap_report,
        ) = evaluate_dast(
            report_root,
            zap_threshold,
        )

    except RuntimeError as exc:
        emit_error(str(exc))

        print(
            f"Security gate error: {exc}",
            file=sys.stderr,
        )

        return 2

    print("OWASP security policy gate")
    print(f"Report directory: {report_root}")
    print(f"Semgrep report: {sast_report}")
    print(f"SAST threshold: {sast_threshold}")
    print(f"ZAP threshold: {zap_threshold}")
    print()

    print("SAST severity counts:")
    print(
        f"  ERROR: "
        f"{sast_counts.get('ERROR', 0)}"
    )
    print(
        f"  WARNING: "
        f"{sast_counts.get('WARNING', 0)}"
    )
    print(
        f"  INFO: "
        f"{sast_counts.get('INFO', 0)}"
    )

    if zap_report is None:
        print("ZAP report: not present")
    else:
        print(f"ZAP report: {zap_report}")
        print("ZAP risk counts:")
        print(
            f"  High: "
            f"{zap_counts.get('HIGH', 0)}"
        )
        print(
            f"  Medium: "
            f"{zap_counts.get('MEDIUM', 0)}"
        )
        print(
            f"  Low: "
            f"{zap_counts.get('LOW', 0)}"
        )
        print(
            "  Informational: "
            f"{zap_counts.get('INFORMATIONAL', 0)}"
        )

    if sast_blocking:
        print("\nBlocking SAST findings:")

        for finding in sast_blocking:
            print(
                f"  [{finding['severity']}] "
                f"{finding['rule']} at "
                f"{finding['file']}:"
                f"{finding['line']}"
            )

            print(
                f"    {finding['message']}"
            )

            if finding["cwe"]:
                print(
                    f"    CWE: {finding['cwe']}"
                )

            emit_error(
                (
                    f"[{finding['severity']}] "
                    f"{finding['rule']}: "
                    f"{finding['message']}"
                ),
                file=finding["file"],
                line=finding["line"],
                title="Blocking Semgrep finding",
            )

    if zap_blocking:
        print("\nBlocking DAST findings:")

        for finding in zap_blocking:
            plugin_description = ""

            if finding["plugin_id"]:
                plugin_description = (
                    " (plugin "
                    f"{finding['plugin_id']})"
                )

            print(
                f"  [{finding['risk']}] "
                f"{finding['name']} on "
                f"{finding['site']}"
                f"{plugin_description}"
            )

            emit_error(
                (
                    f"[{finding['risk']}] ZAP "
                    f"{finding['name']} on "
                    f"{finding['site']}"
                    f"{plugin_description}"
                ),
                title="Blocking OWASP ZAP finding",
            )

    passed = (
        not sast_blocking
        and not zap_blocking
    )

    write_job_summary(
        sast_threshold=sast_threshold,
        sast_counts=sast_counts,
        sast_blocking=sast_blocking,
        zap_threshold=zap_threshold,
        zap_counts=zap_counts,
        zap_blocking=zap_blocking,
        zap_report=zap_report,
        passed=passed,
    )

    if not passed:
        print(
            "\nSecurity gate failed: "
            f"{len(sast_blocking)} blocking "
            "SAST finding(s), "
            f"{len(zap_blocking)} blocking "
            "DAST finding(s)."
        )

        return 1

    print("\nSecurity gate passed")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())