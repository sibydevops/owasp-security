#!/usr/bin/env python3
"""Convert Semgrep or OWASP ZAP JSON into normalized reports."""

from __future__ import annotations

import html
import json
import os
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml


SUPPORTED_TOOLS = {
    "semgrep",
    "zap",
}


def normalize(value: Any) -> str:
    """Convert a value to a trimmed string."""
    return str(value or "").strip()


def load_json(path: Path) -> dict[str, Any]:
    """Load and validate a JSON report."""
    if not path.is_file():
        raise RuntimeError(
            f"Input report does not exist: {path}"
        )

    try:
        document = json.loads(
            path.read_text(
                encoding="utf-8"
            )
        )
    except OSError as exc:
        raise RuntimeError(
            f"Unable to read {path}: {exc}"
        ) from exc
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"Invalid JSON in {path} at "
            f"line {exc.lineno}, "
            f"column {exc.colno}: "
            f"{exc.msg}"
        ) from exc

    if not isinstance(document, dict):
        raise RuntimeError(
            "Scanner report must contain a JSON object"
        )

    return document


def normalize_semgrep_severity(
    severity: Any,
) -> str:
    """Normalize Semgrep severity."""
    normalized = normalize(
        severity
    ).upper()

    if normalized in {
        "ERROR",
        "WARNING",
        "INFO",
    }:
        return normalized

    return "INFO"


def extract_semgrep_findings(
    report: dict[str, Any],
) -> list[dict[str, Any]]:
    """Extract findings from Semgrep JSON."""
    results = report.get(
        "results",
        [],
    )

    if not isinstance(results, list):
        raise RuntimeError(
            "Semgrep results must be an array"
        )

    findings: list[dict[str, Any]] = []

    for result in results:
        if not isinstance(result, dict):
            continue

        extra = result.get(
            "extra",
            {},
        )

        if not isinstance(extra, dict):
            extra = {}

        metadata = extra.get(
            "metadata",
            {},
        )

        if not isinstance(metadata, dict):
            metadata = {}

        start = result.get(
            "start",
            {},
        )

        if not isinstance(start, dict):
            start = {}

        cwe = metadata.get(
            "cwe",
            "",
        )

        if isinstance(cwe, list):
            cwe = ", ".join(
                str(value)
                for value in cwe
            )

        owasp = metadata.get(
            "owasp",
            "",
        )

        if isinstance(owasp, list):
            owasp = ", ".join(
                str(value)
                for value in owasp
            )

        findings.append(
            {
                "severity": normalize_semgrep_severity(
                    extra.get(
                        "severity",
                        "INFO",
                    )
                ),
                "rule_id": normalize(
                    result.get(
                        "check_id",
                        "unknown-rule",
                    )
                ),
                "title": normalize(
                    result.get(
                        "check_id",
                        "Unknown Semgrep finding",
                    )
                ),
                "asset": normalize(
                    result.get(
                        "path",
                        "unknown-file",
                    )
                ),
                "line": start.get(
                    "line",
                    "",
                ),
                "column": start.get(
                    "col",
                    "",
                ),
                "description": normalize(
                    extra.get(
                        "message",
                        "Semgrep security finding",
                    )
                ),
                "solution": normalize(
                    metadata.get(
                        "fix",
                        "",
                    )
                ),
                "cwe": normalize(cwe),
                "owasp": normalize(owasp),
            }
        )

    return findings


def normalize_zap_severity(
    alert: dict[str, Any],
) -> str:
    """Normalize OWASP ZAP risk."""
    raw_risk = normalize(
        alert.get("riskdesc")
        or alert.get("risk")
        or alert.get("riskcode")
    ).upper()

    if (
        "HIGH" in raw_risk
        or raw_risk == "3"
    ):
        return "HIGH"

    if (
        "MEDIUM" in raw_risk
        or raw_risk == "2"
    ):
        return "MEDIUM"

    if (
        "LOW" in raw_risk
        or raw_risk == "1"
    ):
        return "LOW"

    return "INFORMATIONAL"


def extract_zap_findings(
    report: dict[str, Any],
) -> list[dict[str, Any]]:
    """Extract findings from OWASP ZAP JSON."""
    sites = report.get(
        "site",
        [],
    )

    if not isinstance(sites, list):
        raise RuntimeError(
            "ZAP site property must be an array"
        )

    findings: list[dict[str, Any]] = []

    for site in sites:
        if not isinstance(site, dict):
            continue

        site_name = normalize(
            site.get("@name")
            or site.get("name")
            or "unknown-site"
        )

        alerts = site.get(
            "alerts",
            [],
        )

        if not isinstance(alerts, list):
            continue

        for alert in alerts:
            if not isinstance(alert, dict):
                continue

            findings.append(
                {
                    "severity": normalize_zap_severity(
                        alert
                    ),
                    "rule_id": normalize(
                        alert.get("pluginid")
                        or alert.get("pluginId")
                    ),
                    "title": normalize(
                        alert.get("alert")
                        or alert.get("name")
                        or "Unknown ZAP alert"
                    ),
                    "asset": site_name,
                    "line": "",
                    "column": "",
                    "description": normalize(
                        alert.get("desc")
                        or alert.get(
                            "description"
                        )
                    ),
                    "solution": normalize(
                        alert.get(
                            "solution",
                            "",
                        )
                    ),
                    "cwe": normalize(
                        alert.get(
                            "cweid",
                            "",
                        )
                    ),
                    "owasp": normalize(
                        alert.get(
                            "wascid",
                            "",
                        )
                    ),
                }
            )

    return findings


def severity_rank(
    severity: str,
) -> int:
    """Return severity sorting rank."""
    ranks = {
        "ERROR": 0,
        "HIGH": 0,
        "WARNING": 1,
        "MEDIUM": 1,
        "LOW": 2,
        "INFO": 3,
        "INFORMATIONAL": 3,
    }

    return ranks.get(
        severity,
        99,
    )


def build_markdown(
    title: str,
    document: dict[str, Any],
) -> str:
    """Generate Markdown report."""
    assessment = document[
        "assessment"
    ]

    summary = document[
        "summary"
    ]

    findings = document[
        "findings"
    ]

    lines = [
        f"# {title}",
        "",
        (
            "- Repository: "
            f"`{assessment['repository']}`"
        ),
        (
            "- Commit: "
            f"`{assessment['sha']}`"
        ),
        (
            "- Scan mode: "
            f"`{assessment['scan_mode']}`"
        ),
        (
            "- Total findings: "
            f"{summary['findings']}"
        ),
        "",
        "## Severity Summary",
        "",
    ]

    for severity, count in summary[
        "severity"
    ].items():
        lines.append(
            f"- {severity}: {count}"
        )

    if not findings:
        lines.extend(
            [
                "",
                "## Findings",
                "",
                "No security findings were detected.",
                "",
            ]
        )

        return "\n".join(lines)

    for index, finding in enumerate(
        findings,
        start=1,
    ):
        location = finding[
            "asset"
        ]

        if finding["line"]:
            location += (
                f":{finding['line']}"
            )

        lines.extend(
            [
                "",
                (
                    f"## {index}. "
                    f"[{finding['severity']}] "
                    f"{finding['title']}"
                ),
                "",
                (
                    "- Rule: "
                    f"`{finding['rule_id']}`"
                ),
                (
                    "- Asset: "
                    f"`{location}`"
                ),
                (
                    "- CWE: "
                    f"{finding['cwe'] or 'Not supplied'}"
                ),
                (
                    "- OWASP/WASC: "
                    f"{finding['owasp'] or 'Not supplied'}"
                ),
                "",
                finding["description"]
                or "No description supplied.",
                "",
            ]
        )

        if finding["solution"]:
            lines.extend(
                [
                    "### Recommended Solution",
                    "",
                    finding["solution"],
                    "",
                ]
            )

    return "\n".join(lines)


def build_html(
    title: str,
    document: dict[str, Any],
) -> str:
    """Generate standalone HTML report."""
    assessment = document[
        "assessment"
    ]

    summary = document[
        "summary"
    ]

    findings = document[
        "findings"
    ]

    rows = []

    for finding in findings:
        location = finding[
            "asset"
        ]

        if finding["line"]:
            location += (
                f":{finding['line']}"
            )

        rows.append(
            (
                "<tr>"
                f"<td>{html.escape(finding['severity'])}</td>"
                f"<td>{html.escape(finding['rule_id'])}</td>"
                f"<td>{html.escape(finding['title'])}</td>"
                f"<td>{html.escape(location)}</td>"
                f"<td>{html.escape(finding['description'])}</td>"
                f"<td>{html.escape(finding['cwe'])}</td>"
                f"<td>{html.escape(finding['owasp'])}</td>"
                "</tr>"
            )
        )

    if not rows:
        rows.append(
            (
                '<tr><td colspan="7">'
                "No security findings were detected."
                "</td></tr>"
            )
        )

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta
    name="viewport"
    content="width=device-width, initial-scale=1"
  >

  <title>{html.escape(title)}</title>

  <style>
    body {{
      margin: 32px;
      color: #1f2937;
      font-family:
        "Segoe UI",
        Arial,
        sans-serif;
    }}

    h1 {{
      color: #0067b8;
    }}

    .summary {{
      margin: 24px 0;
      padding: 16px;
      border: 1px solid #d1d5db;
      border-radius: 8px;
    }}

    .metric {{
      font-size: 32px;
      font-weight: 700;
    }}

    table {{
      width: 100%;
      border-collapse: collapse;
    }}

    th,
    td {{
      padding: 8px;
      border: 1px solid #d1d5db;
      text-align: left;
      vertical-align: top;
    }}

    th {{
      color: #ffffff;
      background: #0067b8;
    }}

    tr:nth-child(even) {{
      background: #f3f4f6;
    }}
  </style>
</head>

<body>
  <h1>{html.escape(title)}</h1>

  <p>
    Repository:
    {html.escape(assessment["repository"])}
  </p>

  <p>
    Commit:
    {html.escape(assessment["sha"])}
  </p>

  <div class="summary">
    <div class="metric">
      {summary["findings"]}
    </div>

    <div>Total findings</div>
  </div>

  <table>
    <thead>
      <tr>
        <th>Severity</th>
        <th>Rule</th>
        <th>Title</th>
        <th>Asset</th>
        <th>Description</th>
        <th>CWE</th>
        <th>OWASP/WASC</th>
      </tr>
    </thead>

    <tbody>
      {''.join(rows)}
    </tbody>
  </table>
</body>
</html>
"""


def validate_outputs(
    output_paths: list[Path],
) -> None:
    """Validate all expected output files."""
    for output_path in output_paths:
        if not output_path.is_file():
            raise RuntimeError(
                "Expected output is missing: "
                f"{output_path}"
            )

        if output_path.stat().st_size == 0:
            raise RuntimeError(
                "Expected output is empty: "
                f"{output_path}"
            )


def main() -> int:
    """Run report conversion."""
    tool = normalize(
        os.getenv(
            "REPORT_TOOL",
            "",
        )
    ).lower()

    input_value = os.getenv(
        "REPORT_INPUT",
        "",
    )

    output_value = os.getenv(
        "REPORT_OUTPUT",
        "reports",
    )

    if tool not in SUPPORTED_TOOLS:
        print(
            "REPORT_TOOL must be semgrep or zap",
            file=sys.stderr,
        )

        return 2

    if not input_value:
        print(
            "REPORT_INPUT is required",
            file=sys.stderr,
        )

        return 2

    input_path = Path(
        input_value
    )

    output_directory = Path(
        output_value
    )

    try:
        source_report = load_json(
            input_path
        )

        if tool == "semgrep":
            findings = (
                extract_semgrep_findings(
                    source_report
                )
            )

            title = "Semgrep SAST Report"
            control_id = "SAST"
            scanner_name = "semgrep"
        else:
            findings = (
                extract_zap_findings(
                    source_report
                )
            )

            title = "OWASP ZAP DAST Report"
            control_id = "DAST"
            scanner_name = "owasp-zap"

        findings = sorted(
            findings,
            key=lambda finding: (
                severity_rank(
                    finding["severity"]
                ),
                finding["asset"].lower(),
                int(
                    finding["line"]
                    or 0
                ),
                finding[
                    "rule_id"
                ].lower(),
            ),
        )

        severity_counts = Counter(
            finding["severity"]
            for finding in findings
        )

        document = {
            "assessment": {
                "framework": "OWASP",
                "scanner": scanner_name,
                "repository": os.getenv(
                    "REPORT_REPOSITORY",
                    "",
                ),
                "sha": os.getenv(
                    "REPORT_SHA",
                    "",
                ),
                "scan_mode": os.getenv(
                    "REPORT_SCAN_MODE",
                    "",
                ),
                "source_report": str(
                    input_path
                ),
                "generated_at": datetime.now(
                    timezone.utc
                ).isoformat(),
            },
            "summary": {
                "findings": len(
                    findings
                ),
                "severity": dict(
                    sorted(
                        severity_counts.items(),
                        key=lambda item: (
                            severity_rank(
                                item[0]
                            )
                        ),
                    )
                ),
            },
            "findings": findings,
        }

        output_directory.mkdir(
            parents=True,
            exist_ok=True,
        )

        normalized_json = (
            output_directory
            / f"{tool}-normalized.json"
        )

        normalized_yaml = (
            output_directory
            / f"{tool}-normalized.yaml"
        )

        summary_markdown = (
            output_directory
            / f"{tool}-summary.md"
        )

        report_html = (
            output_directory
            / f"{tool}-report.html"
        )

        status_json = (
            output_directory
            / f"{tool}-status.json"
        )

        status_yaml = (
            output_directory
            / f"{tool}-status.yaml"
        )

        normalized_json.write_text(
            json.dumps(
                document,
                indent=2,
                ensure_ascii=False,
            )
            + "\n",
            encoding="utf-8",
        )

        normalized_yaml.write_text(
            yaml.safe_dump(
                document,
                sort_keys=False,
                allow_unicode=True,
            ),
            encoding="utf-8",
        )

        summary_markdown.write_text(
            build_markdown(
                title,
                document,
            ),
            encoding="utf-8",
        )

        report_html.write_text(
            build_html(
                title,
                document,
            ),
            encoding="utf-8",
        )

        status_document = {
            "control": {
                "id": control_id,
                "status": "completed",
                "reason": "",
                "tool": scanner_name,
                "repository": document[
                    "assessment"
                ][
                    "repository"
                ],
                "sha": document[
                    "assessment"
                ][
                    "sha"
                ],
                "scan_mode": document[
                    "assessment"
                ][
                    "scan_mode"
                ],
                "findings": len(
                    findings
                ),
                "severity": dict(
                    severity_counts
                ),
                "evidence": [
                    normalized_json.name,
                    normalized_yaml.name,
                    summary_markdown.name,
                    report_html.name,
                ],
                "recorded_at": datetime.now(
                    timezone.utc
                ).isoformat(),
            }
        }

        status_json.write_text(
            json.dumps(
                status_document,
                indent=2,
                ensure_ascii=False,
            )
            + "\n",
            encoding="utf-8",
        )

        status_yaml.write_text(
            yaml.safe_dump(
                status_document,
                sort_keys=False,
                allow_unicode=True,
            ),
            encoding="utf-8",
        )

        output_paths = [
            normalized_json,
            normalized_yaml,
            summary_markdown,
            report_html,
            status_json,
            status_yaml,
        ]

        validate_outputs(
            output_paths
        )

    except (
        RuntimeError,
        OSError,
        ValueError,
        TypeError,
    ) as exc:
        print(
            f"Report generation failed: {exc}",
            file=sys.stderr,
        )

        return 2

    print(
        f"Generated reports for {tool}:"
    )

    for output_path in output_paths:
        print(
            f"  {output_path}"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())