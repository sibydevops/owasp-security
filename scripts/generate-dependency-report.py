#!/usr/bin/env python3
from __future__ import annotations
import argparse
import html
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import yaml


def severity(vulnerability: dict[str, Any]) -> str:
    details = vulnerability.get("database_specific", {})
    value = str(details.get("severity", "")).upper() if isinstance(details, dict) else ""
    return value if value in {"CRITICAL", "HIGH", "MEDIUM", "LOW"} else "UNKNOWN"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input_file", type=Path)
    parser.add_argument("output_directory", type=Path)
    parser.add_argument("--repository", default="")
    parser.add_argument("--sha", default="")
    args = parser.parse_args()
    raw = json.loads(args.input_file.read_text(encoding="utf-8"))
    findings = []
    for result in raw.get("results", []):
        if not isinstance(result, dict):
            continue
        source_value = result.get("source", {})
        source = source_value.get("path", "") if isinstance(source_value, dict) else ""
        for entry in result.get("packages", []):
            if not isinstance(entry, dict):
                continue
            package = entry.get("package", {})
            package = package if isinstance(package, dict) else {}
            for vulnerability in entry.get("vulnerabilities", []):
                if not isinstance(vulnerability, dict):
                    continue
                findings.append({
                    "severity": severity(vulnerability),
                    "id": str(vulnerability.get("id", "")),
                    "package": str(package.get("name", "")),
                    "version": str(package.get("version", "")),
                    "source": str(source),
                    "summary": str(vulnerability.get("summary", "")),
                })
    counts = Counter(item["severity"] for item in findings)
    args.output_directory.mkdir(parents=True, exist_ok=True)
    document = {
        "assessment": {
            "scanner": "osv-scanner",
            "repository": args.repository,
            "sha": args.sha,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        },
        "summary": {"findings": len(findings), "severity": dict(counts)},
        "findings": findings,
    }
    (args.output_directory / "dependency-review.yaml").write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    markdown = "# Dependency Security Report\n\n" + f"- Findings: {len(findings)}\n"
    (args.output_directory / "dependency-review.md").write_text(markdown, encoding="utf-8")
    rows = "".join(
        "<tr>"
        f"<td>{html.escape(item['severity'])}</td>"
        f"<td>{html.escape(item['id'])}</td>"
        f"<td>{html.escape(item['package'])}</td>"
        f"<td>{html.escape(item['version'])}</td>"
        f"<td>{html.escape(item['summary'])}</td>"
        "</tr>"
        for item in findings
    )
    page = (
        "<!doctype html><html><head><meta charset='utf-8'><title>Dependency Report</title></head>"
        "<body><h1>Dependency Security Report</h1><table>"
        "<tr><th>Severity</th><th>ID</th><th>Package</th><th>Version</th><th>Summary</th></tr>"
        f"{rows}</table></body></html>"
    )
    (args.output_directory / "dependency-review.html").write_text(page, encoding="utf-8")
    status = {
        "control": {
            "id": "DEPENDENCY_REVIEW",
            "status": "not_applicable" if raw.get("status") == "not_applicable" else "completed",
            "reason": str(raw.get("reason", "")),
            "tool": "osv-scanner",
            "findings": len(findings),
        }
    }
    (args.output_directory / "dependency-status.json").write_text(json.dumps(status, indent=2) + "\n", encoding="utf-8")
    (args.output_directory / "dependency-status.yaml").write_text(yaml.safe_dump(status, sort_keys=False), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
