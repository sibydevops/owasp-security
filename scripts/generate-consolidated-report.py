#!/usr/bin/env python3
from __future__ import annotations
import argparse
import html
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import yaml


def load_statuses(root: Path) -> list[dict[str, Any]]:
    statuses = []
    for path in sorted(root.rglob("*-status.yaml")):
        try:
            document = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError):
            continue
        if isinstance(document, dict) and isinstance(document.get("control"), dict):
            status = dict(document["control"])
            status["source_file"] = str(path.relative_to(root))
            statuses.append(status)
    return statuses


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("report_directory", type=Path)
    parser.add_argument("--repository", default="")
    parser.add_argument("--sha", default="")
    args = parser.parse_args()
    root = args.report_directory
    root.mkdir(parents=True, exist_ok=True)
    statuses = load_statuses(root)
    names = ["completed", "not_applicable", "failed", "configuration_error", "missing"]
    counts = {name: sum(1 for item in statuses if item.get("status") == name) for name in names}
    document = {
        "assessment": {
            "framework": "OWASP",
            "repository": args.repository,
            "sha": args.sha,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        },
        "controls": counts,
        "control_statuses": statuses,
        "manual_testing_required": [
            "Authentication testing",
            "Authorization testing",
            "Session management testing",
            "Business logic testing",
            "Manual exploit validation",
        ],
    }
    (root / "owasp-summary.json").write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    (root / "owasp-summary.yaml").write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    markdown = ["# OWASP Security Assessment", ""]
    markdown.extend(f"- {name}: {count}" for name, count in counts.items())
    (root / "owasp-summary.md").write_text("\n".join(markdown) + "\n", encoding="utf-8")
    rows = "".join(
        "<tr>"
        f"<td>{html.escape(str(item.get('id', '')))}</td>"
        f"<td>{html.escape(str(item.get('status', '')))}</td>"
        f"<td>{html.escape(str(item.get('tool', '')))}</td>"
        f"<td>{html.escape(str(item.get('reason', '')))}</td>"
        "</tr>"
        for item in statuses
    )
    page = (
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<title>OWASP Assessment</title></head><body>"
        "<h1>OWASP Security Assessment</h1><table>"
        "<tr><th>Control</th><th>Status</th><th>Tool</th><th>Reason</th></tr>"
        f"{rows}</table></body></html>"
    )
    (root / "owasp-summary.html").write_text(page, encoding="utf-8")
    manifest = {
        "artifact": {
            "repository": args.repository,
            "sha": args.sha,
            "files": [
                {"path": str(path.relative_to(root)), "size_bytes": path.stat().st_size}
                for path in sorted(root.rglob("*"))
                if path.is_file()
            ],
        }
    }
    (root / "report-manifest.yaml").write_text(yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8")
    print(f"Generated consolidated reports under {root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
