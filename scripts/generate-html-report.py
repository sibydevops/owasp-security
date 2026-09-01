#!/usr/bin/env python3
"""Generate a standalone HTML SAST report from Semgrep JSON.

Usage:
    python3 scripts/generate-html-report.py \
        reports/semgrep.json \
        reports/sast-report.html
"""

from __future__ import annotations

import argparse
import html
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SEVERITY_ORDER = {
    "ERROR": 0,
    "WARNING": 1,
    "INFO": 2,
    "UNKNOWN": 3,
}

SEVERITY_LABELS = {
    "ERROR": "High",
    "WARNING": "Medium",
    "INFO": "Informational",
    "UNKNOWN": "Unknown",
}


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate a standalone HTML report from Semgrep JSON."
    )

    parser.add_argument(
        "semgrep_json",
        type=Path,
        help="Path to the Semgrep JSON report.",
    )

    parser.add_argument(
        "output_html",
        type=Path,
        nargs="?",
        default=Path("reports/sast-report.html"),
        help="Output HTML path.",
    )

    return parser.parse_args()


def load_report(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise RuntimeError(
            f"Semgrep report does not exist: {path}"
        )

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
            "Semgrep report must contain a JSON object."
        )

    results = report.get("results", [])

    if not isinstance(results, list):
        raise RuntimeError(
            "Semgrep report 'results' must be an array."
        )

    return report


def normalize_severity(value: Any) -> str:
    severity = str(value or "UNKNOWN").strip().upper()

    if severity not in {
        "ERROR",
        "WARNING",
        "INFO",
    }:
        return "UNKNOWN"

    return severity


def text(value: Any) -> str:
    if value is None:
        return ""

    if isinstance(value, list):
        return ", ".join(
            str(item)
            for item in value
        )

    if isinstance(value, dict):
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
        )

    return str(value)


def escaped(value: Any) -> str:
    return html.escape(
        text(value),
        quote=True,
    )


def extract_finding(
    result: dict[str, Any],
) -> dict[str, Any]:
    extra = result.get("extra", {})

    if not isinstance(extra, dict):
        extra = {}

    metadata = extra.get("metadata", {})

    if not isinstance(metadata, dict):
        metadata = {}

    start = result.get("start", {})

    if not isinstance(start, dict):
        start = {}

    end = result.get("end", {})

    if not isinstance(end, dict):
        end = {}

    severity = normalize_severity(
        extra.get("severity")
    )

    return {
        "severity": severity,
        "severity_label": SEVERITY_LABELS[severity],
        "rule": text(
            result.get(
                "check_id",
                "unknown-rule",
            )
        ),
        "path": text(
            result.get(
                "path",
                "unknown-file",
            )
        ),
        "start_line": start.get("line", ""),
        "start_column": start.get("col", ""),
        "end_line": end.get("line", ""),
        "end_column": end.get("col", ""),
        "message": text(
            extra.get(
                "message",
                "No description supplied.",
            )
        ),
        "cwe": text(metadata.get("cwe", "")),
        "owasp": text(metadata.get("owasp", "")),
        "confidence": text(
            metadata.get("confidence", "")
        ),
        "impact": text(
            metadata.get("impact", "")
        ),
        "likelihood": text(
            metadata.get("likelihood", "")
        ),
        "references": metadata.get(
            "references",
            [],
        ),
        "source": text(
            extra.get("lines", "")
        ),
    }


def build_reference_list(
    references: Any,
) -> str:
    if not isinstance(references, list):
        references = (
            [references]
            if references
            else []
        )

    links: list[str] = []

    for reference in references:
        url = text(reference).strip()

        if not url:
            continue

        safe_url = html.escape(
            url,
            quote=True,
        )

        links.append(
            f'<li>{safe_url}'
            f"{safe_url}</a></li>"
        )

    if not links:
        return "<p>Not supplied</p>"

    return (
        '<ul class="references">'
        + "".join(links)
        + "</ul>"
    )


def build_finding_card(
    finding: dict[str, Any],
    index: int,
) -> str:
    severity = finding["severity"]
    location = (
        f"{finding['path']}:"
        f"{finding['start_line']}"
    )

    source_block = ""

    if finding["source"]:
        source_block = f"""
        <div class="field full-width">
          <div class="field-label">Matching source</div>
          <pre><code>{escaped(finding["source"])}</code></pre>
        </div>
        """

    return f"""
    <article
      class="finding"
      data-severity="{escaped(severity)}"
      data-search="{escaped(
          finding["rule"]
          + " "
          + finding["path"]
          + " "
          + finding["message"]
          + " "
          + finding["cwe"]
          + " "
          + finding["owasp"]
      )}"
    >
      <div class="finding-heading">
        <div>
          <div class="finding-number">Finding {index}</div>
          <h3>{escaped(finding["rule"])}</h3>
        </div>

        <span class="severity severity-{severity.lower()}">
          {escaped(finding["severity_label"])}
        </span>
      </div>

      <div class="location">
        {escaped(location)}
      </div>

      <p class="message">
        {escaped(finding["message"])}
      </p>

      <div class="finding-grid">
        <div class="field">
          <div class="field-label">Semgrep severity</div>
          <div>{escaped(severity)}</div>
        </div>

        <div class="field">
          <div class="field-label">CWE</div>
          <div>{escaped(finding["cwe"]) or "Not supplied"}</div>
        </div>

        <div class="field">
          <div class="field-label">OWASP mapping</div>
          <div>{escaped(finding["owasp"]) or "Not supplied"}</div>
        </div>

        <div class="field">
          <div class="field-label">Confidence</div>
          <div>{escaped(finding["confidence"]) or "Not supplied"}</div>
        </div>

        <div class="field">
          <div class="field-label">Impact</div>
          <div>{escaped(finding["impact"]) or "Not supplied"}</div>
        </div>

        <div class="field">
          <div class="field-label">Likelihood</div>
          <div>{escaped(finding["likelihood"]) or "Not supplied"}</div>
        </div>

        <div class="field full-width">
          <div class="field-label">References</div>
          {build_reference_list(finding["references"])}
        </div>

        {source_block}
      </div>
    </article>
    """


def generate_html(
    report: dict[str, Any],
    source_path: Path,
) -> str:
    raw_results = report.get("results", [])

    findings = [
        extract_finding(result)
        for result in raw_results
        if isinstance(result, dict)
    ]

    findings.sort(
        key=lambda finding: (
            SEVERITY_ORDER.get(
                finding["severity"],
                99,
            ),
            finding["path"].lower(),
            int(finding["start_line"] or 0),
            finding["rule"].lower(),
        )
    )

    severity_counts = Counter(
        finding["severity"]
        for finding in findings
    )

    generated_at = datetime.now(
        timezone.utc
    ).strftime("%Y-%m-%d %H:%M:%S UTC")

    cards = "\n".join(
        build_finding_card(
            finding,
            index,
        )
        for index, finding in enumerate(
            findings,
            start=1,
        )
    )

    if not cards:
        cards = """
        <section class="empty-state">
          <h2>No Semgrep findings detected</h2>
          <p>
            The supplied Semgrep report did not contain
            any security findings.
          </p>
        </section>
        """

    errors = report.get("errors", [])

    error_count = (
        len(errors)
        if isinstance(errors, list)
        else 0
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta
    name="viewport"
    content="width=device-width, initial-scale=1"
  >

  <title>OWASP SAST Report</title>

  <style>
    :root {{
      color-scheme: light;
      --background: #f4f6f8;
      --surface: #ffffff;
      --surface-muted: #f8fafc;
      --border: #d7dde5;
      --text: #1f2937;
      --muted: #5f6b7a;
      --primary: #0067b8;
      --primary-dark: #004b87;
      --error: #b42318;
      --error-bg: #fee4e2;
      --warning: #b54708;
      --warning-bg: #fef0c7;
      --info: #175cd3;
      --info-bg: #dbeafe;
      --unknown: #475467;
      --unknown-bg: #eaecf0;
      --shadow: 0 2px 8px rgba(16, 24, 40, 0.08);
    }}

    * {{
      box-sizing: border-box;
    }}

    body {{
      margin: 0;
      color: var(--text);
      background: var(--background);
      font-family:
        "Segoe UI",
        Arial,
        sans-serif;
      line-height: 1.5;
    }}

    header {{
      color: #ffffff;
      background:
        linear-gradient(
          135deg,
          #003b6f,
          #0078d4
        );
      padding: 32px 24px;
    }}

    .header-content,
    main {{
      width: min(1180px, calc(100% - 32px));
      margin: 0 auto;
    }}

    header h1 {{
      margin: 0 0 8px;
      font-size: 30px;
    }}

    header p {{
      margin: 4px 0;
      opacity: 0.92;
    }}

    main {{
      padding: 24px 0 48px;
    }}

    .summary-grid {{
      display: grid;
      grid-template-columns:
        repeat(auto-fit, minmax(160px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }}

    .summary-card {{
      padding: 18px;
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 10px;
      box-shadow: var(--shadow);
    }}

    .summary-value {{
      display: block;
      margin-bottom: 4px;
      font-size: 28px;
      font-weight: 700;
    }}

    .summary-label {{
      color: var(--muted);
      font-size: 14px;
    }}

    .controls {{
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
      align-items: center;
      margin-bottom: 20px;
      padding: 16px;
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 10px;
      box-shadow: var(--shadow);
    }}

    .controls input,
    .controls select {{
      min-height: 40px;
      padding: 8px 12px;
      color: var(--text);
      background: #ffffff;
      border: 1px solid #aab4c1;
      border-radius: 6px;
      font: inherit;
    }}

    .controls input {{
      flex: 1;
      min-width: 240px;
    }}

    .result-count {{
      margin-left: auto;
      color: var(--muted);
      font-size: 14px;
    }}

    .finding {{
      margin-bottom: 18px;
      padding: 20px;
      background: var(--surface);
      border: 1px solid var(--border);
      border-left: 6px solid var(--unknown);
      border-radius: 10px;
      box-shadow: var(--shadow);
    }}

    .finding[data-severity="ERROR"] {{
      border-left-color: var(--error);
    }}

    .finding[data-severity="WARNING"] {{
      border-left-color: var(--warning);
    }}

    .finding[data-severity="INFO"] {{
      border-left-color: var(--info);
    }}

    .finding-heading {{
      display: flex;
      gap: 16px;
      align-items: flex-start;
      justify-content: space-between;
    }}

    .finding-heading h3 {{
      margin: 2px 0 6px;
      font-size: 19px;
      overflow-wrap: anywhere;
    }}

    .finding-number {{
      color: var(--muted);
      font-size: 13px;
      font-weight: 600;
      text-transform: uppercase;
    }}

    .severity {{
      display: inline-block;
      flex: 0 0 auto;
      padding: 5px 10px;
      border-radius: 999px;
      font-size: 13px;
      font-weight: 700;
    }}

    .severity-error {{
      color: var(--error);
      background: var(--error-bg);
    }}

    .severity-warning {{
      color: var(--warning);
      background: var(--warning-bg);
    }}

    .severity-info {{
      color: var(--info);
      background: var(--info-bg);
    }}

    .severity-unknown {{
      color: var(--unknown);
      background: var(--unknown-bg);
    }}

    .location {{
      color: var(--primary-dark);
      font-family:
        Consolas,
        "Courier New",
        monospace;
      font-size: 14px;
      overflow-wrap: anywhere;
    }}

    .message {{
      margin: 14px 0;
      white-space: pre-wrap;
    }}

    .finding-grid {{
      display: grid;
      grid-template-columns:
        repeat(3, minmax(0, 1fr));
      gap: 12px;
    }}

    .field {{
      padding: 12px;
      background: var(--surface-muted);
      border: 1px solid #e5e9ef;
      border-radius: 7px;
      overflow-wrap: anywhere;
    }}

    .full-width {{
      grid-column: 1 / -1;
    }}

    .field-label {{
      margin-bottom: 5px;
      color: var(--muted);
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
    }}

    pre {{
      max-height: 320px;
      margin: 8px 0 0;
      padding: 14px;
      overflow: auto;
      color: #e5e7eb;
      background: #111827;
      border-radius: 7px;
    }}

    code {{
      font-family:
        Consolas,
        "Courier New",
        monospace;
      font-size: 13px;
    }}

    a {{
      color: var(--primary);
    }}

    .references {{
      margin: 0;
      padding-left: 22px;
    }}

    .empty-state {{
      padding: 36px;
      text-align: center;
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 10px;
      box-shadow: var(--shadow);
    }}

    .hidden {{
      display: none;
    }}

    footer {{
      margin-top: 28px;
      color: var(--muted);
      font-size: 13px;
      text-align: center;
    }}

    @media (max-width: 760px) {{
      .finding-grid {{
        grid-template-columns: 1fr;
      }}

      .finding-heading {{
        flex-direction: column;
      }}

      .result-count {{
        width: 100%;
        margin-left: 0;
      }}
    }}

    @media print {{
      body {{
        background: #ffffff;
      }}

      header {{
        color: #000000;
        background: #ffffff;
        border-bottom: 2px solid #000000;
      }}

      .controls {{
        display: none;
      }}

      .finding,
      .summary-card {{
        break-inside: avoid;
        box-shadow: none;
      }}

      main {{
        width: 100%;
      }}
    }}
  </style>
</head>

<body>
  <header>
    <div class="header-content">
      <h1>OWASP SAST Report</h1>
      <p>Generated from Semgrep JSON</p>
      <p>
        Source: {escaped(source_path)} |
        Generated: {escaped(generated_at)}
      </p>
    </div>
  </header>

  <main>
    <section class="summary-grid">
      <div class="summary-card">
        <span class="summary-value">
          {len(findings)}
        </span>
        <span class="summary-label">
          Total findings
        </span>
      </div>

      <div class="summary-card">
        <span class="summary-value">
          {severity_counts.get("ERROR", 0)}
        </span>
        <span class="summary-label">
          High / ERROR
        </span>
      </div>

      <div class="summary-card">
        <span class="summary-value">
          {severity_counts.get("WARNING", 0)}
        </span>
        <span class="summary-label">
          Medium / WARNING
        </span>
      </div>

      <div class="summary-card">
        <span class="summary-value">
          {severity_counts.get("INFO", 0)}
        </span>
        <span class="summary-label">
          Informational
        </span>
      </div>

      <div class="summary-card">
        <span class="summary-value">
          {error_count}
        </span>
        <span class="summary-label">
          Scanner errors
        </span>
      </div>
    </section>

    <section class="controls">
      <input
        id="search"
        type="search"
        placeholder="Search rule, file, message, CWE, or OWASP mapping"
        aria-label="Search findings"
      >

      <select
        id="severityFilter"
        aria-label="Filter by severity"
      >
        <option value="ALL">All severities</option>
        <option value="ERROR">High / ERROR</option>
        <option value="WARNING">Medium / WARNING</option>
        <option value="INFO">Informational</option>
        <option value="UNKNOWN">Unknown</option>
      </select>

      <span
        id="resultCount"
        class="result-count"
      >
        Showing {len(findings)} finding(s)
      </span>
    </section>

    <section id="findings">
      {cards}
    </section>

    <footer>
      Standalone OWASP SAST report.
      Open this file in Microsoft Edge, Chrome, or Firefox.
    </footer>
  </main>

  <script>
    (() => {{
      const searchInput =
        document.getElementById("search");

      const severityFilter =
        document.getElementById("severityFilter");

      const resultCount =
        document.getElementById("resultCount");

      const findings = Array.from(
        document.querySelectorAll(".finding")
      );

      function applyFilters() {{
        const searchTerm =
          searchInput.value.trim().toLowerCase();

        const selectedSeverity =
          severityFilter.value;

        let visibleCount = 0;

        for (const finding of findings) {{
          const severity =
            finding.dataset.severity || "UNKNOWN";

          const searchableText =
            finding.dataset.search || "";

          const severityMatches =
            selectedSeverity === "ALL"
            || severity === selectedSeverity;

          const searchMatches =
            !searchTerm
            || searchableText
              .toLowerCase()
              .includes(searchTerm);

          const visible =
            severityMatches && searchMatches;

          finding.classList.toggle(
            "hidden",
            !visible
          );

          if (visible) {{
            visibleCount += 1;
          }}
        }}

        resultCount.textContent =
          `Showing ${{visibleCount}} finding(s)`;
      }}

      searchInput.addEventListener(
        "input",
        applyFilters
      );

      severityFilter.addEventListener(
        "change",
        applyFilters
      );
    }})();
  </script>
</body>
</html>
"""


def main() -> int:
    arguments = parse_arguments()

    try:
        report = load_report(
            arguments.semgrep_json
        )

        html_document = generate_html(
            report,
            arguments.semgrep_json,
        )

        arguments.output_html.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        arguments.output_html.write_text(
            html_document,
            encoding="utf-8",
        )

    except RuntimeError as exc:
        print(
            f"HTML report generation failed: {exc}",
            file=sys.stderr,
        )
        return 2
    except OSError as exc:
        print(
            f"Unable to write HTML report: {exc}",
            file=sys.stderr,
        )
        return 2

    print(
        "HTML SAST report generated: "
        f"{arguments.output_html}"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())