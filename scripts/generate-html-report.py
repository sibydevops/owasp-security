#!/usr/bin/env python3
"""
Generate HTML reports from SAST and DAST JSON findings.
Supports Semgrep SAST and ZAP DAST findings with severity-based coloring.
"""

import json
import sys
from pathlib import Path
from datetime import datetime
from urllib.parse import quote


def get_severity_color(severity):
    """Return CSS color class based on severity level."""
    severity = str(severity).upper()
    if severity in ['CRITICAL', 'CRITICAL_RISK']:
        return 'critical'
    elif severity in ['HIGH', 'HIGH_RISK']:
        return 'high'
    elif severity in ['MEDIUM', 'MEDIUM_RISK']:
        return 'medium'
    elif severity in ['LOW', 'LOW_RISK']:
        return 'low'
    else:
        return 'info'


def format_value(value):
    """Format a value for display, handling None and special characters."""
    if value is None:
        return '<span class="null">null</span>'
    if isinstance(value, bool):
        return f'<span class="boolean">{"true" if value else "false"}</span>'
    if isinstance(value, (int, float)):
        return f'<span class="number">{value}</span>'
    if isinstance(value, str):
        # Escape HTML but preserve line breaks
        escaped = (value.replace('&', '&amp;')
                        .replace('<', '&lt;')
                        .replace('>', '&gt;')
                        .replace('"', '&quot;'))
        if len(escaped) > 200:
            return f'<details><summary>View...</summary><pre>{escaped}</pre></details>'
        return f'<span class="string">{escaped}</span>'
    return str(value)


def generate_semgrep_html(semgrep_json_path, output_path):
    """Generate HTML report from Semgrep JSON findings."""
    with open(semgrep_json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    results = data.get('results', [])
    errors = data.get('errors', [])

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Semgrep SAST Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif; line-height: 1.6; color: #333; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 8px; margin-bottom: 30px; }}
        header h1 {{ font-size: 2.5em; margin-bottom: 10px; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }}
        .summary-card {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .summary-card h3 {{ color: #667eea; margin-bottom: 10px; }}
        .summary-card .number {{ font-size: 2em; font-weight: bold; }}
        .count-critical {{ color: #dc3545; }}
        .count-high {{ color: #fd7e14; }}
        .count-medium {{ color: #ffc107; }}
        .count-low {{ color: #28a745; }}
        .count-info {{ color: #17a2b8; }}
        .findings {{ margin: 30px 0; }}
        .finding {{ background: white; margin-bottom: 15px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); overflow: hidden; }}
        .finding-header {{ padding: 15px; border-left: 5px solid #ddd; cursor: pointer; }}
        .finding.critical .finding-header {{ border-left-color: #dc3545; background: #fff5f5; }}
        .finding.high .finding-header {{ border-left-color: #fd7e14; background: #fff8f5; }}
        .finding.medium .finding-header {{ border-left-color: #ffc107; background: #fffef5; }}
        .finding.low .finding-header {{ border-left-color: #28a745; background: #f5fff5; }}
        .finding.info .finding-header {{ border-left-color: #17a2b8; background: #f5fbff; }}
        .finding-header h3 {{ margin-bottom: 8px; font-size: 1.1em; }}
        .finding-meta {{ display: flex; gap: 15px; flex-wrap: wrap; font-size: 0.9em; color: #666; }}
        .finding-meta span {{ display: flex; align-items: center; gap: 5px; }}
        .badge {{ display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 0.85em; font-weight: 600; }}
        .badge-critical {{ background: #dc3545; color: white; }}
        .badge-high {{ background: #fd7e14; color: white; }}
        .badge-medium {{ background: #ffc107; color: #333; }}
        .badge-low {{ background: #28a745; color: white; }}
        .badge-info {{ background: #17a2b8; color: white; }}
        .finding-body {{ padding: 0 15px 15px; display: none; }}
        .finding.expanded .finding-body {{ display: block; }}
        .finding-body pre {{ background: #f8f9fa; padding: 12px; border-radius: 4px; overflow-x: auto; margin-top: 10px; font-size: 0.85em; }}
        .metadata {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 10px; margin-top: 10px; }}
        .metadata-item {{ padding: 10px; background: #f8f9fa; border-radius: 4px; }}
        .metadata-item dt {{ font-weight: 600; color: #667eea; }}
        .metadata-item dd {{ margin-left: 10px; color: #666; word-break: break-word; }}
        .errors {{ background: #fff5f5; border: 1px solid #dc3545; border-radius: 8px; padding: 15px; margin-top: 30px; }}
        .errors h3 {{ color: #dc3545; margin-bottom: 10px; }}
        .error-item {{ background: white; padding: 10px; border-radius: 4px; margin-top: 8px; border-left: 3px solid #dc3545; }}
        footer {{ text-align: center; color: #999; margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; }}
        @media print {{
            body {{ background: white; }}
            .container {{ max-width: 100%; }}
            .finding {{ break-inside: avoid; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>📋 Semgrep SAST Security Report</h1>
            <p>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
        </header>
"""

    # Count findings by severity
    severity_counts = {}
    for result in results:
        sev = result.get('extra', {}).get('severity', 'UNKNOWN').upper()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    total = len(results)
    html += f"""
        <div class="summary">
            <div class="summary-card">
                <h3>Total Findings</h3>
                <div class="number">{total}</div>
            </div>
"""

    for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'UNKNOWN']:
        count = severity_counts.get(sev, 0)
        if count > 0 or sev == 'CRITICAL':
            html += f"""            <div class="summary-card">
                <h3>{sev}</h3>
                <div class="number count-{sev.lower()}">{count}</div>
            </div>
"""

    html += "        </div>"

    # Add findings
    if results:
        html += "        <section class='findings'>"
        for i, finding in enumerate(results):
            sev = finding.get('extra', {}).get('severity', 'UNKNOWN').upper()
            sev_class = get_severity_color(sev)
            check_id = finding.get('check_id', 'N/A')
            path = finding.get('path', 'N/A')
            line = finding.get('start', {}).get('line', 'N/A')
            message = finding.get('extra', {}).get('message', 'No message')
            metadata = finding.get('extra', {}).get('metadata', {})
            cwe = metadata.get('cwe', 'N/A')
            owasp = metadata.get('owasp', ['N/A'])
            if isinstance(owasp, list):
                owasp = ', '.join(owasp)

            html += f"""            <div class="finding {sev_class} expanded" onclick="this.classList.toggle('expanded')">
                <div class="finding-header">
                    <h3>{check_id}</h3>
                    <div class="finding-meta">
                        <span><strong>Severity:</strong> <span class="badge badge-{sev_class}">{sev}</span></span>
                        <span><strong>File:</strong> {path}:{line}</span>
                        <span><strong>CWE:</strong> {cwe}</span>
                        <span><strong>OWASP:</strong> {owasp}</span>
                    </div>
                </div>
                <div class="finding-body">
                    <p><strong>Message:</strong> {message}</p>
                    <div class="metadata">
                        <div class="metadata-item">
                            <dt>Rule ID</dt>
                            <dd>{check_id}</dd>
                        </div>
                        <div class="metadata-item">
                            <dt>File Path</dt>
                            <dd>{path}</dd>
                        </div>
                        <div class="metadata-item">
                            <dt>Line Number</dt>
                            <dd>{line}</dd>
                        </div>
                        <div class="metadata-item">
                            <dt>Severity</dt>
                            <dd>{sev}</dd>
                        </div>
                        <div class="metadata-item">
                            <dt>CWE</dt>
                            <dd>{cwe}</dd>
                        </div>
                        <div class="metadata-item">
                            <dt>OWASP</dt>
                            <dd>{owasp}</dd>
                        </div>
                    </div>
                </div>
            </div>
"""
        html += "        </section>"
    else:
        html += "        <div class='summary-card' style='grid-column: 1/-1;'><p>✓ No findings detected</p></div>"

    if errors:
        html += f"""        <section class="errors">
            <h3>Errors ({len(errors)})</h3>
"""
        for error in errors:
            msg = error.get('message', 'Unknown error')
            html += f"            <div class='error-item'>{msg}</div>\n"
        html += "        </section>"

    html += """        <footer>
            <p>Semgrep Community Edition SAST Report | <a href="https://semgrep.dev">semgrep.dev</a></p>
        </footer>
    </div>
    <script>
        document.querySelectorAll('.finding').forEach(el => {{
            el.addEventListener('click', e => {{
                if (e.target.closest('.finding-header')) {{
                    el.classList.toggle('expanded');
                }}
            }});
        }});
    </script>
</body>
</html>
"""

    Path(output_path).write_text(html, encoding='utf-8')


def generate_zap_html(zap_json_path, output_path):
    """Generate HTML report from ZAP JSON findings."""
    with open(zap_json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    sites = data.get('site', [])
    total_alerts = 0
    alerts_by_risk = {}

    for site in sites:
        for alert in site.get('alerts', []):
            risk = alert.get('riskcode', '3')
            risk_level = ['Info', 'Low', 'Medium', 'High', 'Critical'].get(int(risk), 'Unknown')
            alerts_by_risk[risk_level] = alerts_by_risk.get(risk_level, 0) + 1
            total_alerts += 1

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ZAP DAST Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif; line-height: 1.6; color: #333; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        header {{ background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); color: white; padding: 30px; border-radius: 8px; margin-bottom: 30px; }}
        header h1 {{ font-size: 2.5em; margin-bottom: 10px; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }}
        .summary-card {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .summary-card h3 {{ color: #f5576c; margin-bottom: 10px; }}
        .summary-card .number {{ font-size: 2em; font-weight: bold; }}
        .findings {{ margin: 30px 0; }}
        .finding {{ background: white; margin-bottom: 15px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); overflow: hidden; }}
        .finding-header {{ padding: 15px; border-left: 5px solid #ddd; cursor: pointer; }}
        .finding.critical .finding-header {{ border-left-color: #dc3545; background: #fff5f5; }}
        .finding.high .finding-header {{ border-left-color: #fd7e14; background: #fff8f5; }}
        .finding.medium .finding-header {{ border-left-color: #ffc107; background: #fffef5; }}
        .finding.low .finding-header {{ border-left-color: #28a745; background: #f5fff5; }}
        .finding.info .finding-header {{ border-left-color: #17a2b8; background: #f5fbff; }}
        .finding-header h3 {{ margin-bottom: 8px; font-size: 1.1em; }}
        .finding-meta {{ display: flex; gap: 15px; flex-wrap: wrap; font-size: 0.9em; color: #666; }}
        .finding-meta span {{ display: flex; align-items: center; gap: 5px; }}
        .badge {{ display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 0.85em; font-weight: 600; }}
        .badge-critical {{ background: #dc3545; color: white; }}
        .badge-high {{ background: #fd7e14; color: white; }}
        .badge-medium {{ background: #ffc107; color: #333; }}
        .badge-low {{ background: #28a745; color: white; }}
        .badge-info {{ background: #17a2b8; color: white; }}
        .finding-body {{ padding: 0 15px 15px; display: none; }}
        .finding.expanded .finding-body {{ display: block; }}
        .finding-body pre {{ background: #f8f9fa; padding: 12px; border-radius: 4px; overflow-x: auto; margin-top: 10px; font-size: 0.85em; }}
        .metadata {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 10px; margin-top: 10px; }}
        .metadata-item {{ padding: 10px; background: #f8f9fa; border-radius: 4px; }}
        .metadata-item dt {{ font-weight: 600; color: #f5576c; }}
        .metadata-item dd {{ margin-left: 10px; color: #666; word-break: break-word; }}
        .site-section {{ margin-top: 30px; }}
        .site-section h2 {{ color: #f5576c; margin-bottom: 15px; padding-bottom: 10px; border-bottom: 2px solid #f5576c; }}
        footer {{ text-align: center; color: #999; margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; }}
        @media print {{
            body {{ background: white; }}
            .container {{ max-width: 100%; }}
            .finding {{ break-inside: avoid; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔍 OWASP ZAP DAST Security Report</h1>
            <p>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
        </header>

        <div class="summary">
            <div class="summary-card">
                <h3>Total Alerts</h3>
                <div class="number">{total_alerts}</div>
            </div>
"""

    for risk_level in ['Critical', 'High', 'Medium', 'Low', 'Info']:
        count = alerts_by_risk.get(risk_level, 0)
        if count > 0 or risk_level == 'Critical':
            html += f"""            <div class="summary-card">
                <h3>{risk_level}</h3>
                <div class="number">{count}</div>
            </div>
"""

    html += "        </div>"

    # Add findings by site
    for site in sites:
        site_name = site.get('name', 'Unknown Site')
        alerts = site.get('alerts', [])

        if alerts:
            html += f"""        <section class="site-section findings">
            <h2>Site: {site_name}</h2>
"""
            for alert in alerts:
                risk = alert.get('riskcode', '3')
                risk_level = ['Info', 'Low', 'Medium', 'High', 'Critical'].get(int(risk), 'Unknown')
                sev_class = get_severity_color(risk_level)
                alert_name = alert.get('name', 'Unknown')
                url = alert.get('uri', 'N/A')
                description = alert.get('desc', 'No description')
                solution = alert.get('solution', 'No solution provided')
                reference = alert.get('reference', 'N/A')
                instances = alert.get('instances', [])

                html += f"""            <div class="finding {sev_class} expanded" onclick="this.classList.toggle('expanded')">
                    <div class="finding-header">
                        <h3>{alert_name}</h3>
                        <div class="finding-meta">
                            <span><strong>Risk:</strong> <span class="badge badge-{sev_class}">{risk_level}</span></span>
                            <span><strong>Instances:</strong> {len(instances)}</span>
                            <span><strong>URL:</strong> {url}</span>
                        </div>
                    </div>
                    <div class="finding-body">
                        <div class="metadata">
                            <div class="metadata-item">
                                <dt>Description</dt>
                                <dd>{description}</dd>
                            </div>
                            <div class="metadata-item">
                                <dt>Solution</dt>
                                <dd>{solution}</dd>
                            </div>
                            <div class="metadata-item">
                                <dt>Reference</dt>
                                <dd>{reference}</dd>
                            </div>
                        </div>
                        <div style="margin-top: 15px; border-top: 1px solid #ddd; padding-top: 15px;">
                            <h4>Instances ({len(instances)})</h4>
"""
                for instance in instances[:10]:  # Limit to first 10 instances
                    method = instance.get('method', 'N/A')
                    uri = instance.get('uri', 'N/A')
                    param = instance.get('param', 'N/A')
                    html += f"""                            <div style="background: #f8f9fa; padding: 8px; border-radius: 4px; margin-top: 8px;">
                                <strong>{method}</strong> {uri}
"""
                    if param and param != 'N/A':
                        html += f"                                <br><small>Param: {param}</small>\n"
                    html += "                            </div>\n"

                if len(instances) > 10:
                    html += f"""                            <div style="margin-top: 8px; padding: 8px; background: #f8f9fa; border-radius: 4px; text-align: center;">
                                <em>... and {len(instances) - 10} more instances</em>
                            </div>
"""

                html += """                        </div>
                    </div>
                </div>
"""
            html += "        </section>"

    html += """        <footer>
            <p>OWASP ZAP DAST Report | <a href="https://www.zaproxy.org">zaproxy.org</a></p>
        </footer>
    </div>
    <script>
        document.querySelectorAll('.finding').forEach(el => {{
            el.addEventListener('click', e => {{
                if (e.target.closest('.finding-header')) {{
                    el.classList.toggle('expanded');
                }}
            }});
        }});
    </script>
</body>
</html>
"""

    Path(output_path).write_text(html, encoding='utf-8')


def main():
    if len(sys.argv) < 3:
        print("Usage: generate-html-report.py <type> <input.json> <output.html>", file=sys.stderr)
        print("  type: semgrep or zap", file=sys.stderr)
        raise SystemExit(2)

    report_type = sys.argv[1].lower()
    input_path = sys.argv[2]
    output_path = sys.argv[3]

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)

    if report_type == 'semgrep':
        generate_semgrep_html(input_path, output_path)
    elif report_type == 'zap':
        generate_zap_html(input_path, output_path)
    else:
        print(f"Unknown report type: {report_type}", file=sys.stderr)
        raise SystemExit(2)

    print(f"Generated {report_type.upper()} HTML report: {output_path}")


if __name__ == "__main__":
    main()
