# Security Report Artifacts Quick Reference

## What You Get

After each security scan, GitHub Actions generates reports in **4 different formats** for both SAST (code scanning) and DAST (dynamic scanning):

### 📋 SAST Reports (Semgrep Code Scanning)
- **semgrep.json** - Raw findings (for tool integration)
- **semgrep.yaml** - Structured findings (for documentation)
- **semgrep.html** - 🎨 **Interactive report** (open in browser)
- **sast-normalized.json** - Categorized by OWASP standard

### 🔍 DAST Reports (OWASP ZAP)
- **zap.json** - Raw alerts (for tool integration)  
- **zap.yaml** - Structured alerts (for documentation)
- **zap.html** - 🎨 **Interactive report** (open in browser)
- **dast-normalized.json** - Categorized by OWASP standard

## How to Access Reports

1. **In GitHub Actions**:
   - Navigate to your workflow run
   - Scroll to "Artifacts" section
   - Download the `sast-[commit]` or `dast-[commit]` artifact
   - Extract the ZIP file

2. **In VS Code**:
   - Check the `reports/` directory after running scripts locally
   - HTML files open directly in your browser

## Choosing the Right Format

| Need | Format | Why |
|------|--------|-----|
| Send to stakeholders | `.html` | Pretty, interactive, professional |
| Track in version control | `.yaml` | Git-friendly, readable diffs |
| Parse in scripts | `.json` | Machine-readable, complete data |
| Quick overview | summary `.md` | Short summary at a glance |

## Opening HTML Reports

**HTML reports are interactive and best viewed in a web browser:**

```bash
# Windows
start reports/semgrep.html
start reports/zap.html

# macOS
open reports/semgrep.html
open reports/zap.html

# Linux
xdg-open reports/semgrep.html
xdg-open reports/zap.html
```

## HTML Report Features

✨ **Semgrep Report**:
- Dashboard showing finding counts by severity
- Collapsible detailed findings
- File paths with line numbers
- CWE and OWASP mapping links
- Printable/PDF-friendly

✨ **ZAP Report**:
- Risk assessment dashboard
- Alert details organized by target URL
- Affected instances with HTTP methods and parameters
- Solution and reference documentation
- Severity-based color coding

## New in This Release

✅ **HTML Reports** - Beautiful interactive reports for sharing with team and stakeholders  
✅ **YAML Exports** - Structured format for documentation and configuration management  
✅ **Improved Formatting** - Better organized, color-coded by severity

## File Locations After Scan

```
GitHub Actions Artifacts:
sast-abc123def456.zip/
├── semgrep.json
├── semgrep.yaml
├── semgrep.html          ← Open this in browser!
├── sast-normalized.json
└── sast-summary.md

dast-abc123def456.zip/
├── zap.json
├── zap.yaml
├── zap.html              ← Open this in browser!
├── dast-normalized.json
├── dast-summary.md
└── zap.md
```

## Integration Examples

### Using HTML Reports in Issues
```markdown
## Security Scan Results

View detailed report: [Download HTML Report](https://github.com/ORG/repo/actions/runs/123/artifacts)

![Findings](report-link)
```

### Using JSON in CI/CD
```bash
# Parse findings and fail if critical
python3 -c "
import json
data = json.load(open('reports/sast-normalized.json'))
critical = [f for f in data if 'CRITICAL' in f.get('severity', '')]
exit(1 if critical else 0)
"
```

### Using YAML in GitOps
```yaml
# Store as baseline for comparison
baseline_findings: !include reports/semgrep.yaml
```

## Support

For detailed information about each format and integration patterns, see:
- [📚 ARTIFACT-FORMATS.md](ARTIFACT-FORMATS.md) - Complete documentation
- [🚀 IMPLEMENTATION-GUIDE.md](IMPLEMENTATION-GUIDE.md) - Setup instructions
- [🔐 OWASP-PENETRATION-TESTING-WORKFLOW.md](OWASP-PENETRATION-TESTING-WORKFLOW.md) - Full workflow guide
