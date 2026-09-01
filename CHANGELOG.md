# Changelog - HTML & YAML Artifacts

## [1.1.0] - 2024-09-01

### ✨ New Features

#### HTML Report Generation
- **NEW**: `scripts/generate-html-report.py` - Beautiful interactive HTML reports for both SAST and DAST
  - Semgrep SAST reports with severity dashboard, collapsible findings, and OWASP mappings
  - OWASP ZAP DAST reports with risk assessment and alert details
  - Responsive design, print-friendly, mobile-compatible
  - Color-coded severity levels (Critical/High/Medium/Low/Info)
  - Self-contained, no external dependencies

#### YAML Output Enhancement  
- SAST now generates `semgrep.yaml` alongside `semgrep.json`
- DAST continues to generate `zap.yaml` (existing)
- Both use improved YAML serialization via `convert_json_to_yaml.py`
- Structured format ideal for documentation and version control

### 📝 Documentation

#### New Documentation Files
- **docs/ARTIFACTS-QUICKSTART.md** - Quick reference guide for using reports
  - Access instructions
  - Format selection guide
  - Opening HTML reports
  - Integration examples

- **docs/ARTIFACT-FORMATS.md** - Comprehensive artifact documentation
  - Detailed format specifications
  - Use case recommendations
  - Processing pipeline
  - Troubleshooting guide
  - Customization instructions

- **IMPLEMENTATION-SUMMARY.md** - Project completion summary
  - Overview of all changes
  - File structure after scan
  - How to use reports
  - Benefits matrix
  - Testing and customization

#### Documentation Updates
- **README.md** 
  - Added prominent mention of HTML reports
  - Added links to new documentation
  - Highlighted report artifacts section

### 🧪 Testing

- **NEW**: `tests/test_html_reports.py` - Comprehensive test suite
  - Semgrep HTML generation tests
  - ZAP HTML generation tests
  - Empty/no-findings scenario tests
  - Validates key content presence
  - All tests passing ✅

### 🔄 Script Updates

#### Updated: `scripts/run-semgrep.sh`
- Added YAML generation: `python3 scripts/convert_json_to_yaml.py`
- Added HTML generation: `python3 scripts/generate-html-report.py semgrep`
- Outputs: `semgrep.yaml`, `semgrep.html` (in addition to existing JSON)

#### Updated: `scripts/run-zap.sh`
- Added HTML generation: `python3 scripts/generate-html-report.py zap`
- Outputs: `zap.html` (in addition to existing JSON/YAML)

### 📊 Report Artifacts

#### SAST Artifacts (Semgrep)
```
✅ semgrep.json          (existing)
✨ semgrep.yaml          (NEW)
✨ semgrep.html          (NEW) - Interactive report
✅ sast-normalized.json  (existing)
✅ sast-summary.md       (existing)
```

#### DAST Artifacts (OWASP ZAP)
```
✅ zap.json              (existing)
✅ zap.yaml              (existing)
✨ zap.html              (NEW) - Interactive report
✅ dast-normalized.json  (existing)
✅ dast-summary.md       (existing)
✅ zap.md                (existing)
```

### 🔧 Technical

- **Backward Compatible**: No breaking changes to existing workflows
- **No Workflow Changes Needed**: GitHub Actions automatically captures new files
- **Python 3 Only**: Requires Python 3.6+
- **No Dependencies**: Uses only Python stdlib (json, sys, pathlib, datetime, urllib)
- **Performant**: Minimal overhead, concurrent with existing scripts

### 🎨 Semgrep HTML Report Features

- Dashboard showing finding counts by severity
- Color-coded severity badges
- Collapsible detailed findings
- File path with line numbers
- CWE and OWASP mapping
- Full metadata in structured format
- Print-to-PDF support
- Responsive design

### 🔍 ZAP HTML Report Features

- Risk assessment dashboard
- Alerts organized by site/URL
- Instance details with HTTP methods and parameters
- Solution and reference documentation
- Risk-level color coding
- Compact instance summary (first 10 + count)
- Professional styling
- Print-friendly layout

### ✅ Validation

- Python syntax validation: `python -m py_compile` ✅
- All test cases passing ✅
- No linting errors
- Comprehensive error handling
- Edge cases handled (empty results, special characters, large datasets)

### 🚀 Usage

#### Local Execution
```bash
# SAST
bash scripts/run-semgrep.sh target reports
open reports/semgrep.html  # View in browser

# DAST  
export TARGET_URL=https://example.com DAST_MODE=baseline
bash scripts/run-zap.sh reports
open reports/zap.html  # View in browser
```

#### GitHub Actions
- No changes needed
- HTML and YAML files automatically included in artifacts
- Download from workflow run's Artifacts section

### 📋 Migration Guide

For existing users:
1. Pull latest code
2. No configuration changes needed
3. Existing artifacts continue to work
4. New HTML and YAML files appear in next scan
5. No impact on security gate or policy enforcement

### 🐛 Known Issues

None. Implementation is complete and tested.

### 🔐 Security Notes

- HTML reports contain finding details (appropriate for authorized users only)
- No sensitive data is included beyond what was in JSON
- Reports should be downloaded/viewed securely
- Treat HTML reports as you would JSON reports in terms of access control

### 📞 Support

For questions about new features:
1. Check [ARTIFACTS-QUICKSTART.md](docs/ARTIFACTS-QUICKSTART.md)
2. Review [ARTIFACT-FORMATS.md](docs/ARTIFACT-FORMATS.md)  
3. Run tests: `python tests/test_html_reports.py`
4. Customize as needed using instructions in docs

---

**Status**: ✅ Production Ready

All features tested, documented, and ready for deployment.
