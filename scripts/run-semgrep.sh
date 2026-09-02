#!/usr/bin/env bash
set -euo pipefail
TARGET_DIRECTORY="${1:-.}"
REPORT_DIRECTORY="${2:-reports/sast}"
SEMGREP_CONFIG="${SEMGREP_CONFIG:-auto}"
mkdir -p "$REPORT_DIRECTORY"
[[ -d "$TARGET_DIRECTORY" ]] || { echo "Target missing: $TARGET_DIRECTORY" >&2; exit 2; }
command -v semgrep >/dev/null 2>&1 || python3 -m pip install --disable-pip-version-check semgrep
set +e
semgrep scan --config "$SEMGREP_CONFIG" --json --output "$REPORT_DIRECTORY/semgrep.json" "$TARGET_DIRECTORY"
scanner_rc=$?
set -e
[[ -s "$REPORT_DIRECTORY/semgrep.json" ]] || { echo "Semgrep report missing (scanner rc=$scanner_rc)" >&2; exit 2; }
python3 - "$REPORT_DIRECTORY/semgrep.json" <<'PY'
import json, sys
from pathlib import Path
report=json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
if not isinstance(report, dict) or not isinstance(report.get("results", []), list):
    raise SystemExit("Invalid Semgrep JSON")
print(f"Semgrep findings: {len(report.get('results', []))}")
PY
exit 0
