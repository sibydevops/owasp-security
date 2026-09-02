#!/usr/bin/env bash
set -euo pipefail
REPORT_DIRECTORY="${1:-reports/dast-web}"
TARGET_URL="${TARGET_URL:-}"
OPENAPI_URL="${OPENAPI_URL:-}"
DAST_MODE="${DAST_MODE:-baseline}"
ZAP_RULES_FILE="${ZAP_RULES_FILE:-}"
ZAP_IMAGE="${ZAP_IMAGE:-ghcr.io/zaproxy/zaproxy:stable}"
[[ -n "$TARGET_URL" ]] || { echo "TARGET_URL is required" >&2; exit 2; }
case "$DAST_MODE" in baseline|full|api) ;; *) echo "Invalid DAST_MODE" >&2; exit 2;; esac
[[ "$DAST_MODE" != api || -n "$OPENAPI_URL" ]] || { echo "OPENAPI_URL is required" >&2; exit 2; }
mkdir -p "$REPORT_DIRECTORY"
REPORT_DIRECTORY="$(cd "$REPORT_DIRECTORY" && pwd)"
chmod 0777 "$REPORT_DIRECTORY"
args=(docker run --rm --network host --volume "$REPORT_DIRECTORY:/zap/wrk/:rw" "$ZAP_IMAGE")
reports=(-J zap.json -w zap.md -r zap.html -I)
if [[ -n "$ZAP_RULES_FILE" ]]; then
  [[ -s "$REPORT_DIRECTORY/$ZAP_RULES_FILE" ]] || { echo "Rules file missing" >&2; exit 2; }
  reports+=(-c "$ZAP_RULES_FILE")
fi
set +e
case "$DAST_MODE" in
  baseline) "${args[@]}" zap-baseline.py -t "$TARGET_URL" "${reports[@]}"; rc=$? ;;
  full) "${args[@]}" zap-full-scan.py -t "$TARGET_URL" "${reports[@]}"; rc=$? ;;
  api) "${args[@]}" zap-api-scan.py -t "$OPENAPI_URL" -f openapi "${reports[@]}"; rc=$? ;;
esac
set -e
sudo chown -R "$(id -u):$(id -g)" "$REPORT_DIRECTORY" 2>/dev/null || true
chmod -R u+rwX "$REPORT_DIRECTORY"
[[ -s "$REPORT_DIRECTORY/zap.json" ]] || { echo "ZAP report missing (scanner rc=$rc)" >&2; exit 2; }
python3 - "$REPORT_DIRECTORY/zap.json" <<'PY'
import json, sys
from pathlib import Path
report=json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
if not isinstance(report, dict) or not isinstance(report.get("site", []), list):
    raise SystemExit("Invalid ZAP JSON")
print("ZAP report valid")
PY
exit 0
