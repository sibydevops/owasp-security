#!/usr/bin/env bash
set -euo pipefail

REPORT_DIR="${1:-reports}"
TARGET_URL="${TARGET_URL:-}"
OPENAPI_URL="${OPENAPI_URL:-}"
DAST_MODE="${DAST_MODE:-baseline}"
ZAP_IMAGE="${ZAP_IMAGE:-ghcr.io/zaproxy/zaproxy:stable}"

[[ -n "$TARGET_URL" ]] || { echo "TARGET_URL is required" >&2; exit 2; }
case "$DAST_MODE" in baseline|full|api) ;; *) echo "Unsupported DAST_MODE: $DAST_MODE" >&2; exit 2;; esac
if [[ "$DAST_MODE" == api && -z "$OPENAPI_URL" ]]; then
  echo "OPENAPI_URL is required for api mode" >&2
  exit 2
fi

mkdir -p "$REPORT_DIR"
REPORT_DIR="$(cd "$REPORT_DIR" && pwd)"
chmod 0777 "$REPORT_DIR"

echo "Pulling $ZAP_IMAGE"
docker pull "$ZAP_IMAGE"

common=(docker run --rm --network host -v "$REPORT_DIR:/zap/wrk/:rw" "$ZAP_IMAGE")
set +e
case "$DAST_MODE" in
  baseline)
    "${common[@]}" zap-baseline.py -t "$TARGET_URL" -J zap.json -w zap.md -r zap.html -I
    rc=$?
    ;;
  full)
    "${common[@]}" zap-full-scan.py -t "$TARGET_URL" -J zap.json -w zap.md -r zap.html -I
    rc=$?
    ;;
  api)
    "${common[@]}" zap-api-scan.py -t "$OPENAPI_URL" -f openapi -J zap.json -w zap.md -r zap.html -I
    rc=$?
    ;;
esac
set -e

# ZAP automation scripts can return 1 or 2 for findings/warnings. The policy gate
# evaluates report severity later. Only missing/invalid output is a scanner failure.
if [[ ! -s "$REPORT_DIR/zap.json" ]]; then
  echo "ZAP failed to create zap.json (scanner exit code: $rc)" >&2
  exit "$rc"
fi
python3 - "$REPORT_DIR/zap.json" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as fh:
    data=json.load(fh)
if not isinstance(data, dict):
    raise SystemExit("ZAP report root is not an object")
PY

echo "ZAP completed with scanner exit code $rc; report created successfully"
exit 0
