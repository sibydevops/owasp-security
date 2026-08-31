#!/usr/bin/env bash
set -euo pipefail
out=${1:?output}; mkdir -p "$out"; chmod 777 "$out"
image=ghcr.io/zaproxy/zaproxy:stable
common=(--rm -v "$PWD/$out:/zap/wrk/:rw" "$image")
case "$DAST_MODE" in
 baseline) docker run "${common[@]}" zap-baseline.py -t "$TARGET_URL" -J zap.json -w zap.md -I || true ;;
 full) docker run "${common[@]}" zap-full-scan.py -t "$TARGET_URL" -J zap.json -w zap.md -I || true ;;
 api)
   spec=${OPENAPI_URL:-$TARGET_URL}
   docker run "${common[@]}" zap-api-scan.py -t "$spec" -f openapi -J zap.json -w zap.md -I || true ;;
 *) echo 'Unsupported mode'; exit 2 ;;
esac
if [ -f "$out/zap.json" ]; then
  python3 scripts/convert_json_to_yaml.py "$out/zap.json" "$out/zap.yaml"
else
  echo '{"site":[]}' > "$out/zap.json"
  python3 scripts/convert_json_to_yaml.py "$out/zap.json" "$out/zap.yaml"
fi
