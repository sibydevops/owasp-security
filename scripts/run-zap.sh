#!/usr/bin/env bash
set -euo pipefail

out=${1:?output}
mkdir -p "$out"
chmod 777 "$out"

# Validate required environment variables
if [ -z "${TARGET_URL:-}" ]; then
    echo "ERROR: TARGET_URL environment variable is required for DAST"
    echo "DAST will be skipped. To enable DAST:"
    echo "  1. Provide target_url parameter in workflow dispatch"
    echo "  2. Ensure target is a non-production environment"
    echo "  3. Set dast_mode to: baseline, full, or api"
    exit 0  # Don't fail - DAST is optional
fi

if [ -z "${DAST_MODE:-}" ]; then
    echo "ERROR: DAST_MODE environment variable is required"
    echo "Valid modes: baseline, full, api"
    exit 0  # Don't fail - DAST is optional
fi

echo "=========================================="
echo "OWASP ZAP Dynamic Security Testing"
echo "=========================================="
echo "Mode: $DAST_MODE"
echo "Target: $TARGET_URL"
echo ""

# Check if target is reachable
echo "Checking target reachability..."
if ! timeout 10 curl -s -m 5 -o /dev/null -w "%{http_code}" "$TARGET_URL" 2>/dev/null | grep -qE "200|301|302|401|403"; then
    echo "WARNING: Target URL may not be reachable"
    echo "Proceeding anyway - ZAP will attempt connection"
fi

echo "Starting ZAP scan (this may take several minutes)..."
image=ghcr.io/zaproxy/zaproxy:stable
common=(--rm -v "$PWD/$out:/zap/wrk/:rw" "$image")

# Run ZAP based on mode
case "$DAST_MODE" in
 baseline)
    echo "Running ZAP baseline scan..."
    docker run "${common[@]}" zap-baseline.py -t "$TARGET_URL" -J zap.json -w zap.md -I || true
    ;;
 full)
    echo "Running ZAP full scan (may take 30+ minutes)..."
    docker run "${common[@]}" zap-full-scan.py -t "$TARGET_URL" -J zap.json -w zap.md -I || true
    ;;
 api)
    spec=${OPENAPI_URL:-$TARGET_URL}
    echo "Running ZAP API scan..."
    echo "Spec: $spec"
    docker run "${common[@]}" zap-api-scan.py -t "$spec" -f openapi -J zap.json -w zap.md -I || true
    ;;
 *)
    echo "ERROR: Unsupported DAST_MODE: $DAST_MODE"
    echo "Valid modes: baseline, full, api"
    exit 2
    ;;
esac

echo ""
echo "ZAP scan completed"

# Process results
if [ -f "$out/zap.json" ]; then
  echo "Converting ZAP JSON to YAML..."
  python3 scripts/convert_json_to_yaml.py "$out/zap.json" "$out/zap.yaml"
  echo "Generating HTML report..."
  python3 scripts/generate-html-report.py zap "$out/zap.json" "$out/zap.html" || echo "WARNING: HTML report generation failed"
else
  echo "WARNING: No ZAP results found. Creating empty report."
  echo '{"site":[]}' > "$out/zap.json"
  python3 scripts/convert_json_to_yaml.py "$out/zap.json" "$out/zap.yaml"
  python3 scripts/generate-html-report.py zap "$out/zap.json" "$out/zap.html" || true
fi

echo "=========================================="
echo "DAST Reports:"
echo "  - $out/zap.json (raw results)"
echo "  - $out/zap.yaml (structured results)"
echo "  - $out/zap.html (interactive report)"
echo "  - $out/zap.md (markdown summary)"
echo "=========================================="
