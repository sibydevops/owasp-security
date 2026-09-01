#!/usr/bin/env bash
set -euo pipefail
src=${1:?source}
out=${2:?output}
mkdir -p "$out"

echo "=========================================="
echo "Semgrep Static Security Analysis (SAST)"
echo "=========================================="
echo "Source: $src"
echo "Output: $out"
echo ""

# Try to use remote OWASP ruleset first (requires network access to semgrep.dev)
# If network is unavailable, fall back to local config only
echo "Attempting Semgrep scan with OWASP Top Ten rules..."
docker run --rm -v "$PWD/$src:/src:ro" -v "$PWD/$out:/out" semgrep/semgrep:latest \
  semgrep scan --config /src/configs/semgrep --config p/owasp-top-ten --json --output /out/semgrep.json /src 2>/tmp/semgrep-error.log || {
  
  # Check if failure was due to network connectivity
  if grep -q "NameResolutionError\|ConnectionError\|HTTPSConnectionPool" /tmp/semgrep-error.log 2>/dev/null; then
    echo "WARNING: Cannot reach semgrep.dev (network unreachable). Falling back to local configuration only."
    # Retry with local config only
    docker run --rm --network=none -v "$PWD/$src:/src:ro" -v "$PWD/$out:/out" semgrep/semgrep:latest \
      semgrep scan --config /src/configs/semgrep --json --output /out/semgrep.json /src || rc=$?
  else
    # Different error - re-raise
    rc=$?
  fi
}

rc=${rc:-0}
# Semgrep can return nonzero for findings/errors. Preserve report, gate later.
if [ ! -s "$out/semgrep.json" ]; then
  echo '{"results":[],"errors":[{"message":"Semgrep produced no report"}]}' > "$out/semgrep.json"
fi

echo ""
echo "Converting Semgrep JSON to YAML..."
python3 scripts/convert_json_to_yaml.py "$out/semgrep.json" "$out/semgrep.yaml"

echo "Generating HTML report..."
python3 scripts/generate-html-report.py semgrep "$out/semgrep.json" "$out/semgrep.html" || echo "WARNING: HTML report generation failed"

echo ""
echo "=========================================="
echo "SAST Reports:"
echo "  - $out/semgrep.json (raw results)"
echo "  - $out/semgrep.yaml (structured results)"
echo "  - $out/semgrep.html (interactive report)"
echo "=========================================="

exit 0
