#!/usr/bin/env bash
set -euo pipefail
src=${1:?source}; out=${2:?output}; mkdir -p "$out"
docker run --rm --network=none -v "$PWD/$src:/src:ro" -v "$PWD/$out:/out" semgrep/semgrep:latest \
  semgrep scan --config /src/configs/semgrep  --config p/owasp-top-ten --json --output /out/semgrep.json /src || rc=$?
rc=${rc:-0}
# Semgrep can return nonzero for findings/errors. Preserve report, gate later.
test -s "$out/semgrep.json" || { echo '{"results":[],"errors":[{"message":"Semgrep produced no report"}]}' > "$out/semgrep.json"; }

# Convert JSON to YAML format
python3 scripts/convert_json_to_yaml.py "$out/semgrep.json" "$out/semgrep.yaml"

# Generate HTML report
python3 scripts/generate-html-report.py semgrep "$out/semgrep.json" "$out/semgrep.html"

exit 0
