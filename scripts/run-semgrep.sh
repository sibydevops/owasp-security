#!/usr/bin/env bash
set -euo pipefail
src=${1:?source}; out=${2:?output}; mkdir -p "$out"
docker run --rm --network=none -v "$PWD/$src:/src:ro" -v "$PWD/$out:/out" semgrep/semgrep:latest \
  semgrep scan --config /src/configs/semgrep  --config p/owasp-top-ten --json --output /out/semgrep.json /src || rc=$?
rc=${rc:-0}
# Semgrep can return nonzero for findings/errors. Preserve report, gate later.
test -s "$out/semgrep.json" || { echo '{"results":[],"errors":[{"message":"Semgrep produced no report"}]}' > "$out/semgrep.json"; }
exit 0
