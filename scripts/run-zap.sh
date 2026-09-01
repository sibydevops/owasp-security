#!/usr/bin/env bash

set -euo pipefail

REPORT_DIR="${1:-reports}"
TARGET_URL="${TARGET_URL:-}"
OPENAPI_URL="${OPENAPI_URL:-}"
DAST_MODE="${DAST_MODE:-baseline}"
ZAP_IMAGE="${ZAP_IMAGE:-ghcr.io/zaproxy/zaproxy:stable}"

log() {
  printf '[run-zap] %s\n' "$*"
}

fail() {
  printf '[run-zap] ERROR: %s\n' "$*" >&2
  exit 2
}

if [[ -z "$TARGET_URL" ]]; then
  fail "TARGET_URL is required"
fi

case "$DAST_MODE" in
  baseline|full|api)
    ;;
  *)
    fail "Unsupported DAST_MODE: $DAST_MODE"
    ;;
esac

if [[ "$DAST_MODE" == "api" && -z "$OPENAPI_URL" ]]; then
  fail "OPENAPI_URL is required when DAST_MODE=api"
fi

mkdir -p "$REPORT_DIR"

REPORT_DIR="$(
  cd "$REPORT_DIR"
  pwd
)"

# ZAP runs as a non-root user inside the container and must be able
# to write report files into the mounted directory.
chmod 0777 "$REPORT_DIR"

log "DAST mode: $DAST_MODE"
log "Target URL: $TARGET_URL"
log "Report directory: $REPORT_DIR"
log "ZAP image: $ZAP_IMAGE"

log "Pulling OWASP ZAP container image"
docker pull "$ZAP_IMAGE"

docker_arguments=(
  docker
  run
  --rm
  --network
  host
  --volume
  "$REPORT_DIR:/zap/wrk/:rw"
  "$ZAP_IMAGE"
)

set +e

case "$DAST_MODE" in
  baseline)
    log "Starting OWASP ZAP baseline scan"

    "${docker_arguments[@]}" \
      zap-baseline.py \
      -t "$TARGET_URL" \
      -J zap.json \
      -w zap.md \
      -r zap.html \
      -I

    zap_exit_code=$?
    ;;

  full)
    log "Starting OWASP ZAP full scan"

    "${docker_arguments[@]}" \
      zap-full-scan.py \
      -t "$TARGET_URL" \
      -J zap.json \
      -w zap.md \
      -r zap.html \
      -I

    zap_exit_code=$?
    ;;

  api)
    log "Starting OWASP ZAP OpenAPI scan"
    log "OpenAPI URL: $OPENAPI_URL"

    "${docker_arguments[@]}" \
      zap-api-scan.py \
      -t "$OPENAPI_URL" \
      -f openapi \
      -J zap.json \
      -w zap.md \
      -r zap.html \
      -I

    zap_exit_code=$?
    ;;
esac

set -e

log "OWASP ZAP scanner exit code: $zap_exit_code"

# ZAP can return a non-zero status when warnings or alerts are discovered.
# Security findings are evaluated later by security-gate.py.
#
# The scanner execution is considered technically successful when a valid
# zap.json report was generated.

if [[ ! -s "$REPORT_DIR/zap.json" ]]; then
  printf '[run-zap] ERROR: ZAP did not create zap.json\n' >&2

  printf '[run-zap] Files found in report directory:\n' >&2

  find "$REPORT_DIR" \
    -maxdepth 3 \
    -type f \
    -print \
    2>/dev/null || true

  if [[ "$zap_exit_code" -eq 0 ]]; then
    exit 2
  fi

  exit "$zap_exit_code"
fi

log "Validating reports/zap.json"

python3 - "$REPORT_DIR/zap.json" <<'PY'
import json
import sys
from pathlib import Path

report_path = Path(sys.argv[1])

try:
    report = json.loads(
        report_path.read_text(encoding="utf-8")
    )
except OSError as exc:
    raise SystemExit(
        f"Unable to read ZAP report: {exc}"
    )
except json.JSONDecodeError as exc:
    raise SystemExit(
        f"Invalid ZAP JSON at line {exc.lineno}, "
        f"column {exc.colno}: {exc.msg}"
    )

if not isinstance(report, dict):
    raise SystemExit(
        "ZAP report must contain a JSON object"
    )

sites = report.get("site", [])

if not isinstance(sites, list):
    raise SystemExit(
        "ZAP report 'site' property must be an array"
    )

alert_count = 0
risk_counts = {
    "HIGH": 0,
    "MEDIUM": 0,
    "LOW": 0,
    "INFORMATIONAL": 0,
}

for site in sites:
    if not isinstance(site, dict):
        continue

    alerts = site.get("alerts", [])

    if not isinstance(alerts, list):
        continue

    alert_count += len(alerts)

    for alert in alerts:
        if not isinstance(alert, dict):
            continue

        raw_risk = str(
            alert.get("riskdesc")
            or alert.get("risk")
            or alert.get("riskcode")
            or ""
        ).strip().upper()

        if "HIGH" in raw_risk or raw_risk == "3":
            risk_counts["HIGH"] += 1
        elif "MEDIUM" in raw_risk or raw_risk == "2":
            risk_counts["MEDIUM"] += 1
        elif "LOW" in raw_risk or raw_risk == "1":
            risk_counts["LOW"] += 1
        else:
            risk_counts["INFORMATIONAL"] += 1

print("ZAP report validation succeeded")
print(f"Sites: {len(sites)}")
print(f"Alerts: {alert_count}")
print(f"High: {risk_counts['HIGH']}")
print(f"Medium: {risk_counts['MEDIUM']}")
print(f"Low: {risk_counts['LOW']}")
print(
    "Informational: "
    f"{risk_counts['INFORMATIONAL']}"
)
PY

log "ZAP report generated successfully"
log "Security findings will be evaluated by security-gate.py"

exit 0