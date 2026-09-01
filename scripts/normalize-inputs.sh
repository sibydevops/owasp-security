#!/usr/bin/env bash
set -euo pipefail
pick(){ local a="${1:-}" b="${2:-}" d="${3:-}"; if [[ -n "$a" ]]; then printf '%s' "$a"; elif [[ -n "$b" ]]; then printf '%s' "$b"; else printf '%s' "$d"; fi; }

# For automatic triggers (push, pull_request, schedule), use STAGING_URL secret
# For manual triggers (dispatch, repository_dispatch), use provided inputs
event_name="${GITHUB_EVENT_NAME:-unknown}"

if [[ "$event_name" == "push" || "$event_name" == "pull_request" || "$event_name" == "schedule" ]]; then
  # Automatic trigger: use current repo/sha with STAGING_URL secret for DAST
  repo="${GITHUB_REPOSITORY}"
  sha="${GITHUB_SHA}"
  app="auto"
  url="${STAGING_URL:-}"  # Will be empty if secret not configured, DAST will skip
  openapi=""
  mode="${url:+baseline}"  # baseline if url exists, else empty
  mode="${mode:-none}"     # default to 'none' if still empty
else
  # Manual trigger: use provided inputs or payloads
  repo=$(pick "${WD_REPOSITORY:-}" "${RD_REPOSITORY:-}" '')
  sha=$(pick "${WD_SHA:-}" "${RD_SHA:-}" '')
  app=$(pick "${WD_APP_TYPE:-}" "${RD_APP_TYPE:-}" auto)
  url=$(pick "${WD_TARGET_URL:-}" "${RD_TARGET_URL:-}" '')
  openapi=$(pick "${WD_OPENAPI_URL:-}" "${RD_OPENAPI_URL:-}" '')
  mode=$(pick "${WD_DAST_MODE:-}" "${RD_DAST_MODE:-}" baseline)
fi

[[ "$repo" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || { echo 'Invalid repository'; exit 2; }
[[ "$sha" =~ ^[0-9a-fA-F]{7,40}$ ]] || { echo 'Invalid commit SHA'; exit 2; }
[[ "$app" =~ ^(auto|web|api|cloud-native|desktop|library)$ ]] || exit 2
[[ "$mode" =~ ^(baseline|full|api|none)$ ]] || exit 2

{
 echo "repository=$repo"
 echo "sha=$sha"
 echo "app_type=$app"
 echo "target_url=$url"
 echo "openapi_url=$openapi"
 echo "dast_mode=$mode"
} >> "$GITHUB_OUTPUT"
