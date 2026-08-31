#!/usr/bin/env bash
set -euo pipefail
pick(){ local a="${1:-}" b="${2:-}" d="${3:-}"; if [[ -n "$a" ]]; then printf '%s' "$a"; elif [[ -n "$b" ]]; then printf '%s' "$b"; else printf '%s' "$d"; fi; }
repo=$(pick "${WD_REPOSITORY:-}" "${RD_REPOSITORY:-}" '')
sha=$(pick "${WD_SHA:-}" "${RD_SHA:-}" '')
app=$(pick "${WD_APP_TYPE:-}" "${RD_APP_TYPE:-}" auto)
url=$(pick "${WD_TARGET_URL:-}" "${RD_TARGET_URL:-}" '')
openapi=$(pick "${WD_OPENAPI_URL:-}" "${RD_OPENAPI_URL:-}" '')
mode=$(pick "${WD_DAST_MODE:-}" "${RD_DAST_MODE:-}" baseline)
[[ "$repo" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || { echo 'Invalid repository'; exit 2; }
[[ "$sha" =~ ^[0-9a-fA-F]{7,40}$ ]] || { echo 'Invalid commit SHA'; exit 2; }
[[ "$app" =~ ^(auto|web|api|cloud-native|desktop|library)$ ]] || exit 2
[[ "$mode" =~ ^(baseline|full|api|none)$ ]] || exit 2
{
 echo "repository=$repo"; echo "sha=$sha"; echo "app_type=$app"; echo "target_url=$url"; echo "openapi_url=$openapi"; echo "dast_mode=$mode";
} >> "$GITHUB_OUTPUT"
