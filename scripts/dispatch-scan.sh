#!/usr/bin/env bash
set -euo pipefail
central=${1:?central owner/repo}; target=${2:?target owner/repo}; sha=${3:?sha}; type=${4:-auto}; url=${5:-}; mode=${6:-baseline}; openapi=${7:-}
gh api -X POST "repos/$central/dispatches" -f event_type=owasp-security-scan --input - <<JSON
{"event_type":"owasp-security-scan","client_payload":{"target_repository":"$target","target_sha":"$sha","app_type":"$type","target_url":"$url","dast_mode":"$mode","openapi_url":"$openapi"}}
JSON
