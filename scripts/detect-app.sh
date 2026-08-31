#!/usr/bin/env bash
set -euo pipefail
root=${1:-.}; requested=${REQUESTED_APP_TYPE:-auto}
if [[ "$requested" != auto ]]; then type=$requested
elif find "$root" -maxdepth 4 -type f \( -name 'openapi*.yml' -o -name 'openapi*.yaml' -o -name 'swagger*.json' \) | grep -q .; then type=api
elif find "$root" -maxdepth 4 -type f \( -name 'Dockerfile' -o -name 'Chart.yaml' -o -name 'deployment.yaml' \) | grep -q .; then type=cloud-native
elif find "$root" -maxdepth 4 -type f \( -name '*.csproj' -o -name '*.sln' -o -name 'electron-builder.yml' \) | grep -q .; then type=desktop
elif find "$root" -maxdepth 4 -type f \( -name 'package.json' -o -name 'pom.xml' -o -name 'requirements.txt' -o -name 'go.mod' \) | grep -q .; then type=web
else type=library; fi
printf 'app_type=%s\n' "$type"
