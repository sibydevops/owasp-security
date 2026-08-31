#!/usr/bin/env bash
set -euo pipefail
rm -rf target
header=$(printf 'x-access-token:%s' "$GH_TOKEN" | base64 -w0)
git -c http.https://github.com/.extraheader="AUTHORIZATION: basic $header" clone --filter=blob:none --no-checkout "https://github.com/${TARGET_REPOSITORY}.git" target
git -C target fetch --depth=1 origin "$TARGET_SHA"
git -C target -c advice.detachedHead=false checkout "$TARGET_SHA"
test "$(git -C target rev-parse HEAD)" = "$(git -C target rev-parse "$TARGET_SHA")"
