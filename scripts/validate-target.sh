#!/usr/bin/env bash
set -euo pipefail
python3 - <<'PY'
import os,sys,urllib.parse,ipaddress,socket
u=urllib.parse.urlparse(os.environ['TARGET_URL'])
if u.scheme not in ('http','https') or not u.hostname: sys.exit('TARGET_URL must be HTTP/HTTPS')
allowed=[x.strip().lower() for x in os.getenv('ALLOWED_TARGET_SUFFIXES','').split(',') if x.strip()]
if not allowed: sys.exit('ALLOWED_TARGET_SUFFIXES organization variable must be set')
h=u.hostname.lower()
if not any(h==s or h.endswith('.'+s) for s in allowed): sys.exit('Target host is outside approved suffixes')
print('Authorized target:',h)
PY
