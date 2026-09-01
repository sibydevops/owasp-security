# Local demo DAST setup

Copy these files into the repository:

- `owasp-penetration-testing-local-demo.yml` to `.github/workflows/owasp-penetration-testing.yml`
- `run-zap.sh` to `scripts/run-zap.sh`
- `security-gate.py` to `scripts/security-gate.py`

No DAST URL is required. When `target_url` and `DAST_TARGET_URL` are empty, the workflow starts an isolated OWASP Juice Shop container at `http://127.0.0.1:3000` in the DAST runner.

Recommended repository variables during pipeline validation:

- `DEFAULT_DAST_MODE=baseline`
- `FAIL_ON_SAST=ERROR`
- `FAIL_ON_ZAP_RISK=NONE`

Juice Shop is intentionally vulnerable, so switch `FAIL_ON_ZAP_RISK` to `HIGH` only when a failing DAST gate is expected.
