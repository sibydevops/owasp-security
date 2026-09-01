# DAST (Dynamic Application Security Testing) - Setup & Troubleshooting

## Why DAST Didn't Run

DAST (OWASP ZAP scanning) only runs when **both** of these conditions are met:

```yaml
if: ${{ needs.validate.outputs.dast_mode != 'none' 
    && needs.validate.outputs.target_url != '' }}
```

**DAST will be skipped if:**
- ❌ No `target_url` provided (parameter was empty)
- ❌ `dast_mode` set to `'none'`
- ❌ Only SAST is needed (no HTTP target available)

---

## How to Enable DAST

### Via GitHub Actions Workflow Dispatch

1. Go to **Actions** → **Central OWASP Security Scan**
2. Click **Run workflow**
3. Fill in parameters:

```
target_repository: org/my-app
target_sha: [commit-hash]
app_type: web                    # ← Select your app type
target_url: https://staging.example.com  # ← REQUIRED for DAST
dast_mode: baseline              # ← Choose: baseline, full, or api
openapi_url: [leave empty unless API]
```

### Via Repository Dispatch (API)

```bash
curl -X POST \
  https://api.github.com/repos/ORG/security-workflows/dispatches \
  -H "Authorization: token $GH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "event_type": "owasp-security-scan",
    "client_payload": {
      "target_repository": "org/my-app",
      "target_sha": "abc123...",
      "app_type": "web",
      "target_url": "https://staging.example.com",
      "dast_mode": "baseline"
    }
  }'
```

---

## DAST Modes

| Mode | Purpose | Time | Details |
|------|---------|------|---------|
| **baseline** | Quick scan | 5-15 min | Spider + passive scan. Best for CI/CD. |
| **full** | Comprehensive scan | 30-90 min | Active attack tests. For dedicated testing. |
| **api** | API scan | 10-30 min | OpenAPI-driven testing. Requires OpenAPI spec. |
| **none** | Skip DAST | - | Only run SAST. Use for libraries/non-web apps. |

### Baseline Scan (Recommended for CI/CD)
```yaml
app_type: web
target_url: https://staging.example.com
dast_mode: baseline
```

### Full Scan (Comprehensive Testing)
```yaml
app_type: web
target_url: https://staging.example.com
dast_mode: full
```
⚠️ **Warning**: Full scan actively attacks the application. Only use on:
- Ephemeral/disposable test environments
- Non-production instances
- Explicitly authorized targets

### API Scan
```yaml
app_type: api
target_url: https://api.staging.example.com
dast_mode: api
openapi_url: https://api.staging.example.com/openapi.json
```

---

## Target Requirements

### ✅ Valid Targets
- Staging/test environments
- Ephemeral test instances
- Internal development URLs
- Explicitly authorized systems
- **Non-production only**

### ❌ Invalid Targets
- Production systems (without separate approval)
- Systems you don't own
- Systems without written authorization
- External third-party APIs
- Targets outside your network

### Firewall/Network Access
The self-hosted runner must be able to reach the target URL:
- HTTP/HTTPS (ports 80, 443)
- Same network or VPN access
- No blocking firewalls
- DNS resolution working

---

## Troubleshooting DAST Issues

### Problem: DAST job doesn't appear in workflow run

**Cause**: `target_url` parameter was empty or `dast_mode` was `'none'`

**Solution**:
1. Run workflow dispatch again
2. Provide a valid `target_url`
3. Set `dast_mode` to `baseline`, `full`, or `api`
4. Verify `app_type` matches your application

### Problem: DAST job fails with connection error

**Cause**: Target URL is not reachable from runner

**Solutions**:
1. Verify target is running and accessible
2. Check firewall/security groups allow runner access
3. Verify DNS resolution: `nslookup staging.example.com`
4. Check VPN/network connectivity from runner
5. Try simpler URL (e.g., without path): `https://staging.example.com`

### Problem: ZAP container fails to pull

**Cause**: No network access to ghcr.io (GitHub Container Registry)

**Solutions**:
1. Verify outbound HTTPS (port 443) to `ghcr.io`
2. Pre-pull container on runner: `docker pull ghcr.io/zaproxy/zaproxy:stable`
3. Cache container image on runner
4. Use private registry mirror if available

### Problem: ZAP scan times out

**Cause**: 
- Full scan taking too long
- Target responding slowly
- Network issues

**Solutions**:
1. Use `baseline` mode instead of `full`
2. Increase timeout in workflow (default 90 min)
3. Check target performance/availability
4. Reduce scope with API mode if scanning API only

### Problem: DAST skipped but target_url was provided

**Cause**: Validation script (`validate-target.sh`) rejected the URL

**Solutions**:
1. Check target matches `ALLOWED_TARGET_SUFFIXES`
2. Verify no production domains in allowed list
3. Check GitHub organization variable: `ALLOWED_TARGET_SUFFIXES`
4. Example configuration:
   ```
   ALLOWED_TARGET_SUFFIXES=staging.internal,dev.example.com,test.example.com
   ```

---

## Security Considerations

### Before Running DAST

⚠️ **CRITICAL**: Ensure written authorization for all DAST scanning

- [ ] Target is non-production
- [ ] Target is explicitly authorized for testing
- [ ] Full scans only on ephemeral/disposable environments
- [ ] No PII or real user data in test target
- [ ] No production credentials used
- [ ] Team lead has approved scope and timing

### ZAP Active Scan Impact

Full and active scans may:
- Generate lots of web server logs
- Trigger security alerts/alarms
- Modify application data (form submissions)
- Create test orders/transactions
- Temporarily impact performance
- Trigger rate limiting

**Mitigation**:
- Run during maintenance windows
- Use dedicated test data/accounts
- Monitor target during scan
- Have rollback plan ready
- Use baseline mode for CI/CD (passive only)

---

## Best Practices

### 1. Start with Baseline
```yaml
dast_mode: baseline  # Quick, passive, safe for CI/CD
```

### 2. Schedule Full Scans Separately
- Not every commit
- Scheduled weekly or monthly
- During maintenance windows
- On disposable test environment

### 3. Combine SAST + DAST
- SAST (Semgrep) catches code issues
- DAST (ZAP) catches runtime issues
- Both together = comprehensive coverage

### 4. Monitor Results
- Review HTML reports
- Track trends over time
- Prioritize by severity
- Set up alerts for critical issues

### 5. Integrate with Development
- Link findings to code
- Create issues for remediation
- Track fix progress
- Retest after fixes

---

## DAST Reports

After DAST completes, check artifacts for:

| File | Purpose |
|------|---------|
| `zap.json` | Raw JSON results (for parsing) |
| `zap.yaml` | Structured YAML format |
| `zap.html` | Interactive HTML report |
| `zap.md` | Markdown summary |
| `dast-normalized.json` | OWASP-categorized findings |

### View HTML Report
```bash
# Download from GitHub Actions artifacts
# Extract dast-[commit].zip
# Open zap.html in web browser
```

---

## Common DAST Issues & Solutions

| Issue | Solution |
|-------|----------|
| "Connection refused" | Target not running, check if service is up |
| "DNS resolution failed" | Wrong hostname, verify DNS/network |
| "Timeout" | Use baseline mode, increase timeout, check network |
| "Too many alerts" | Normal for first scans, baseline mode reduces noise |
| "Only passive findings" | Expected with baseline mode, switch to full for active tests |
| "No findings" | Target may be secure, try different mode/target |
| "Authentication required" | API auth may not be supported, check ZAP docs |

---

## Next Steps

1. **Review** [IMPLEMENTATION-GUIDE.md](../docs/IMPLEMENTATION-GUIDE.md) section on DAST
2. **Prepare** a test environment
3. **Configure** `target_url` in workflow
4. **Run** baseline DAST scan
5. **Review** results in HTML reports
6. **Schedule** full scans for high-risk apps

---

## Support

For more information:
- [OWASP ZAP Documentation](https://www.zaproxy.org/docs/)
- [OWASP WSTG Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Project README](../README.md)
- [Implementation Guide](../docs/IMPLEMENTATION-GUIDE.md)
