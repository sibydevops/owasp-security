# Automatic Security Scanning Setup

## What Runs Automatically Now

✅ **SAST (Semgrep)** - Static Application Security Testing
- ✅ Runs on every push to main/develop
- ✅ Runs on every pull request to main/develop  
- ✅ Runs nightly at 2 AM UTC (scheduled)
- ✅ Always works (no target needed)

⏭️ **DAST (OWASP ZAP)** - Dynamic Application Security Testing
- ⏭️ Skipped automatically (no target URL provided yet)
- 🔄 Will start automatically when `STAGING_URL` secret is added
- 🔄 Runs on Saturday nights at 4 AM UTC (when secret is configured)

---

## Automatic Execution Events

### 1. **On Every Push to Main/Develop**
```
When: Push event to main or develop branch
What runs: SAST (Semgrep) only
DAST: Skipped (no target URL)
Time: Immediate
```

### 2. **On Every Pull Request to Main/Develop**
```
When: Pull request created/updated targeting main or develop
What runs: SAST (Semgrep) only
DAST: Skipped (no target URL)
Time: Immediate
```

### 3. **Nightly at 2 AM UTC**
```
When: Scheduled cron job (0 2 * * *)
What runs: SAST (Semgrep)
DAST: Skipped (no target URL configured)
Time: Every day at 2 AM UTC
Repository: sibydevops/owasp-security (security repo)
```

### 4. **Weekly at 4 AM UTC (Saturdays)**
```
When: Scheduled cron job (0 4 * * 6)
What runs: SAST (Semgrep)
DAST: Skipped (waiting for STAGING_URL secret)
Time: Every Saturday at 4 AM UTC
Note: Ready for DAST when you add STAGING_URL
```

### 5. **Manual Dispatch (Any Time)**
```
When: You manually trigger from GitHub UI
What runs: SAST + optional DAST
DAST: Runs only if you provide target_url parameter
Time: On-demand
```

---

## How to Enable DAST (Once You Have a Staging URL)

### Step 1: Get Your Staging URL Ready
```bash
# Ensure your staging environment is:
✓ Non-production
✓ Reachable from GitHub runners
✓ Authorized for security testing
✓ No real user data

curl -v https://staging.your-app.com
```

### Step 2: Add STAGING_URL Secret to Repository

**Option A: GitHub UI**
1. Go to **Settings** → **Secrets and variables** → **Actions**
2. Click **New repository secret**
3. Name: `STAGING_URL`
4. Value: `https://staging.your-app.com`
5. Click **Add secret**

**Option B: GitHub CLI**
```bash
gh secret set STAGING_URL --body "https://staging.your-app.com"
```

### Step 3: Automatic DAST Activation
Once `STAGING_URL` secret is added:
- ✅ Saturday 4 AM UTC scans will include DAST
- ✅ Manual dispatch can provide it directly
- ✅ SAST scans remain unaffected

---

## Current Status

| Trigger | SAST | DAST | Frequency |
|---------|------|------|-----------|
| Push to main/develop | ✅ | ⏭️ | Every push |
| Pull request | ✅ | ⏭️ | Every PR |
| Nightly (2 AM UTC) | ✅ | ⏭️ | Daily |
| Weekly (4 AM Sat UTC) | ✅ | ⏭️ Waiting for secret | Weekly |
| Manual dispatch | ✅ | ✅ (if provided) | On-demand |

---

## Workflow Files Modified

✅ `.github/workflows/central-security.yml`
- Added push trigger (main/develop)
- Added pull_request trigger (main/develop)
- Added two schedule triggers (nightly + weekly)
- Added STAGING_URL and SCHEDULED_DAST_MODE env vars

✅ `scripts/normalize-inputs.sh`
- Enhanced to handle scheduled runs
- Falls back to STAGING_URL secret for DAST when scheduling
- Maintains all existing dispatch capabilities

---

## Testing the Automatic Setup

### Test 1: Verify Push Trigger
```bash
git commit --allow-empty -m "Test security scan"
git push origin main
```
→ Watch GitHub Actions for "Central OWASP Security Scan" job

### Test 2: Verify Schedule (Wait for 2 AM UTC)
Go to **Actions** tab → See "Central OWASP Security Scan" scheduled entries

### Test 3: Enable DAST
```bash
gh secret set STAGING_URL --body "https://staging.your-app.com"
```
→ Next Saturday 4 AM UTC scan will include DAST

---

## Artifact Locations

All scans automatically upload reports to GitHub Actions artifacts:

### After Each Run:
- **SAST Reports**: `artifacts/sast-<commit-sha>/`
  - `semgrep.json` - Raw findings
  - `semgrep.yaml` - Structured OWASP mapping
  - `semgrep.html` - Interactive report
  - `sast-normalized.json` - Normalized format
  - `sast-summary.md` - Markdown summary

- **DAST Reports** (when enabled): `artifacts/dast-<commit-sha>/`
  - `zap.json` - Raw findings
  - `zap.yaml` - Structured OWASP mapping
  - `zap.html` - Interactive report
  - `zap.md` - Markdown summary
  - `dast-normalized.json` - Normalized format

---

## Troubleshooting

### "Schedule not triggering"
- Schedules run on the **security repository** only (sibydevops/owasp-security)
- Must be public or have self-hosted runner enabled
- GitHub requires minimum 5-minute intervals

### "DAST still not running on schedule"
- `STAGING_URL` secret not yet added
- After adding secret, it activates for next scheduled run
- Manual dispatch works immediately if you provide target_url

### "Push trigger not working"
- Ensure you're pushing to `main` or `develop` branch
- Check branch protection rules don't block the workflow
- Review Actions tab for error logs

---

## Next Steps

1. **Test push trigger**: Make a commit and push
2. **Monitor nightly scans**: Check Actions tab 
3. **When ready for DAST**: Add `STAGING_URL` secret
4. **Review reports**: Download HTML reports from artifacts

---

## Security Notes

⚠️ Before enabling DAST with STAGING_URL:
- [ ] Environment is **non-production**
- [ ] Have **written authorization** for testing
- [ ] No **real user data** in test environment
- [ ] No **production credentials** stored
- [ ] Understand **full scans can modify data** (if full mode)

---

**Status**: ✅ Automatic SAST enabled
**Next**: Add STAGING_URL secret to enable automatic DAST
