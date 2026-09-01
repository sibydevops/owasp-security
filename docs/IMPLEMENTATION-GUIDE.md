# Implementation Guide

## 1. Select the trigger model

For zero changes in 10,000 application repositories, an organization GitHub App, organization webhook, or existing event platform must send `repository_dispatch` to the central repository. GitHub Actions in one repository do not receive push events for other repositories.

If a one-time bulk change is acceptable, deploy one of the caller examples to each repository and protect it with organization rulesets.

## 2. Create the central repository

Create `ORG/security-workflows`, copy this project, protect `main`, require reviews for `.github/workflows`, `scripts`, and rules, and pin a release tag such as `v1` after validation.

## 3. Configure runners

Use isolated ephemeral self-hosted Linux runners. Apply labels:

```text
self-hosted, linux, security
```

Install Docker, Git, Python 3, GitHub CLI, CA certificates, and internal DNS/CA trust.

### Network Access Requirements

Configure outbound network access as follows:

**Required** (for tool operation):
- `github.com` - Clone target repositories
- Container registries:
  - `ghcr.io` - For ZAP container
  - `docker.io` or `registry.hub.docker.com` - For Semgrep container

**Optional but recommended** (for enhanced scanning):
- `semgrep.dev` (HTTPS 443) - Download OWASP Top Ten ruleset
  - If unavailable: Script falls back to local config automatically
  - No workflow failure if unreachable

**Never allow:**
- Broad production network access
- Outbound to non-approved targets
- Access to private/sensitive infrastructure from this runner

### Network Failover Behavior

The Semgrep scanner will:
1. **Attempt remote rules first** (requires network to semgrep.dev)
   - Downloads OWASP Top Ten ruleset for enhanced scanning
   - Combines with local rules in `configs/semgrep/`
2. **Fallback to local rules** if network unavailable
   - Automatically retries with local config only
   - No workflow failure
   - Reduced rule coverage but still effective

This ensures scans complete even in air-gapped or restricted network environments.

## 4. Configure authentication

For public repositories, no custom token is required because the workflow can clone anonymously. For private repositories or restricted access, create `SECURITY_REPO_TOKEN` as an organization secret visible only to the central repository. Prefer a GitHub App installation token broker in production. The token needs read-only Contents access to target repositories. A separate token or GitHub App identity used by the dispatcher needs permission to send repository dispatch events to the central repository.

## 5. Configure organization variables

Set:

```text
ALLOWED_TARGET_SUFFIXES=dev.example.internal,test.example.internal
FAIL_ON_SAST=ERROR
FAIL_ON_ZAP_RISK=High
```

Never authorize production domains for active scans without a separate controlled process. ZAP full and API scans send attack payloads and may modify data or submit forms.

## 6. Put local Semgrep rules in target source

The workflow expects `target/configs/semgrep`. For a truly central ruleset, change `run-semgrep.sh` to mount this repository's `configs/semgrep` directory instead. The included `target-config-example` demonstrates an MIT-licensed rule. Review licenses for every community rule used.

## 7. Provide application target inventory

DAST needs a deployed target. The event producer should look up repository-to-target metadata from a central catalog and include:

```json
{
  "target_repository": "ORG/app",
  "target_sha": "0123456789abcdef",
  "app_type": "web",
  "target_url": "https://app-test.example.internal",
  "dast_mode": "baseline"
}
```

Use `dast_mode=api` and `openapi_url` for OpenAPI services. Use `none` for libraries and desktop applications with no HTTP endpoint.

## 8. Test manually

```bash
./scripts/dispatch-scan.sh ORG/security-workflows ORG/app SHA web https://app-test.example.internal baseline
```

Confirm exact SHA checkout, Semgrep artifact, ZAP artifact, gate behavior, cancellation, and runner cleanup.

## 9. Enable DAST (Optional)

⚠️ **Dynamic Application Security Testing (DAST) requires:**
- Non-production test environment URL
- Explicit written authorization
- Network access from runner to target
- Configuration of target URL and scan mode

For detailed DAST setup, requirements, security considerations, and troubleshooting:

**→ [See DAST-SETUP.md](DAST-SETUP.md)**

Key points:
- Provide `target_url` parameter to enable DAST
- Choose scan mode: `baseline` (quick, CI/CD), `full` (comprehensive), `api` (OpenAPI)
- Only authorized, non-production targets
- Full scans may impact application (form submissions, data changes)

## 10. Connect all repository changes

Configure the event producer to process push and pull-request events, extract the exact head SHA, enrich the event with catalog metadata, and send `repository_dispatch`. De-duplicate by `repository + SHA`. The central workflow concurrency key prevents duplicate runs for the same commit.

## 11. Branch enforcement

A status from a workflow running only in the central repository is not automatically a required check in the source repository. To block merges without adding a source-repository workflow, the event producer must use the GitHub Checks API against the source commit. That capability is outside pure GitHub Actions YAML and requires a GitHub App. If merge blocking is mandatory with Actions alone, use the reusable caller workflow in every source repository.

## 12. Application profiles

- Web: Semgrep plus ZAP baseline on each eligible change; full active scan only against disposable test targets.
- API: Semgrep plus ZAP API scan using OpenAPI.
- Cloud-native: scan the HTTP service after the existing deployment pipeline exposes an ephemeral URL.
- Desktop/native: Semgrep applies to supported languages. ZAP applies only to HTTP endpoints exposed by the application.
- Library/SDK/IaC: SAST only. DAST is not applicable without a running HTTP target.

## 13. OWASP governance

Use WSTG as the human and automated test catalog, ASVS as the application verification requirement baseline, and ZAP/Semgrep as partial automation. Automated ZAP does not cover business logic, role abuse, complex authorization, social engineering, or every WSTG test. Keep periodic manual penetration testing for high-risk applications.

## 14. Complete penetration-testing workflow

Use [OWASP-PENETRATION-TESTING-WORKFLOW.md](OWASP-PENETRATION-TESTING-WORKFLOW.md) for the operational assessment process. It covers written authorization and rules of engagement, scope and safety controls, reconnaissance, threat modeling, WSTG/ASVS/API/MASVS/cloud coverage, automated and manual execution, sanitized evidence, severity, reporting, risk decisions, remediation, retesting, and closure.

The central workflow is one part of that process. A successful GitHub Actions run does not replace manual authorization, business-logic and authorization testing, coverage review, or an independent assessment for high-risk applications.

---

## Troubleshooting

### Semgrep Network Connectivity Issues

**Problem**: Workflow fails with `NameResolutionError` or `ConnectionError` when trying to reach `semgrep.dev`

**Cause**: The self-hosted runner cannot reach semgrep.dev to download the OWASP Top Ten ruleset. This may occur in:
- Air-gapped networks without internet access
- Restricted network environments with firewall rules
- DNS resolution failures
- Temporary network outages

**Solution**: The script automatically handles this gracefully:
1. Attempts to download remote OWASP Top Ten ruleset
2. If network is unavailable, falls back to local config only
3. Workflow completes successfully with reduced rule coverage

**Verify it's working**: Check GitHub Actions output for:
```
Attempting Semgrep scan with OWASP Top Ten rules...
WARNING: Cannot reach semgrep.dev (network unreachable). Falling back to local configuration only.
```

This is expected in restricted network environments and is not a failure.

**To restore full coverage**:
Option 1: Enable outbound HTTPS access to `semgrep.dev:443` in your firewall rules
Option 2: Pre-download OWASP rules and commit them to `configs/semgrep/` as local config

### Container Registry Access

**Problem**: Docker container pull fails for semgrep or zaproxy images

**Solution**: Ensure outbound access to container registries:
- `docker.io` (Docker Hub) - For Semgrep container
- `ghcr.io` (GitHub Container Registry) - For ZAP container

Alternatively, pre-pull and cache container images on your runners.

### HTML Report Generation

**Problem**: HTML reports not generated in artifacts

**Cause**: Python 3 or required packages not installed

**Solution**:
1. Verify Python 3 is installed on the runner: `python3 --version`
2. Ensure runner has write access to output directory
3. Check workflow logs for Python error messages

### GitHub Token Permissions

**Problem**: Workflow fails when cloning private repositories

**Solution**:
1. Create `SECURITY_REPO_TOKEN` organization secret
2. Grant it read-only `Contents` access to target repositories
3. Ensure dispatcher has permission to send `repository_dispatch` events

See "Configure authentication" section above for details.


