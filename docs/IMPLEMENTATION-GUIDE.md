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

Install Docker, Git, Python 3, GitHub CLI, CA certificates, and internal DNS/CA trust. Allow outbound access to GitHub, the Semgrep rule registry if `p/owasp-top-ten` is used, the ZAP container registry, and approved test targets. Deny broad production network access.

## 4. Configure authentication

Create `SECURITY_REPO_TOKEN` as an organization secret visible only to the central repository. Prefer a GitHub App installation token broker in production. The token needs read-only Contents access to target repositories. A separate token or GitHub App identity used by the dispatcher needs permission to send repository dispatch events to the central repository.

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

## 9. Connect all repository changes

Configure the event producer to process push and pull-request events, extract the exact head SHA, enrich the event with catalog metadata, and send `repository_dispatch`. De-duplicate by `repository + SHA`. The central workflow concurrency key prevents duplicate runs for the same commit.

## 10. Branch enforcement

A status from a workflow running only in the central repository is not automatically a required check in the source repository. To block merges without adding a source-repository workflow, the event producer must use the GitHub Checks API against the source commit. That capability is outside pure GitHub Actions YAML and requires a GitHub App. If merge blocking is mandatory with Actions alone, use the reusable caller workflow in every source repository.

## 11. Application profiles

- Web: Semgrep plus ZAP baseline on each eligible change; full active scan only against disposable test targets.
- API: Semgrep plus ZAP API scan using OpenAPI.
- Cloud-native: scan the HTTP service after the existing deployment pipeline exposes an ephemeral URL.
- Desktop/native: Semgrep applies to supported languages. ZAP applies only to HTTP endpoints exposed by the application.
- Library/SDK/IaC: SAST only. DAST is not applicable without a running HTTP target.

## 12. OWASP governance

Use WSTG as the human and automated test catalog, ASVS as the application verification requirement baseline, and ZAP/Semgrep as partial automation. Automated ZAP does not cover business logic, role abuse, complex authorization, social engineering, or every WSTG test. Keep periodic manual penetration testing for high-risk applications.

## 13. Complete penetration-testing workflow

Use [OWASP-PENETRATION-TESTING-WORKFLOW.md](OWASP-PENETRATION-TESTING-WORKFLOW.md) for the operational assessment process. It covers written authorization and rules of engagement, scope and safety controls, reconnaissance, threat modeling, WSTG/ASVS/API/MASVS/cloud coverage, automated and manual execution, sanitized evidence, severity, reporting, risk decisions, remediation, retesting, and closure.

The central workflow is one part of that process. A successful GitHub Actions run does not replace manual authorization, business-logic and authorization testing, coverage review, or an independent assessment for high-risk appl

'tstsfaf
F


sdafaf