# Central OWASP Security Workflow for GitHub

A central GitHub Actions reference implementation for scanning a changed repository and exact commit with:

- Semgrep Community Edition SAST using open-source OWASP-oriented rules
- OWASP ZAP baseline, full, or API DAST
- Automatic repository classification for web, API, cloud-native, desktop, library, and unknown repositories
- **🎨 Interactive HTML reports** + JSON, YAML, Markdown, and SARIF artifacts
- Configurable security gate
- No Gitleaks, Trivy, paid scanner, or scheduled trigger

## Report Artifacts

Each scan generates comprehensive reports in multiple formats:

- **HTML** - Interactive, visual reports for stakeholders (open in browser)
- **YAML** - Structured format for documentation and version control
- **JSON** - Machine-readable format for tool integration
- **Markdown** - Quick summaries for GitHub comments

📚 **[Artifact Quick Start Guide](docs/ARTIFACTS-QUICKSTART.md)** - Start here!  
📖 **[Complete Artifact Documentation](docs/ARTIFACT-FORMATS.md)** - Detailed reference

## Important trigger limitation

A workflow in this central repository cannot automatically receive `push` or `pull_request` events from another repository. Choose one trigger pattern:

1. Organization GitHub App or organization webhook sends `repository_dispatch` to this central repository. This requires no workflow in each application repository.
2. A small caller workflow is placed in each application repository and calls the reusable workflow.
3. An existing organization CI platform calls `workflow_dispatch` through the GitHub API.

The central workflow is in `.github/workflows/central-security.yml`.

## DAST limitation

OWASP ZAP scans a running HTTP/HTTPS application, not source code. Supply `target_url` for web, API, cloud-native, Electron backend, or desktop applications exposing HTTP services. Repositories without a reachable target receive SAST and a documented `DAST_NOT_APPLICABLE` result.

## Quick start

1. Create a private repository such as `ORG/security-workflows`.
2. Copy this project into it.
3. Configure self-hosted runners labeled `self-hosted`, `linux`, `security` with Docker and network access to test targets.
4. Add repository or organization secret `SECURITY_REPO_TOKEN` with read-only access to target repositories.
5. Dispatch a test scan:

```bash
export GH_TOKEN='TOKEN_ALLOWED_TO_DISPATCH'
./scripts/dispatch-scan.sh ORG/security-workflows ORG/app-repo COMMIT_SHA web https://staging.example.internal baseline
```

See `docs/IMPLEMENTATION-GUIDE.md` for production rollout.

For the complete authorized assessment lifecycle, including manual OWASP testing,
evidence, reporting, remediation, and retesting, see
`docs/OWASP-PENETRATION-TESTING-WORKFLOW.md`.
