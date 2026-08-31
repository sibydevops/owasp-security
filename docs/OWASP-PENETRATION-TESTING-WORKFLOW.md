# OWASP Penetration Testing Workflow

This workflow defines the complete security assessment lifecycle for an authorized, non-production application. It combines automated checks in the central GitHub workflow with manual testing based on the OWASP Web Security Testing Guide (WSTG), Application Security Verification Standard (ASVS), API Security Top 10, and, where applicable, Mobile Application Security Verification Standard (MASVS) and Cloud-Native Application Security Top 10.

Automated results are evidence and triage input, not a substitute for manual penetration testing. Testing must be authorized in writing and performed only against assets listed in the approved scope.

## 1. Intake and authorization

Create one assessment record before testing starts.

Required fields:

- Assessment ID, requesting owner, business owner, technical lead, and tester
- Application name, repository, commit or release, environment, and deployment URL
- In-scope domains, APIs, IP ranges, mobile packages, cloud accounts, and third-party integrations
- Explicit out-of-scope assets and prohibited actions
- Test window, timezone, maintenance contacts, emergency stop contact, and escalation path
- Approved test intensity: passive, baseline, authenticated, full active, or API
- Test accounts for each role, MFA requirements, seeded data, and cleanup method
- Data-handling, retention, legal, privacy, and third-party authorization requirements
- Rollback and incident-response procedures
- Risk acceptance authority and finding due dates

The owner signs the rules of engagement (RoE). The tester verifies authorization, target ownership, scope, credentials, and a safe test environment before sending active requests. No production testing, denial-of-service testing, destructive actions, social engineering, persistence, or data exfiltration is permitted unless separately approved in the RoE.

## 2. Prepare the test

1. Create a ticket or assessment record and attach the signed RoE.
2. Confirm the exact source SHA and deployed artifact are known.
3. Validate DNS, TLS, authentication, role accounts, rate limits, logging, and monitoring contacts.
4. Record a baseline of application health, test data, and known issues.
5. Run the central workflow with the appropriate profile:

```bash
./scripts/dispatch-scan.sh ORG/security-workflows ORG/app SHA web https://app-test.example.internal baseline
```

Use `api` with `openapi_url` for an API and `none` when no HTTP target exists. Run `full` only on disposable or explicitly approved test environments.

6. Preserve the SAST, DAST, repository, SHA, configuration, and tool-version artifacts in the assessment record.
7. Establish a finding identifier format, for example `APP-2026-001`.

## 3. Reconnaissance and attack-surface mapping

Perform passive discovery first, then approved active discovery. Build an inventory and mark each item in scope.

- Domains, subdomains, certificates, redirects, ports, services, and technology fingerprints
- Application routes, parameters, forms, uploads, WebSockets, GraphQL, webhooks, and error paths
- API specifications, versions, undocumented endpoints, methods, schemas, and rate-limit behavior
- Authentication, registration, password recovery, MFA, session, token, logout, and account-linking flows
- User roles, tenant boundaries, administrative functions, background jobs, and integrations
- Sensitive data locations, security headers, CORS, caching, secrets exposure, and logging behavior
- Mobile deep links, local storage, exported components, and backend endpoints when mobile is in scope
- Cloud entry points, IAM roles, storage, queues, functions, metadata access, and trust boundaries when cloud-native is in scope

Produce an attack-surface diagram, role matrix, endpoint inventory, and prioritized test plan. Remove discovered assets that are not authorized rather than testing them.

## 4. Threat model and test plan

For each trust boundary, identify assets, actors, entry points, abuse cases, and likely impact. Prioritize authentication, authorization, tenant isolation, sensitive data, administrative functions, and business-critical transactions.

Map planned tests to:

- WSTG categories and test IDs for web behavior
- ASVS version and verification requirements for control expectations
- API Security Top 10 risks for API abuse cases
- MASVS controls for mobile clients
- Cloud-Native Application Security risks for cloud workloads
- CWE and the repository's severity policy for reporting consistency

The test plan records the test ID, preconditions, role, request or action, expected secure behavior, evidence to collect, and cleanup action. A test is `Pass`, `Fail`, `Blocked`, `Not applicable`, or `Not tested` with a reason.

## 5. Execute automated testing

The central workflow performs:

- Exact SHA checkout and repository classification
- Semgrep SAST with local and OWASP-oriented rules
- OWASP ZAP baseline, full, or API scanning against an approved HTTP target
- OWASP WSTG and ASVS mapping for normalized findings
- Configurable SAST and DAST security gates
- JSON, SARIF, YAML, Markdown, and tool reports as artifacts

Review scanner errors separately from findings. A successful job with an empty report is not proof of coverage. Record unreachable targets, missing authentication, rule exclusions, rate limits, and false-positive decisions. Do not silently treat a failed scanner as a clean result.

## 6. Execute manual tests

Use the WSTG test catalog and the attack-surface inventory. At minimum, assess the following where applicable:

### Configuration and deployment

- Information disclosure, default files and credentials, directory listing, backup files, debug modes
- TLS, security headers, cookie attributes, CORS, caching, HTTP methods, host handling, and error handling
- Dependency and component versions, exposed management interfaces, and unsafe cloud configuration

### Identity and authentication

- Registration, enumeration, password policy, reset and recovery, MFA, session fixation, logout, timeout
- Credential handling, token validation, token audience and issuer, refresh and revocation, device binding
- Brute-force protections and account lockout within approved rate and safety limits

### Authorization and access control

- Horizontal and vertical privilege escalation
- Object-level and function-level authorization on every relevant endpoint
- Tenant isolation, administrative actions, indirect object references, and workflow step skipping
- Access after logout, role change, account disablement, and token expiration

### Input handling and injection

- Server-side validation, output encoding, parser differentials, template and command injection
- SQL/NoSQL/LDAP injection, path traversal, file inclusion, SSRF, request smuggling, and XXE where relevant
- File upload type, size, storage, execution, download authorization, and content handling

### Client-side and browser behavior

- XSS, DOM sinks, CSRF, clickjacking, postMessage, WebSocket authorization, CORS, and browser storage
- Open redirects, client-side secrets, sensitive data in URLs, and cache history behavior

### Business logic and data protection

- Rate, quantity, price, state-transition, replay, race-condition, and approval bypasses
- Abuse of invitations, refunds, exports, notifications, search, bulk actions, and integrations
- Encryption in transit and at rest, key handling, PII exposure, logging, and retention

### API and service-specific testing

- Object, property, and function authorization; mass assignment; excessive data exposure
- Resource consumption, pagination, filtering, versioning, inventory, webhooks, and unsafe third-party flows
- Schema validation, content types, GraphQL introspection and resolver authorization where applicable

### Mobile and cloud-native extensions

- Mobile reverse-engineering resistance, local data, platform permissions, deep links, exported components, and certificate validation
- Cloud IAM least privilege, metadata services, storage and queue access, secrets, service identity, network policy, and workload isolation

Stop and escalate when a test indicates instability, unauthorized data access, third-party impact, or a possible incident. Capture only the minimum proof needed to demonstrate impact.

## 7. Evidence and finding quality

Each finding contains:

- Finding ID, title, affected asset, endpoint or component, and first-seen commit
- WSTG test ID, ASVS or applicable standard control, CWE, and tool/manual source
- Preconditions, concise reproduction steps, expected versus observed behavior
- Minimal sanitized request/response, screenshot or log reference, and timestamps
- Impact in business terms, affected roles or tenants, and realistic attack prerequisites
- CVSS v4.0 vector when appropriate, severity, confidence, and scope
- Remediation guidance, owner, due date, and links to the assessment evidence

Sanitize tokens, passwords, personal data, secrets, and customer content before storing evidence. Keep raw evidence access-restricted and retain it only for the approved period.

Use this severity model unless the organization has a stricter policy:

| Severity | Meaning | Default target |
| --- | --- | --- |
| Critical | Broad compromise, remote code execution, or major sensitive-data impact with low complexity | 7 days |
| High | Material confidentiality, integrity, availability, or privilege impact | 30 days |
| Medium | Exploitable weakness with constrained impact or meaningful prerequisites | 60 days |
| Low | Limited impact, defense-in-depth, or difficult exploitation | 90 days |
| Informational | Observation or hardening recommendation without direct exploitable impact | Track |

Do not duplicate one root cause into many findings unless affected owners or impacts differ. Link scanner findings to manual validation and mark false positives with evidence and rationale.

## 8. Reporting and decision

Deliver a report containing:

- Executive summary, scope, dates, environment, limitations, and overall risk opinion
- Methodology and standards used, coverage matrix, and test-status summary
- Attack-surface inventory and role/tenant coverage
- Findings grouped by severity and root cause, with remediation owners and due dates
- Accepted risks, compensating controls, false positives, blocked tests, and residual risk
- Automated artifact links, evidence index, and an appendix of tested WSTG/ASVS items

Hold a readout with the owner and engineering team. The risk owner decides whether findings are remediated, accepted with an expiry date, transferred, or mitigated. Acceptance never removes the finding from the report.

## 9. Remediation and retest

1. The owner records the fix, affected version or commit, and regression tests.
2. Re-run the relevant SAST/DAST scan and repeat the original manual steps.
3. Test adjacent roles, tenants, endpoints, and alternate flows for regression.
4. Set the result to `Verified fixed`, `Partially fixed`, `Still open`, or `Unable to verify`.
5. Attach retest evidence and update residual risk.
6. Close only when the tester and risk owner agree that the acceptance criteria are met.

A retest must not overwrite the original evidence. Preserve discovery, remediation, and verification timestamps for auditability.

## 10. Release gate and operating cadence

- Pull request or release: exact-SHA SAST and approved ZAP baseline
- API release: authenticated API scan plus manual authorization and business-logic tests
- High-risk change: targeted manual assessment before release and full assessment before production
- High-risk application: independent manual penetration test at least annually and after material architecture or authentication changes
- Cloud or mobile: reassess after trust-boundary, identity, platform, or package changes
- Continuous monitoring: review scanner failures, new endpoints, dependency changes, incidents, and overdue findings

The release decision must account for open findings, scanner failures, blocked coverage, accepted risk expiry, and whether the deployed artifact matches the tested commit. A green automated gate alone does not certify OWASP or penetration-test compliance.

## Completion checklist

- [ ] Written authorization and RoE approved
- [ ] Scope, exclusions, target version, accounts, and test window confirmed
- [ ] Safety controls, contacts, monitoring, and rollback verified
- [ ] Reconnaissance, inventory, threat model, and test plan recorded
- [ ] Automated SAST/DAST completed and tool errors reviewed
- [ ] Applicable WSTG, ASVS, API, mobile, and cloud tests executed or justified
- [ ] Findings contain reproducible, sanitized evidence and owners
- [ ] Report delivered and risk decisions recorded
- [ ] Fixes retested, residual risk updated, and evidence retained
- [ ] Assessment formally closed with next review date
