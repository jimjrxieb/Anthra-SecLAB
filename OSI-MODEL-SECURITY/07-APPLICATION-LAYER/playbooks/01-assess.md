# Layer 7 Application — Assess Current State

## Purpose

Document the current application security posture before implementing any controls. This assessment covers SAST/DAST coverage, input validation, audit logging, authentication controls, and API security. The baseline established here measures improvement after remediation.

## Assessment Checklist

### SI-10 Information Input Validation

- [ ] Inventory all application endpoints that accept user input (forms, query params, path params, headers, file uploads)
- [ ] For each endpoint: is input validated? What method? (allowlist, blocklist, type check, length limit)
- [ ] Are SQL queries parameterized? Or do any use string concatenation/formatting?
- [ ] Are there any raw SQL queries in the codebase? Search for: `execute(`, `.query(`, `cursor.execute(`
- [ ] Is there a Web Application Firewall (WAF) in front of the application?
- [ ] Has the application ever had a SAST scan? When was the last scan?
- [ ] Has the application ever had a DAST scan? When was the last scan?
- [ ] Has the application ever had a penetration test? When was the last test?
- [ ] Are there Semgrep or other SAST rules in the CI/CD pipeline?
- [ ] Are error messages sanitized? (No database structure, stack traces, or SQL in responses)
- [ ] Is there output encoding for XSS prevention? (HTML encoding, JavaScript encoding)
- [ ] Are file uploads validated? (Type checking, size limits, content scanning)
- [ ] Are API inputs validated against a schema? (OpenAPI/Swagger, JSON Schema)

### AU-2 Event Logging

- [ ] What events are currently logged? List each event type
- [ ] Are authentication events logged? (successful login, failed login, logout, password change)
- [ ] Are failed login attempts logged with source IP and username?
- [ ] Is there a brute force detection mechanism? (threshold-based alerting)
- [ ] Are data access events logged? (who accessed what, when, how many records)
- [ ] Are authorization failures logged? (access denied, privilege escalation attempts)
- [ ] Are administrative actions logged? (user creation, role changes, config changes)
- [ ] What log format is in use? (plaintext, JSON, syslog)
- [ ] Are logs structured (JSON) for SIEM ingestion?
- [ ] Where are logs stored? (local disk, centralized, SIEM)
- [ ] Is there a log shipping agent? (Splunk forwarder, Filebeat, Fluentd)
- [ ] What is the log retention period?
- [ ] Are there detection/alerting rules configured? (KQL, SPL queries)
- [ ] Are logs reviewed regularly? By whom? What frequency?
- [ ] Can individual user actions be traced via correlation ID or session ID?

### SA-11 Developer Security Testing

- [ ] Is SAST integrated in CI/CD? What tool? (Semgrep, SonarQube, CodeQL)
- [ ] Is DAST run against staging/pre-prod? What tool? (ZAP, Burp Suite, Nikto)
- [ ] Is dependency scanning enabled? (Trivy, Snyk, pip-audit, npm audit)
- [ ] Is secret detection enabled in CI? (Gitleaks, TruffleHog)
- [ ] Are there security unit tests? (Authentication tests, authorization tests, input validation tests)
- [ ] Is there a security code review process? (Manual review checklist, automated gates)
- [ ] What is the vulnerability SLA? (Critical: X days, High: X days, Medium: X days)

### RA-5 Vulnerability Scanning

- [ ] Is there a regular vulnerability scanning schedule? What frequency?
- [ ] What scanning tools are in use? (ZAP, Nikto, Nessus, Qualys)
- [ ] Are scan results reviewed and triaged?
- [ ] Is there a vulnerability tracking system? (Jira, ServiceNow, DefectDojo)
- [ ] What is the remediation rate? (% of findings fixed within SLA)

### AC-6 Least Privilege (Application Level)

- [ ] Does the application implement role-based access control (RBAC)?
- [ ] Are admin endpoints separated from user endpoints?
- [ ] Are API keys scoped to minimum required permissions?
- [ ] Are database connections using least-privilege accounts?
- [ ] Is there session management? (timeout, invalidation, concurrent session limits)

## Tools for Assessment

| Tool | Command | What It Checks |
|------|---------|----------------|
| Semgrep | `semgrep --config p/owasp-top-ten .` | SAST: OWASP Top 10 patterns in code |
| SQLMap | `sqlmap -u <url> --batch --level=3` | SQL injection in live endpoints |
| OWASP ZAP | `zap-cli quick-scan <url>` | DAST: comprehensive web app scan |
| Nikto | `nikto -h <url>` | Web server misconfiguration |
| Semgrep (SQLi) | `semgrep --config p/sql-injection .` | SQL injection patterns specifically |
| grep (manual) | `grep -rn "execute.*+" src/` | Manual check for string concat SQL |
| Splunk | `search index=main sourcetype=app_audit \| stats count by event_type` | Audit log coverage check |
| Sentinel KQL | `AppAuditLogs \| summarize count() by EventType` | Audit log coverage in Sentinel |

## Output

Complete the checklist above and produce:
1. Application endpoint inventory (endpoint, method, input type, validation status)
2. SAST/DAST coverage matrix (tool, last scan date, findings count, remediation status)
3. Audit logging coverage matrix (event type, logged yes/no, SIEM integrated yes/no, alert rule yes/no)
4. Gap analysis: which SI-10, AU-2, SA-11, RA-5, and AC-6 controls have findings?
5. Risk ranking of findings using 5x5 matrix
