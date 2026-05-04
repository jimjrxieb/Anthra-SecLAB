# 01-assess.md — L7 Application Layer Assessment

| Field | Value |
|---|---|
| **NIST Controls** | SI-10 (input validation), AU-2 (event logging), SA-11 (developer security testing), RA-5 (vulnerability scanning), AC-6 (least privilege) |
| **Tools** | Semgrep / SQLMap / ZAP / Splunk SPL / Sentinel KQL / Trivy / kube-bench |
| **Enterprise Equiv** | Checkmarx ($150K+) / Rapid7 InsightAppSec ($100K+) |
| **Time** | 2 hours |
| **Rank** | D (assessment only — no changes made) |

---

## Purpose

Document the current application security posture before implementing any controls. The baseline established here measures improvement after remediation. Do not fix anything during this phase — assess and record.

---

## Assessment Checklist

### SI-10 Information Input Validation

Priority: **P1** — Input validation is the root cause of SQLi, XSS, command injection

- [ ] Inventory all application endpoints that accept user input (forms, query params, path params, headers, file uploads)
- [ ] For each endpoint: is input validated? What method? (allowlist, blocklist, type check, length limit)
- [ ] Are SQL queries parameterized? Or do any use string concatenation/formatting?
- [ ] Search for raw SQL patterns: `execute(`, `.query(`, `cursor.execute(`, `db.exec(`
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

Priority: **P1** — If it's not logged, it didn't happen (from an audit standpoint)

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
- [ ] What is the log retention period? (Compare against compliance requirements)
- [ ] Are there detection/alerting rules configured? (KQL, SPL queries)
- [ ] Are logs reviewed regularly? By whom? What frequency?
- [ ] Can individual user actions be traced via correlation ID or session ID?

### SA-11 Developer Security Testing

Priority: **P2** — Gates that catch issues before production

- [ ] Is SAST integrated in CI/CD? What tool? (Semgrep, SonarQube, CodeQL)
- [ ] Is DAST run against staging/pre-prod? What tool? (ZAP, Burp Suite, Nikto)
- [ ] Is dependency scanning enabled? (Trivy, Snyk, pip-audit, npm audit)
- [ ] Is secret detection enabled in CI? (Gitleaks, TruffleHog)
- [ ] Are there security unit tests? (Authentication tests, authorization tests, input validation tests)
- [ ] Is there a security code review process? (Manual review checklist, automated gates)
- [ ] What is the vulnerability SLA? (Critical: X days, High: X days, Medium: X days)

### RA-5 Vulnerability Scanning

Priority: **P2** — Know your attack surface before attackers do

- [ ] Is there a regular vulnerability scanning schedule? What frequency?
- [ ] What scanning tools are in use? (ZAP, Nikto, Nessus, Qualys)
- [ ] Are scan results reviewed and triaged?
- [ ] Is there a vulnerability tracking system? (Jira, ServiceNow, DefectDojo)
- [ ] What is the remediation rate? (% of findings fixed within SLA)

### AC-6 Least Privilege (Application Level)

Priority: **P2** — Minimize blast radius when breach occurs

- [ ] Does the application implement role-based access control (RBAC)?
- [ ] Are admin endpoints separated from user endpoints?
- [ ] Are API keys scoped to minimum required permissions?
- [ ] Are database connections using least-privilege accounts?
- [ ] Is there session management? (timeout, invalidation, concurrent session limits)

---

## Assessment Commands

```bash
# SI-10: Find SQL injection patterns in code
semgrep --config p/sql-injection .
grep -rn "execute.*%" src/ --include="*.py"
grep -rn "query.*format" src/ --include="*.py"

# SA-11: SAST scan
semgrep --config p/owasp-top-ten .
semgrep --config p/security-audit . --json > /tmp/semgrep-results.json

# RA-5: Dependency vulnerabilities
trivy fs --security-checks vuln . --format json > /tmp/trivy-deps.json
pip-audit --format json > /tmp/pip-audit.json 2>/dev/null || true
npm audit --json > /tmp/npm-audit.json 2>/dev/null || true

# AU-2: Check what's currently being logged
# Splunk
# search index=main sourcetype=app_audit | stats count by event_type

# Sentinel KQL
# AppAuditLogs | summarize count() by EventType

# RA-5: Run kube-bench
docker run --rm --pid=host -v /etc:/etc:ro -v /var:/var:ro \
  aquasec/kube-bench:v0.7.1 --json > /tmp/kube-bench-baseline.json
```

---

## Assessment Tools Summary

| Tool | Command | What It Checks |
|---|---|---|
| Semgrep | `semgrep --config p/owasp-top-ten .` | SAST: OWASP Top 10 patterns in code |
| Trivy | `trivy fs --security-checks vuln .` | Dependency CVEs, config issues |
| SQLMap | `sqlmap -u <url> --batch --level=3` | SQL injection in live endpoints |
| OWASP ZAP | `zap-baseline.py -t <url>` | DAST: comprehensive web app scan |
| Nikto | `nikto -h <url>` | Web server misconfiguration |
| kube-bench | Docker command above | CIS Kubernetes benchmark |
| Kubescape | `kubescape scan framework NSA` | NSA K8s hardening compliance |
| audit-siem-ingest.sh | `./01-auditors/audit-siem-ingest.sh` | SIEM health and data flow |
| audit-alert-rules.sh | `./01-auditors/audit-alert-rules.sh` | Detection rule coverage |

---

## Output

Complete the checklist above and produce:
1. Application endpoint inventory (endpoint, method, input type, validation status)
2. SAST/DAST coverage matrix (tool, last scan date, findings count, remediation status)
3. Audit logging coverage matrix (event type, logged yes/no, SIEM integrated yes/no, alert rule yes/no)
4. Gap analysis: which SI-10, AU-2, SA-11, RA-5, and AC-6 controls have findings?
5. Risk ranking of findings using 5x5 matrix

Then proceed to specific audit playbooks based on gaps:
- SIEM gaps → `01a-sentinel-audit.md` or `01a-splunk-audit.md`
- Vuln scanning gaps → `01b-vuln-scan-audit.md`
- EDR gaps → `01c-edr-audit.md`
