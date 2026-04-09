# Layer 7 Application — Implement Controls

## Purpose

Implement application security controls based on assessment findings. Start with highest-risk gaps from the 01-assess output. Input validation and audit logging are the two pillars — both must be addressed to close SI-10 and AU-2.

## Implementation Order

Priority by risk and cost-efficiency:

### Priority 1: Input Validation and SQL Injection Remediation (Week 1, ~$3,600)

1. **Replace all string-concatenated SQL with parameterized queries**
   - Python: `cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))`
   - Node.js: `db.query("SELECT * FROM users WHERE id = $1", [userId])`
   - Java: `PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?")`
   - Never use f-strings, string concatenation, or % formatting in SQL
   - Search the entire codebase: `grep -rn "execute.*+" src/` and `grep -rn 'execute(f"' src/`

2. **Add input validation on all endpoints**
   - Define allowlist patterns for each input type (regex)
   - Enforce length limits (maximum length for every field)
   - Type validation (integer fields must be integers, dates must be dates)
   - Reject requests that fail validation with 400 status — do not process them

3. **Sanitize error messages**
   - Replace all `except Exception as e: return str(e)` with generic error messages
   - Never expose SQL queries, stack traces, or database structure in responses
   - Log the full error server-side for debugging; return only "An error occurred" to the client

4. **Remove sensitive data from API responses**
   - Audit every endpoint: what fields are returned?
   - Exclude passwords, SSNs, tokens, and internal IDs from all responses
   - Use explicit field selection, not `SELECT *` or `dict(row)`

5. **Deploy SAST in CI/CD pipeline**
   - Install Semgrep: `pip install semgrep`
   - Add to CI: `semgrep --config p/owasp-top-ten --config p/sql-injection --error .`
   - Create custom rules for organization-specific patterns (see fix.sh Semgrep rule)
   - Block merge on ERROR-severity findings

### Priority 2: Audit Logging (Week 1-2, ~$4,800)

1. **Implement structured JSON logging for all security events**
   - Authentication: success, failure, logout, password change
   - Data access: endpoint, record count, classification level, user identity
   - Authorization: success, failure, attempted action, required role vs actual role
   - Administrative: user management, config changes, role assignments

2. **Required fields in every log entry**
   - `timestamp` (ISO 8601 UTC)
   - `event_type` (authentication, data_access, authorization, admin_action)
   - `status` (success, failed)
   - `source_ip` (client IP address)
   - `user_agent` (for device identification)
   - `correlation_id` (UUID linking all events in a single request)
   - `username` (when applicable)

3. **Configure log shipping to SIEM**
   - Splunk: Deploy Universal Forwarder with inputs.conf for audit.jsonl
   - Sentinel: Deploy Filebeat or Azure Monitor Agent with JSON parsing
   - Verify events appear in SIEM within 5 minutes of generation

4. **Create detection and alerting rules**
   - Brute force: 5+ failed logins from same IP in 10 minutes
   - Credential stuffing: successful login following 3+ failures
   - Data exfiltration: 100+ records accessed in single session
   - Privilege escalation: 3+ authorization failures from same source
   - After-hours access: logins outside business hours

5. **Configure log rotation and retention**
   - Rotate daily, compress after 7 days
   - Retain 30 days locally, 90 days in SIEM, 365 days in cold storage
   - For compliance: HIPAA requires 6 years, PCI-DSS requires 1 year

### Priority 3: DAST Scanning (Week 2-3, ~$2,400)

1. **Deploy OWASP ZAP against staging environment**
   - Spider the application to discover endpoints
   - Run active scan for injection, XSS, CSRF, and other OWASP Top 10 vulnerabilities
   - Schedule weekly scans: `zap-cli quick-scan --self-contained -t <staging-url>`

2. **Deploy SQLMap for targeted SQL injection testing**
   - Run against all endpoints that accept user input
   - Use `--level=3 --risk=2` for thorough testing
   - Integrate into CI for pre-release testing of new endpoints

3. **Deploy Nikto for web server scanning**
   - Check for server misconfigurations, default files, and known vulnerabilities
   - Run monthly: `nikto -h <url> -output nikto-report.txt`

4. **Integrate scan results into vulnerability tracking**
   - All findings go to DefectDojo/Jira/ServiceNow
   - Assign SLA based on severity: Critical (7 days), High (30 days), Medium (90 days)

### Priority 4: SIEM Integration and Alert Tuning (Week 3-4, ~$1,800)

1. **Validate Splunk/Sentinel ingestion**
   - Confirm all log sources are being received
   - Verify JSON parsing is correct (fields extracted properly)
   - Check for data loss (compare application log count to SIEM event count)

2. **Tune detection rules**
   - Baseline normal behavior for 2 weeks
   - Adjust thresholds to minimize false positives while catching real attacks
   - Create runbooks for each alert: what to investigate, escalation criteria

3. **Build dashboards**
   - Authentication overview: logins per hour, failed login trends, top source IPs
   - Data access: access volume trends, classification level breakdown
   - Security posture: open findings, remediation rate, SAST/DAST coverage

### Priority 5: Ongoing Operations (Monthly, ~$600/month)

1. **Weekly SAST scan** of all application code
2. **Weekly DAST scan** of staging environment
3. **Monthly penetration test** of critical endpoints
4. **Quarterly SIEM rule review** and threshold tuning
5. **Annual application security assessment** (full 01-assess checklist)

## Cost Summary

| Phase | Time | One-Time Cost | Annual Cost |
|-------|------|-------------|-------------|
| Input Validation + SAST | Week 1 | $3,600 | $1,200 |
| Audit Logging + SIEM | Week 1-2 | $4,800 | $2,400 |
| DAST Scanning | Week 2-3 | $2,400 | $1,200 |
| SIEM Tuning + Dashboards | Week 3-4 | $1,800 | $600 |
| Ongoing Operations | Monthly | $0 | $7,200 |
| **Total** | **4 weeks** | **$12,600** | **$12,600** |

## Verification After Each Implementation

After each control is implemented, run the corresponding scenario's `validate.sh` to confirm it works. Do not proceed to the next priority without validation.
