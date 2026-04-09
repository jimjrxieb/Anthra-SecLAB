# Layer 7 Application — Break/Fix Scenarios

## Purpose

Run each scenario's break -> detect -> fix -> validate cycle to demonstrate the control's value and produce evidence for governance reporting.

## How to Run a Scenario

Each scenario is in `scenarios/{CONTROL-ID}-{name}/` and contains 5 files:

| File | Purpose | Format |
|------|---------|--------|
| `break.sh` | Creates the vulnerability (SQLi app, disabled logging) | Bash script |
| `detect.sh` | Detects the vulnerability using security tools | Bash script |
| `fix.sh` | Remediates the finding | Bash script |
| `validate.sh` | Confirms the fix is effective | Bash script |
| `governance.md` | CISO brief with risk, cost, ROI | Governance report |

All scripts use `set -euo pipefail` and save evidence to `/tmp/` directories.

## Scenario Execution Order

### Scenario 1: SI-10 SQL Injection

A Flask application with string-concatenated SQL queries vulnerable to injection in search, authentication, and user lookup endpoints. Simulates the Heartland Payment Systems (2008) vulnerability pattern.

1. **Break** — Deploy vulnerable application
   ```bash
   ./scenarios/SI-10-sql-injection/break.sh 5000
   ```
   Creates a Flask app on port 5000 with three SQL injection points: /search (query param concatenation), /login (auth bypass), and /user/<id> (path param). Database contains SSNs and passwords accessible via UNION injection.

2. **Detect** — Scan for SQL injection
   ```bash
   ./scenarios/SI-10-sql-injection/detect.sh http://localhost:5000 /tmp/si10-sqli-evidence-*/vuln-app
   ```
   Runs SQLMap against all endpoints, Semgrep SAST against source code, OWASP ZAP active scan, Nikto web server scan, and manual curl verification of injection payloads. Produces evidence in `/tmp/si10-sqli-detect-*`.

3. **Fix** — Patch to parameterized queries
   ```bash
   ./scenarios/SI-10-sql-injection/fix.sh /tmp/si10-sqli-evidence-*/vuln-app 5000
   ```
   Replaces all string concatenation with parameterized queries. Adds input validation (allowlist regex, length limits). Removes SQL and error details from responses. Excludes sensitive fields (SSN, password) from API output. Creates Semgrep CI rule to prevent regression.

4. **Validate** — Confirm injection is blocked
   ```bash
   ./scenarios/SI-10-sql-injection/validate.sh http://localhost:5000 /tmp/si10-sqli-evidence-*/vuln-app
   ```
   Tests 5 classic SQLi payloads against /search, 3 auth bypass payloads against /login, 5 path injection payloads against /user. Verifies UNION exfiltration fails, SQL not in responses, errors are generic, SSN excluded, SQLMap finds nothing, Semgrep finds nothing, parameterized queries in code.

5. **Governance** — Review the CISO brief
   Read `scenarios/SI-10-sql-injection/governance.md` for the business case: Heartland ($140M), TalkTalk (GBP 60M), $1.46M ALE, $4.8K fix cost, 289x ROSI.

### Scenario 2: AU-2 Missing Audit Logging

A Flask application with logging set to CRITICAL — authentication, data access, and authorization events are invisible. Simulates the blind spot that allowed SolarWinds to go undetected for 14 months.

1. **Break** — Disable audit logging
   ```bash
   ./scenarios/AU-2-missing-logging/break.sh 5001
   ```
   Creates a Flask app on port 5001 with log level CRITICAL. Generates security events (successful login, 5 failed logins, sensitive data access, privilege escalation attempt) — none are recorded.

2. **Detect** — Check for log gaps
   ```bash
   ./scenarios/AU-2-missing-logging/detect.sh http://localhost:5001 /tmp/au2-logging-evidence-*/
   ```
   Generates test events and checks log files for evidence. Reviews log configuration for disabled/CRITICAL level. Checks for structured JSON logging. Queries Splunk/Sentinel for missing events. Verifies SIEM integration and log shipping agents. Produces evidence in `/tmp/au2-logging-detect-*`.

3. **Fix** — Enable structured JSON logging
   ```bash
   ./scenarios/AU-2-missing-logging/fix.sh /tmp/au2-logging-evidence-*/unlogged-app 5001
   ```
   Patches application with JSONFormatter for structured logging. Adds audit events for authentication (success/failure), data access (with classification), authorization failures, and all HTTP requests. Creates Splunk inputs.conf/props.conf, Filebeat config, and KQL/SPL detection queries for brute force, credential stuffing, data exfiltration, and privilege escalation.

4. **Validate** — Confirm events are logged
   ```bash
   ./scenarios/AU-2-missing-logging/validate.sh http://localhost:5001 /tmp/au2-logging-evidence-*/unlogged-app/logs
   ```
   Generates fresh events and verifies: audit log exists, successful/failed logins logged, data access logged with classification, authorization failures logged, all entries are valid JSON, required fields present (timestamp, event_type, status, source_ip, correlation_id), HTTP requests logged, brute force detection queries match.

5. **Governance** — Review the CISO brief
   Read `scenarios/AU-2-missing-logging/governance.md` for the business case: SolarWinds (14 months undetected), IBM $3.93M detection delta, $1.95M ALE, $7.2K fix cost, 229x ROSI.

## Evidence Collection

After each scenario, save evidence to `evidence/YYYY-MM-DD/`:
- SQLMap output files (injection confirmation, data dump)
- Semgrep scan results (before and after fix)
- ZAP/Nikto scan reports
- Before/after application source code
- Fix diff (patch file)
- Audit log samples (JSON entries showing events are captured)
- SIEM query results (Splunk/Sentinel screenshots)
- Validation test results (pass/fail counts)
- Governance brief (completed with environment-specific data)

## Scenario Dependencies

| Scenario | Requires | Ports | Install |
|----------|----------|-------|---------|
| SI-10 SQL Injection | Python 3.8+, pip, curl | 5000 | `pip install flask sqlmap semgrep` |
| AU-2 Missing Logging | Python 3.8+, pip, curl | 5001 | `pip install flask` |

Optional tools for deeper testing:
```bash
# SQLMap
apt-get install sqlmap
# or: pip install sqlmap

# Semgrep
pip install semgrep

# OWASP ZAP
apt-get install zaproxy
# or: snap install zaproxy --classic

# Nikto
apt-get install nikto

# Splunk Universal Forwarder
# Download from: https://www.splunk.com/en_us/download/universal-forwarder.html

# Filebeat (for Sentinel/ELK)
apt-get install filebeat
```
