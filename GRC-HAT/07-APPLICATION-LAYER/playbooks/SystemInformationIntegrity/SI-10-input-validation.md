# SI-10: Information Input Validation
**Family:** System and Information Integrity  
**NIST 800-53 Rev 5**  
**Layer:** Application (L7)

## Control Statement
The information system checks the validity of information inputs to the system, rejecting or quarantining inputs that do not match defined validity requirements such as character set, length, numerical range, and acceptable values.

## Why It Matters at L7
Injection attacks — SQL injection, cross-site scripting, command injection, path traversal — are consistently in the OWASP Top 10 and are the most common initial access vector for web applications. Every one of them exploits a single root cause: the application trusts user-controlled input without validation or encoding. SI-10 is the control that requires this to be designed out of the application, not just detected by a WAF.

---

## GRC Analyst Perspective
> **No code access.** Tools: interviews, documentation review, SIEM dashboards, audit reports, evidence packages.

### Audit Questions
- Does the organization have a documented secure coding standard that explicitly requires parameterized queries/prepared statements for all database interactions, and prohibits string concatenation in SQL construction?
- Are SAST tools (Semgrep, Checkmarx, CodeQL) integrated into the CI/CD pipeline and configured to flag injection vulnerabilities, with results reviewed before code is merged to main?
- Has the organization conducted application penetration testing in the past 12 months that included injection testing (SQLi, XSS, command injection, path traversal)?
- Are Content Security Policy (CSP) headers configured on all web-facing applications to mitigate XSS, and are they reviewed against the OWASP CSP cheat sheet?
- Is input validation performed server-side, not only client-side? Are validation rules documented in the application's design documentation?
- Are developers required to complete OWASP Top 10 security training, and is completion recorded?
- Are WAF rule groups covering injection attacks deployed in prevention mode, and are false positive rates monitored to keep rule tuning current?

### Evidence to Request
| Evidence Item | Source | Acceptable Format |
|---|---|---|
| SAST scan results showing injection findings (last 90 days) | CI/CD pipeline, Semgrep, Checkmarx | PDF, SARIF, HTML report |
| Penetration test report with injection test results | Third-party pentester, internal red team | PDF (executive summary acceptable) |
| Secure coding standard referencing parameterized queries and input validation requirements | Policy repository | PDF, Confluence page |
| CSP header configuration for production web applications | HTTP response headers, application config | Screenshot, curl output |
| WAF rule group configuration and mode (detection vs. prevention) | AWS WAF console, Cloudflare | PDF, console screenshot |
| Developer security training completion records | LMS, training platform | CSV, PDF certificate list |

### Gap Documentation Template
**Control:** SI-10  
**Finding:** SAST scanning is not integrated in the CI/CD pipeline; a recent penetration test identified 3 SQL injection vulnerabilities in the customer portal, none of which had been caught in development.  
**Risk:** SQL injection can result in complete database exfiltration, authentication bypass, and in some configurations remote code execution on the database server. Vulnerabilities not caught in development reach production.  
**Recommendation:** Integrate Semgrep with SQL injection rules into the CI/CD pipeline as a blocking gate for PRs targeting main. Remediate the identified SQLi vulnerabilities using parameterized queries within 72 hours (High severity SLA). Require OWASP Top 10 training completion for all development staff.  
**Owner:** Application Security Lead / Development Team Lead  

### CISO Communication
> Our web application penetration test identified SQL injection vulnerabilities in our customer portal — a finding class that is preventable through basic secure coding practices that were not consistently applied. This category of vulnerability can expose our entire customer database and in some configurations allow attackers to execute commands on backend systems. We are addressing this with three actions: immediate remediation of the identified vulnerabilities, integration of automated code scanning into our development pipeline to catch these issues before they ship, and mandatory developer training on injection prevention. These are low-cost, high-impact controls that directly reduce our most significant web application risk.

---

## Cybersecurity Engineer Perspective
> **Code access available.** Tools: kubectl, cloud CLI, SIEM, scanning tools, direct remediation.

### Assessment Commands
```bash
# --- SAST: Semgrep injection rules ---
# Install semgrep
pip install semgrep 2>/dev/null || pip3 install semgrep 2>/dev/null

# Run injection-focused ruleset against codebase
semgrep --config p/sql-injection \
  --config p/xss \
  --config p/command-injection \
  --config p/path-traversal \
  --json \
  --output /tmp/jsa-evidence/SI-10/semgrep-injection-$(date +%Y%m%d).json \
  . 2>/dev/null

# Human-readable summary
semgrep --config p/sql-injection \
  --config p/xss \
  --config p/command-injection \
  . 2>/dev/null | tail -20

# Check for string concatenation in SQL (common SQLi pattern)
grep -rn --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  -E '(SELECT|INSERT|UPDATE|DELETE|WHERE).*(["'"'"']\s*\+|f".*{|%s|format\()' \
  . 2>/dev/null | grep -v "test\|spec\|mock" | head -20

# Check for eval() on user input (command injection)
grep -rn --include="*.py" \
  -E 'eval\(|exec\(|subprocess.*shell=True' \
  . 2>/dev/null | grep -v "test\|spec" | head -10

# Check for shell=True in Python subprocess
grep -rn --include="*.py" \
  'shell=True' \
  . 2>/dev/null | head -10

# Check CSP headers on a target URL
curl -sI https://localhost 2>/dev/null | grep -i "content-security-policy" || \
  echo "[MISSING] No Content-Security-Policy header"

curl -sI https://localhost 2>/dev/null | grep -i "x-content-type-options" || \
  echo "[MISSING] No X-Content-Type-Options header"

# Check WAF mode
aws wafv2 list-web-acls --scope REGIONAL --output json 2>/dev/null | \
  python3 -c "
import sys, json
data = json.load(sys.stdin)
for acl in data.get('WebACLs', []):
    print(f\"WAF: {acl['Name']}  ARN: {acl['ARN']}\")
" || echo "AWS WAF not accessible"
```

### Detection / Testing
```bash
# ZAP active scan for injection vulnerabilities
# Requires OWASP ZAP running (authorized test environment only)
# Docker-based ZAP scan:
docker run --rm \
  -v /tmp/zap-reports:/zap/wrk:rw \
  ghcr.io/zaproxy/zaproxy:stable \
  zap-full-scan.py \
    -t http://target-app:8080 \
    -r /zap/wrk/zap-full-scan-$(date +%Y%m%d).html \
    -x /zap/wrk/zap-full-scan-$(date +%Y%m%d).xml \
    -I 2>/dev/null
# Copy reports to evidence dir
mkdir -p /tmp/jsa-evidence/SI-10/$(date +%Y%m%d)
cp /tmp/zap-reports/zap-full-scan-*.{html,xml} "/tmp/jsa-evidence/SI-10/$(date +%Y%m%d)/" 2>/dev/null

# SQLMap detection test (READ-ONLY, authorized environments only)
# sqlmap --url="http://target-app/api/users?id=1" --level=1 --risk=1 --batch --technique=B
# Do NOT use --dump, --dbs, or write techniques without explicit authorization

# Test path traversal manually
curl -s "http://localhost:8080/api/files?path=../../etc/passwd" -o /tmp/traversal-test.txt
grep -q "root:" /tmp/traversal-test.txt && \
  echo "[FAIL] Path traversal — /etc/passwd accessible!" || \
  echo "[PASS] Path traversal blocked"
rm -f /tmp/traversal-test.txt

# Test XSS reflection (safe payload — does not execute)
RESPONSE=$(curl -s "http://localhost:8080/search?q=<script>alert(1)</script>" 2>/dev/null)
echo "$RESPONSE" | grep -q "<script>alert(1)</script>" && \
  echo "[FAIL] Reflected XSS — input not encoded in response" || \
  echo "[PASS] XSS input encoded or filtered"

# Check if Semgrep found any HIGH findings in CI artifacts
find . -name "semgrep-*.json" -newer /tmp 2>/dev/null | xargs -I{} python3 -c "
import sys, json
with open('{}') as f:
    data = json.load(f)
results = data.get('results', [])
high = [r for r in results if r.get('extra', {}).get('severity') in ('ERROR', 'WARNING')]
print(f'Semgrep: {len(high)} high/error findings in {}')
" 2>/dev/null | head -10
```

### Remediation
```bash
# --- Fix: Parameterized queries (Python example) ---
# BAD (vulnerable):
# query = "SELECT * FROM users WHERE id = " + user_id
# cursor.execute(query)

# GOOD (parameterized):
# cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

# --- Fix: subprocess without shell=True (Python) ---
# BAD:
# subprocess.run(f"ping {host}", shell=True)
# GOOD:
# subprocess.run(["ping", host], shell=False)

# --- Add CSP headers in Nginx ---
# Add to server {} block in nginx.conf:
cat >> /etc/nginx/conf.d/security-headers.conf << 'EOF'
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none';" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
EOF
nginx -t && nginx -s reload

# --- Add Semgrep to CI/CD pipeline (GitHub Actions) ---
cat > /tmp/semgrep-ci.yml << 'EOF'
name: SAST - Injection Rules
on: [push, pull_request]
jobs:
  semgrep:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: returntocorp/semgrep-action@v1
        with:
          config: >-
            p/sql-injection
            p/xss
            p/command-injection
            p/path-traversal
          generateSarif: "1"
      - uses: github/codeql-action/upload-sarif@v2
        if: always()
        with:
          sarif_file: semgrep.sarif
EOF

# --- Input validation: path traversal prevention (Python example) ---
# import os
# def safe_path(base_dir, user_input):
#     requested = os.path.realpath(os.path.join(base_dir, user_input))
#     if not requested.startswith(os.path.realpath(base_dir)):
#         raise ValueError("Path traversal attempt detected")
#     return requested

# --- WAF: ensure AWSManagedRulesCommonRuleSet is in BLOCK mode ---
# This requires updating the WAF ACL via IaC (Terraform or CloudFormation)
# Key rule groups for injection:
# - AWSManagedRulesCommonRuleSet (XSS, SQLI, path traversal)
# - AWSManagedRulesSQLiRuleSet
# Both should have OverrideAction: None (use rule group default = Block)
```

### Validation
```bash
# Verify Semgrep finds no CRITICAL injection issues in main branch
semgrep --config p/sql-injection \
  --config p/command-injection \
  --error \
  . 2>/dev/null && \
  echo "[PASS] No critical injection findings" || \
  echo "[FAIL] Injection findings detected — review required"
# Expected: exit code 0

# Verify CSP header is present
CSP=$(curl -sI http://localhost:8080 2>/dev/null | grep -i "content-security-policy")
[[ -n "$CSP" ]] && \
  echo "[PASS] CSP header present: $CSP" || \
  echo "[FAIL] CSP header missing"
# Expected: PASS with non-empty policy

# Verify X-Content-Type-Options header
XCTO=$(curl -sI http://localhost:8080 2>/dev/null | grep -i "x-content-type-options")
[[ -n "$XCTO" ]] && echo "[PASS] $XCTO" || echo "[FAIL] X-Content-Type-Options missing"

# Verify path traversal is blocked
curl -s "http://localhost:8080/api/files?path=../../etc/passwd" -o /tmp/si10-val.txt
grep -q "root:" /tmp/si10-val.txt && \
  echo "[FAIL] Path traversal not blocked" || \
  echo "[PASS] Path traversal blocked"
rm -f /tmp/si10-val.txt
# Expected: PASS

# Verify ZAP scan completed and report exists
ls -lh /tmp/jsa-evidence/SI-10/$(date +%Y%m%d)/zap-*.html 2>/dev/null && \
  echo "[PASS] ZAP scan report present" || \
  echo "[INFO] ZAP scan not yet run — run against test environment"
```

### Evidence Capture
```bash
EVIDENCE_DIR="/tmp/jsa-evidence/SI-10/$(date +%Y%m%d)"
mkdir -p "$EVIDENCE_DIR"

# Semgrep results
semgrep --config p/sql-injection \
  --config p/xss \
  --config p/command-injection \
  --config p/path-traversal \
  --json \
  --output "$EVIDENCE_DIR/semgrep-injection-scan.json" \
  . 2>/dev/null || echo "Semgrep scan failed" > "$EVIDENCE_DIR/semgrep-error.txt"

# Security headers check for each application host
for HOST in localhost:8080; do
  curl -sI "http://$HOST" > "$EVIDENCE_DIR/headers-${HOST//[:/]/-}.txt" 2>/dev/null || true
done

# WAF ACL inventory
aws wafv2 list-web-acls --scope REGIONAL --output json \
  > "$EVIDENCE_DIR/waf-acls.json" 2>/dev/null || \
  echo "WAF not accessible" > "$EVIDENCE_DIR/waf-acls.txt"

# Raw grep for SQLi patterns in source
grep -rn --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  -E '(SELECT|INSERT|UPDATE|DELETE|WHERE).*(["'"'"']\s*\+|f".*{|%s)' \
  . 2>/dev/null > "$EVIDENCE_DIR/potential-sqli-patterns.txt" || true

# ZAP report (if exists)
find /tmp/zap-reports -name "*.html" -newer /tmp 2>/dev/null | \
  xargs -I{} cp {} "$EVIDENCE_DIR/" 2>/dev/null || true

# Summary
SEMGREP_FINDINGS=$(python3 -c "
import json
try:
    with open('$EVIDENCE_DIR/semgrep-injection-scan.json') as f:
        data = json.load(f)
    print(len(data.get('results', [])))
except:
    print('unknown')
" 2>/dev/null)

cat > "$EVIDENCE_DIR/SI-10-summary.txt" << EOF
SI-10 Input Validation Evidence
Date: $(date)
Auditor: $(whoami)
Host: $(hostname)

Semgrep injection findings: $SEMGREP_FINDINGS
CSP header: $(curl -sI http://localhost:8080 2>/dev/null | grep -i "content-security-policy" | head -1 || echo "not checked")

Files captured:
$(ls -1 "$EVIDENCE_DIR")
EOF

echo "[DONE] Evidence written to $EVIDENCE_DIR"
```
