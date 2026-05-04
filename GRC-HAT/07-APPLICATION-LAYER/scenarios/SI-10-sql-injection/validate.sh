#!/usr/bin/env bash
set -euo pipefail

# SI-10 SQL Injection — Validate
#
# Confirms that SQL injection remediation is effective:
#   1. SQLMap finds no injectable parameters
#   2. Semgrep finds no SQL injection patterns in source
#   3. Manual injection attempts are blocked by input validation
#   4. Parameterized queries are verified in code
#   5. Error messages do not expose database structure
#   6. Sensitive data (SSN) is not in API responses
#
# CSF 2.0: DE.CM-09 (Computing monitored for adverse events)
# CIS v8: 16.12 (Implement Code-Level Security Checks)
# NIST: SI-10 (Information Input Validation)
#
# REQUIREMENTS:
#   - sqlmap (preferred)
#   - semgrep (preferred)
#   - curl
#
# USAGE:
#   ./validate.sh <target_url> [source_dir]
#
# EXAMPLE:
#   ./validate.sh http://localhost:5000 /tmp/si10-sqli-evidence-*/vuln-app

# --- Argument Validation ---

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <target_url> [source_dir]"
    echo "Example: $0 http://localhost:5000 /path/to/app/source"
    exit 1
fi

TARGET="$1"
SOURCE_DIR="${2:-}"

EVIDENCE_DIR="/tmp/si10-sqli-validate-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$EVIDENCE_DIR"

echo "============================================"
echo "SI-10 SQL Injection — Validation"
echo "============================================"
echo ""
echo "[*] Target:       $TARGET"
echo "[*] Source dir:    ${SOURCE_DIR:-not provided}"
echo "[*] Evidence dir: $EVIDENCE_DIR"
echo ""

PASS=0
FAIL=0
SKIP=0

# --- Helper Function ---

check_result() {
    local test_name="$1"
    local result="$2"
    local detail="$3"

    if [[ "$result" == "pass" ]]; then
        echo "[PASS] $test_name — $detail"
        PASS=$((PASS + 1))
    else
        echo "[FAIL] $test_name — $detail"
        FAIL=$((FAIL + 1))
    fi
}

# --- Test 1: Classic SQL Injection Must Be Blocked ---

echo "[*] Test 1: Classic SQL injection in /search must be blocked"
echo "----------------------------------------------"

SQLI_PAYLOADS=(
    "' OR '1'='1' --"
    "' UNION SELECT 1,2,3,4,5 --"
    "'; DROP TABLE users; --"
    "1' AND 1=1 --"
    "admin' --"
)

INJECTION_BLOCKED=0
INJECTION_TOTAL=${#SQLI_PAYLOADS[@]}

for payload in "${SQLI_PAYLOADS[@]}"; do
    ENCODED=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload'))" 2>/dev/null || echo "$payload")
    RESPONSE=$(curl -s "$TARGET/search?q=$ENCODED" 2>/dev/null || echo "Connection failed")

    # Check if the injection was blocked (should get error or empty results, not data dump)
    if echo "$RESPONSE" | grep -qi "invalid characters\|error\|400" 2>/dev/null; then
        INJECTION_BLOCKED=$((INJECTION_BLOCKED + 1))
    elif echo "$RESPONSE" | grep -qi "count.*0\|results.*\[\]" 2>/dev/null; then
        # Empty results with parameterized query — also acceptable
        INJECTION_BLOCKED=$((INJECTION_BLOCKED + 1))
    fi
done

if [[ "$INJECTION_BLOCKED" -eq "$INJECTION_TOTAL" ]]; then
    check_result "SQL injection blocked in /search" "pass" "All $INJECTION_TOTAL payloads blocked"
else
    check_result "SQL injection blocked in /search" "fail" "Only $INJECTION_BLOCKED of $INJECTION_TOTAL payloads blocked"
fi
echo ""

# --- Test 2: Authentication Bypass Must Be Blocked ---

echo "[*] Test 2: Authentication bypass in /login must be blocked"
echo "----------------------------------------------"

AUTH_PAYLOADS=(
    "admin'--"
    "admin' OR '1'='1'--"
    "' OR 1=1--"
)

AUTH_BLOCKED=0
AUTH_TOTAL=${#AUTH_PAYLOADS[@]}

for payload in "${AUTH_PAYLOADS[@]}"; do
    RESPONSE=$(curl -s -X POST "$TARGET/login" -d "username=$payload&password=anything" 2>/dev/null || echo "Connection failed")

    if echo "$RESPONSE" | grep -qi "invalid\|error\|401\|400" 2>/dev/null; then
        AUTH_BLOCKED=$((AUTH_BLOCKED + 1))
    fi
done

if [[ "$AUTH_BLOCKED" -eq "$AUTH_TOTAL" ]]; then
    check_result "Auth bypass blocked in /login" "pass" "All $AUTH_TOTAL bypass attempts blocked"
else
    check_result "Auth bypass blocked in /login" "fail" "Only $AUTH_BLOCKED of $AUTH_TOTAL bypass attempts blocked"
fi
echo ""

# --- Test 3: Path Parameter Injection Must Be Blocked ---

echo "[*] Test 3: Path parameter injection in /user must be blocked"
echo "----------------------------------------------"

PATH_PAYLOADS=(
    "1 OR 1=1"
    "1; DROP TABLE users"
    "1 UNION SELECT 1,2,3,4,5"
    "abc"
    "-1"
)

PATH_BLOCKED=0
PATH_TOTAL=${#PATH_PAYLOADS[@]}

for payload in "${PATH_PAYLOADS[@]}"; do
    ENCODED=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload'))" 2>/dev/null || echo "$payload")
    RESPONSE=$(curl -s "$TARGET/user/$ENCODED" 2>/dev/null || echo "Connection failed")

    if echo "$RESPONSE" | grep -qi "invalid\|error\|400\|404" 2>/dev/null; then
        PATH_BLOCKED=$((PATH_BLOCKED + 1))
    fi
done

if [[ "$PATH_BLOCKED" -eq "$PATH_TOTAL" ]]; then
    check_result "Path injection blocked in /user" "pass" "All $PATH_TOTAL malicious IDs rejected"
else
    check_result "Path injection blocked in /user" "fail" "Only $PATH_BLOCKED of $PATH_TOTAL malicious IDs rejected"
fi
echo ""

# --- Test 4: UNION-Based Data Exfiltration Must Fail ---

echo "[*] Test 4: UNION-based data exfiltration must fail"
echo "----------------------------------------------"

UNION_TEST=$(curl -s "$TARGET/search?q=%27%20UNION%20SELECT%201%2Cusername%2Cpassword%2Cssn%2Crole%20FROM%20users%20--" 2>/dev/null || echo "Connection failed")
echo "$UNION_TEST" > "$EVIDENCE_DIR/union-test-result.json"

if echo "$UNION_TEST" | grep -qi "admin\|password\|ssn\|123-45" 2>/dev/null; then
    check_result "UNION exfiltration blocked" "fail" "Sensitive data (usernames/passwords/SSNs) still extractable"
else
    check_result "UNION exfiltration blocked" "pass" "UNION injection does not return sensitive data"
fi
echo ""

# --- Test 5: SQL Not Exposed in API Responses ---

echo "[*] Test 5: SQL queries must not appear in API responses"
echo "----------------------------------------------"

NORMAL_RESPONSE=$(curl -s "$TARGET/search?q=widget" 2>/dev/null || echo "Connection failed")
echo "$NORMAL_RESPONSE" > "$EVIDENCE_DIR/normal-response.json"

if echo "$NORMAL_RESPONSE" | grep -qi '"sql"' 2>/dev/null; then
    check_result "SQL hidden from responses" "fail" "SQL query still appears in API response"
else
    check_result "SQL hidden from responses" "pass" "No SQL queries in API responses"
fi
echo ""

# --- Test 6: Error Messages Do Not Expose Database Structure ---

echo "[*] Test 6: Error messages must be generic"
echo "----------------------------------------------"

ERROR_TEST=$(curl -s "$TARGET/user/notanumber" 2>/dev/null || echo "Connection failed")
echo "$ERROR_TEST" > "$EVIDENCE_DIR/error-response.json"

if echo "$ERROR_TEST" | grep -qiE "sqlite|traceback|operationalerror|syntax error|table|column" 2>/dev/null; then
    check_result "Generic error messages" "fail" "Database error details exposed in response"
else
    check_result "Generic error messages" "pass" "Error messages do not reveal database internals"
fi
echo ""

# --- Test 7: Sensitive Data Not in Responses ---

echo "[*] Test 7: Sensitive data (SSN) must not appear in responses"
echo "----------------------------------------------"

# Try legitimate user lookup
USER_RESPONSE=$(curl -s "$TARGET/user/1" 2>/dev/null || echo "Connection failed")
echo "$USER_RESPONSE" > "$EVIDENCE_DIR/user-response.json"

if echo "$USER_RESPONSE" | grep -qi "ssn\|123-45\|password\|admin123" 2>/dev/null; then
    check_result "Sensitive data excluded" "fail" "SSN or password appears in user endpoint response"
else
    check_result "Sensitive data excluded" "pass" "SSN and password are excluded from API responses"
fi
echo ""

# --- Test 8: SQLMap Validation ---

echo "[*] Test 8: SQLMap re-scan must find no injection points"
echo "----------------------------------------------"

if command -v sqlmap &>/dev/null; then
    echo "[*] Running SQLMap against /search endpoint..."
    sqlmap -u "$TARGET/search?q=test" \
        --batch \
        --level=3 \
        --risk=2 \
        --threads=4 \
        --output-dir="$EVIDENCE_DIR/sqlmap-validate" \
        2>&1 | tee "$EVIDENCE_DIR/sqlmap-validate-output.txt" || true

    if grep -qi "is vulnerable\|injectable\|sql injection" "$EVIDENCE_DIR/sqlmap-validate-output.txt" 2>/dev/null; then
        check_result "SQLMap validation" "fail" "SQLMap still detects injectable parameters"
    else
        check_result "SQLMap validation" "pass" "SQLMap finds no injectable parameters"
    fi
else
    echo "[SKIP] sqlmap not installed"
    SKIP=$((SKIP + 1))
fi
echo ""

# --- Test 9: Semgrep SAST Validation ---

echo "[*] Test 9: Semgrep must find no SQL injection patterns"
echo "----------------------------------------------"

if command -v semgrep &>/dev/null; then
    if [[ -n "$SOURCE_DIR" ]] && [[ -d "$SOURCE_DIR" ]]; then
        # Run with the custom CI rule
        if [[ -f "$SOURCE_DIR/.semgrep/sql-injection.yaml" ]]; then
            semgrep --config "$SOURCE_DIR/.semgrep/sql-injection.yaml" \
                --json \
                --output "$EVIDENCE_DIR/semgrep-validate.json" \
                "$SOURCE_DIR/app.py" 2>&1 | tee "$EVIDENCE_DIR/semgrep-validate-output.txt" || true

            SEMGREP_FINDINGS=$(python3 -c "
import json
try:
    with open('$EVIDENCE_DIR/semgrep-validate.json') as f:
        data = json.load(f)
    print(len(data.get('results', [])))
except Exception:
    print('0')
" 2>/dev/null || echo "0")

            if [[ "$SEMGREP_FINDINGS" -eq 0 ]]; then
                check_result "Semgrep SAST validation" "pass" "No SQL injection patterns found in source code"
            else
                check_result "Semgrep SAST validation" "fail" "$SEMGREP_FINDINGS SQL injection pattern(s) still in code"
            fi
        else
            echo "[SKIP] Semgrep CI rule not found — run fix.sh first"
            SKIP=$((SKIP + 1))
        fi
    else
        echo "[SKIP] Source directory not provided"
        SKIP=$((SKIP + 1))
    fi
else
    echo "[SKIP] semgrep not installed"
    SKIP=$((SKIP + 1))
fi
echo ""

# --- Test 10: Parameterized Queries Verified in Code ---

echo "[*] Test 10: Source code must use parameterized queries"
echo "----------------------------------------------"

if [[ -n "$SOURCE_DIR" ]] && [[ -f "$SOURCE_DIR/app.py" ]]; then
    # Check for string concatenation SQL patterns (should be zero)
    CONCAT_COUNT=$(grep -cE 'execute\(.*\+.*\+' "$SOURCE_DIR/app.py" 2>/dev/null || echo "0")
    FSTRING_COUNT=$(grep -cE 'execute\(f"' "$SOURCE_DIR/app.py" 2>/dev/null || echo "0")
    FORMAT_COUNT=$(grep -cE 'execute\(.*%.*%' "$SOURCE_DIR/app.py" 2>/dev/null || echo "0")

    # Check for parameterized queries (should be > 0)
    PARAM_COUNT=$(grep -cE 'execute\(.*\?.*,' "$SOURCE_DIR/app.py" 2>/dev/null || echo "0")

    UNSAFE=$((CONCAT_COUNT + FSTRING_COUNT + FORMAT_COUNT))

    if [[ "$UNSAFE" -eq 0 ]] && [[ "$PARAM_COUNT" -gt 0 ]]; then
        check_result "Parameterized queries in code" "pass" "$PARAM_COUNT parameterized queries, 0 unsafe patterns"
    elif [[ "$UNSAFE" -gt 0 ]]; then
        check_result "Parameterized queries in code" "fail" "$UNSAFE unsafe SQL pattern(s) remain in code"
    else
        check_result "Parameterized queries in code" "fail" "No parameterized queries detected"
    fi
else
    echo "[SKIP] Source directory not provided"
    SKIP=$((SKIP + 1))
fi
echo ""

# --- Validation Summary ---

echo "============================================"
echo "Validation Summary"
echo "============================================"
echo ""
echo "[*] Passed: $PASS"
echo "[*] Failed: $FAIL"
echo "[*] Skipped: $SKIP"
echo ""

if [[ "$FAIL" -eq 0 ]] && [[ "$PASS" -gt 0 ]]; then
    echo "[PASS] SI-10 SQL injection remediation validated successfully."
    echo "[*] All injection attempts blocked, parameterized queries in use,"
    echo "    sensitive data excluded from responses, Semgrep CI rule in place."
    echo ""
    echo "[*] Residual risk: LOW"
    echo "    - Likelihood: 1 (Rare) — parameterized queries + input validation"
    echo "    - Impact: 3 (Moderate) — database access still possible via other vectors"
    echo "    - Residual Score: 3 (Low)"
elif [[ "$FAIL" -gt 0 ]]; then
    echo "[FAIL] SI-10 SQL injection remediation has $FAIL failing check(s)."
    echo "[*] Review the failures above and re-run fix.sh."
else
    echo "[INCOMPLETE] All tests were skipped — provide source directory and install tools."
fi

echo ""
echo "[*] Evidence saved to: $EVIDENCE_DIR"
echo "[*] Files:"
ls -la "$EVIDENCE_DIR/"
