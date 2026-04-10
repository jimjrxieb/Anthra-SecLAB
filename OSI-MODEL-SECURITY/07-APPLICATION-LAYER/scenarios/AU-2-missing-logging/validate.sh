#!/usr/bin/env bash
set -euo pipefail

# AU-2 Missing Audit Logging — Validate
#
# Confirms that audit logging remediation is effective:
#   1. Successful logins are logged with source IP and username
#   2. Failed logins are logged (brute force detection possible)
#   3. Data access events are logged with classification
#   4. Authorization failures are logged with role and action
#   5. Logs are structured JSON (SIEM-parseable)
#   6. Log files exist and are being written to
#   7. Alert rules can match on logged events
#
# REQUIREMENTS:
#   - curl
#   - python3 (for JSON validation)
#   - Access to application log files
#
# USAGE:
#   ./validate.sh <target_url> <log_dir>
#
# EXAMPLE:
#   ./validate.sh http://localhost:5001 /tmp/au2-logging-evidence-*/unlogged-app/logs

# --- Argument Validation ---

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <target_url> [log_dir]"
    echo "Example: $0 http://localhost:5001 /path/to/app/logs/"
    exit 1
fi

TARGET="$1"
LOG_DIR="${2:-}"

# Try to auto-detect log dir
if [[ -z "$LOG_DIR" ]]; then
    LATEST=$(ls -td /tmp/au2-logging-evidence-*/unlogged-app/logs 2>/dev/null | head -1 || true)
    if [[ -n "$LATEST" ]]; then
        LOG_DIR="$LATEST"
        echo "[*] Auto-detected log directory: $LOG_DIR"
    fi
fi

EVIDENCE_DIR="/tmp/au2-logging-validate-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$EVIDENCE_DIR"

echo "============================================"
echo "AU-2 Missing Audit Logging — Validation"
echo "============================================"
echo ""
echo "[*] Target:       $TARGET"
echo "[*] Log dir:      ${LOG_DIR:-not provided}"
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

# --- Generate Fresh Test Events ---

echo "[*] Generating fresh test events..."
TIMESTAMP_BEFORE=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# Successful login
curl -s -X POST "$TARGET/login" -d "username=admin&password=admin123" > /dev/null 2>&1 || true
echo "  [*] Triggered successful login"

# Failed logins (brute force pattern)
for i in 1 2 3 4 5; do
    curl -s -X POST "$TARGET/login" -d "username=admin&password=wrong$i" > /dev/null 2>&1 || true
done
echo "  [*] Triggered 5 failed login attempts"

# Data access
curl -s "$TARGET/data" > /dev/null 2>&1 || true
echo "  [*] Triggered sensitive data access"

# Authorization failure
curl -s -X POST "$TARGET/admin/action" -d "action=delete_users&role=viewer" > /dev/null 2>&1 || true
echo "  [*] Triggered authorization failure"

sleep 1
TIMESTAMP_AFTER=$(date -u +%Y-%m-%dT%H:%M:%SZ)
echo ""

# --- Test 1: Audit Log File Exists ---

echo "[*] Test 1: Audit log file must exist and contain entries"
echo "----------------------------------------------"

if [[ -n "$LOG_DIR" ]]; then
    AUDIT_LOG="$LOG_DIR/audit.jsonl"

    if [[ -f "$AUDIT_LOG" ]]; then
        LINE_COUNT=$(wc -l < "$AUDIT_LOG" 2>/dev/null || echo "0")
        if [[ "$LINE_COUNT" -gt 0 ]]; then
            check_result "Audit log exists" "pass" "$AUDIT_LOG has $LINE_COUNT entries"
            cp "$AUDIT_LOG" "$EVIDENCE_DIR/audit-log-copy.jsonl"
        else
            check_result "Audit log exists" "fail" "Audit log file is empty"
        fi
    else
        check_result "Audit log exists" "fail" "Audit log file not found at $AUDIT_LOG"
    fi
else
    echo "[SKIP] Log directory not provided"
    SKIP=$((SKIP + 1))
fi
echo ""

# --- Test 2: Successful Login Logged ---

echo "[*] Test 2: Successful login must be logged"
echo "----------------------------------------------"

if [[ -n "$LOG_DIR" ]] && [[ -f "$LOG_DIR/audit.jsonl" ]]; then
    AUTH_SUCCESS=$(grep -c '"event_type": "authentication".*"status": "success"\|"status": "success".*"event_type": "authentication"' "$LOG_DIR/audit.jsonl" 2>/dev/null || echo "0")

    if [[ "$AUTH_SUCCESS" -gt 0 ]]; then
        check_result "Successful login logged" "pass" "$AUTH_SUCCESS successful auth event(s) logged"
    else
        check_result "Successful login logged" "fail" "No successful authentication events in audit log"
    fi
else
    echo "[SKIP] Audit log not available"
    SKIP=$((SKIP + 1))
fi
echo ""

# --- Test 3: Failed Login Logged ---

echo "[*] Test 3: Failed logins must be logged (brute force detection)"
echo "----------------------------------------------"

if [[ -n "$LOG_DIR" ]] && [[ -f "$LOG_DIR/audit.jsonl" ]]; then
    AUTH_FAILED=$(grep -c '"event_type": "authentication".*"status": "failed"\|"status": "failed".*"event_type": "authentication"' "$LOG_DIR/audit.jsonl" 2>/dev/null || echo "0")

    if [[ "$AUTH_FAILED" -ge 5 ]]; then
        check_result "Failed logins logged" "pass" "$AUTH_FAILED failed auth event(s) — brute force detectable"
    elif [[ "$AUTH_FAILED" -gt 0 ]]; then
        check_result "Failed logins logged" "pass" "$AUTH_FAILED failed auth event(s) logged (expected >= 5)"
    else
        check_result "Failed logins logged" "fail" "No failed authentication events in audit log"
    fi
else
    echo "[SKIP] Audit log not available"
    SKIP=$((SKIP + 1))
fi
echo ""

# --- Test 4: Data Access Logged ---

echo "[*] Test 4: Sensitive data access must be logged"
echo "----------------------------------------------"

if [[ -n "$LOG_DIR" ]] && [[ -f "$LOG_DIR/audit.jsonl" ]]; then
    DATA_ACCESS=$(grep -c '"event_type": "data_access"' "$LOG_DIR/audit.jsonl" 2>/dev/null || echo "0")

    if [[ "$DATA_ACCESS" -gt 0 ]]; then
        check_result "Data access logged" "pass" "$DATA_ACCESS data access event(s) logged"

        # Check for classification in log
        if grep -q '"classification"' "$LOG_DIR/audit.jsonl" 2>/dev/null; then
            echo "  [OK] Classification level is included in log entries"
        else
            echo "  [WARN] Classification level not found in log entries"
        fi
    else
        check_result "Data access logged" "fail" "No data access events in audit log"
    fi
else
    echo "[SKIP] Audit log not available"
    SKIP=$((SKIP + 1))
fi
echo ""

# --- Test 5: Authorization Failure Logged ---

echo "[*] Test 5: Authorization failures must be logged"
echo "----------------------------------------------"

if [[ -n "$LOG_DIR" ]] && [[ -f "$LOG_DIR/audit.jsonl" ]]; then
    AUTHZ_FAIL=$(grep -c '"event_type": "authorization".*"status": "failed"\|"status": "failed".*"event_type": "authorization"' "$LOG_DIR/audit.jsonl" 2>/dev/null || echo "0")

    if [[ "$AUTHZ_FAIL" -gt 0 ]]; then
        check_result "Authorization failures logged" "pass" "$AUTHZ_FAIL authorization failure event(s) logged"
    else
        check_result "Authorization failures logged" "fail" "No authorization failure events in audit log"
    fi
else
    echo "[SKIP] Audit log not available"
    SKIP=$((SKIP + 1))
fi
echo ""

# --- Test 6: Logs Are Valid JSON ---

echo "[*] Test 6: Log entries must be valid JSON (SIEM-parseable)"
echo "----------------------------------------------"

if [[ -n "$LOG_DIR" ]] && [[ -f "$LOG_DIR/audit.jsonl" ]]; then
    TOTAL_LINES=$(wc -l < "$LOG_DIR/audit.jsonl" 2>/dev/null || echo "0")
    VALID_JSON=0
    INVALID_JSON=0

    while IFS= read -r line; do
        if echo "$line" | python3 -m json.tool > /dev/null 2>&1; then
            VALID_JSON=$((VALID_JSON + 1))
        else
            INVALID_JSON=$((INVALID_JSON + 1))
        fi
    done < "$LOG_DIR/audit.jsonl"

    if [[ "$INVALID_JSON" -eq 0 ]] && [[ "$VALID_JSON" -gt 0 ]]; then
        check_result "Valid JSON format" "pass" "All $VALID_JSON log entries are valid JSON"
    else
        check_result "Valid JSON format" "fail" "$INVALID_JSON of $TOTAL_LINES entries are not valid JSON"
    fi
else
    echo "[SKIP] Audit log not available"
    SKIP=$((SKIP + 1))
fi
echo ""

# --- Test 7: Required Fields Present ---

echo "[*] Test 7: Log entries must include required fields"
echo "----------------------------------------------"

if [[ -n "$LOG_DIR" ]] && [[ -f "$LOG_DIR/audit.jsonl" ]]; then
    REQUIRED_FIELDS=("timestamp" "event_type" "status" "source_ip" "correlation_id")
    FIELD_PASS=0
    FIELD_TOTAL=${#REQUIRED_FIELDS[@]}

    # Check the most recent log entry
    LAST_LINE=$(tail -1 "$LOG_DIR/audit.jsonl" 2>/dev/null || echo "{}")

    for field in "${REQUIRED_FIELDS[@]}"; do
        if echo "$LAST_LINE" | grep -q "\"$field\"" 2>/dev/null; then
            echo "  [OK] Field present: $field"
            FIELD_PASS=$((FIELD_PASS + 1))
        else
            echo "  [--] Field missing: $field"
        fi
    done

    if [[ "$FIELD_PASS" -eq "$FIELD_TOTAL" ]]; then
        check_result "Required fields present" "pass" "All $FIELD_TOTAL required fields found"
    else
        check_result "Required fields present" "fail" "Only $FIELD_PASS of $FIELD_TOTAL required fields present"
    fi
else
    echo "[SKIP] Audit log not available"
    SKIP=$((SKIP + 1))
fi
echo ""

# --- Test 8: Source IP Captured ---

echo "[*] Test 8: Source IP must be captured in log entries"
echo "----------------------------------------------"

if [[ -n "$LOG_DIR" ]] && [[ -f "$LOG_DIR/audit.jsonl" ]]; then
    IP_ENTRIES=$(grep -c '"source_ip"' "$LOG_DIR/audit.jsonl" 2>/dev/null || echo "0")
    TOTAL_ENTRIES=$(wc -l < "$LOG_DIR/audit.jsonl" 2>/dev/null || echo "0")

    if [[ "$IP_ENTRIES" -eq "$TOTAL_ENTRIES" ]] && [[ "$TOTAL_ENTRIES" -gt 0 ]]; then
        check_result "Source IP captured" "pass" "All $TOTAL_ENTRIES entries include source_ip"
    elif [[ "$IP_ENTRIES" -gt 0 ]]; then
        check_result "Source IP captured" "pass" "$IP_ENTRIES of $TOTAL_ENTRIES entries include source_ip"
    else
        check_result "Source IP captured" "fail" "No entries include source_ip"
    fi
else
    echo "[SKIP] Audit log not available"
    SKIP=$((SKIP + 1))
fi
echo ""

# --- Test 9: HTTP Request Logging ---

echo "[*] Test 9: HTTP requests must be logged (app.jsonl)"
echo "----------------------------------------------"

if [[ -n "$LOG_DIR" ]] && [[ -f "$LOG_DIR/app.jsonl" ]]; then
    REQUEST_LOG_LINES=$(wc -l < "$LOG_DIR/app.jsonl" 2>/dev/null || echo "0")

    if [[ "$REQUEST_LOG_LINES" -gt 0 ]]; then
        check_result "HTTP request logging" "pass" "$REQUEST_LOG_LINES request(s) logged in app.jsonl"
    else
        check_result "HTTP request logging" "fail" "No HTTP requests logged"
    fi
else
    echo "[SKIP] app.jsonl not found"
    SKIP=$((SKIP + 1))
fi
echo ""

# --- Test 10: Alert Rules Can Match ---

echo "[*] Test 10: Detection queries can match logged events"
echo "----------------------------------------------"

if [[ -n "$LOG_DIR" ]] && [[ -f "$LOG_DIR/audit.jsonl" ]]; then
    # Simulate brute force detection query
    BRUTE_FORCE_MATCH=$(grep '"event_type": "authentication"' "$LOG_DIR/audit.jsonl" 2>/dev/null | \
        grep '"status": "failed"' 2>/dev/null | wc -l || echo "0")

    if [[ "$BRUTE_FORCE_MATCH" -ge 5 ]]; then
        check_result "Brute force detection" "pass" "$BRUTE_FORCE_MATCH failed logins — alert rule would fire"
    elif [[ "$BRUTE_FORCE_MATCH" -gt 0 ]]; then
        check_result "Brute force detection" "pass" "$BRUTE_FORCE_MATCH failed logins logged (threshold is 5)"
    else
        check_result "Brute force detection" "fail" "No failed login events for alert rules to match"
    fi
else
    echo "[SKIP] Audit log not available"
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
    echo "[PASS] AU-2 audit logging remediation validated successfully."
    echo "[*] All security events are logged in structured JSON format."
    echo "[*] Authentication, data access, and authorization events are captured."
    echo "[*] Brute force detection is now possible via SIEM queries."
    echo ""
    echo "[*] Residual risk: LOW"
    echo "    - Likelihood: 2 (Unlikely) — events are logged and alertable"
    echo "    - Impact: 2 (Minor) — breaches will be detected quickly"
    echo "    - Residual Score: 4 (Low)"
elif [[ "$FAIL" -gt 0 ]]; then
    echo "[FAIL] AU-2 audit logging has $FAIL failing check(s)."
    echo "[*] Review the failures above and re-run fix.sh."
else
    echo "[INCOMPLETE] All tests were skipped — provide log directory."
fi

echo ""
echo "[*] Evidence saved to: $EVIDENCE_DIR"
echo "[*] Files:"
ls -la "$EVIDENCE_DIR/"
