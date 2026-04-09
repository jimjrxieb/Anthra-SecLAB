#!/usr/bin/env bash
set -euo pipefail

# AU-2 Missing Audit Logging — Detect
#
# Detects missing audit logging by:
#   1. Checking for log gaps — generating events and verifying they appear in logs
#   2. Reviewing application log configuration (level, format, handlers)
#   3. Checking if failed logins, data access, and auth failures are logged
#   4. Querying Splunk/Sentinel for missing auth events (if configured)
#   5. Verifying log shipping and SIEM integration
#
# REQUIREMENTS:
#   - curl
#   - Access to application log files
#   - Splunk CLI (optional) or Sentinel/KQL access (optional)
#
# USAGE:
#   ./detect.sh <target_url> [log_dir]
#
# EXAMPLE:
#   ./detect.sh http://localhost:5001 /tmp/au2-logging-evidence-*/
#   ./detect.sh http://10.0.1.50:5001 /var/log/app/

# --- Argument Validation ---

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <target_url> [log_dir]"
    echo "Example: $0 http://localhost:5001 /var/log/app/"
    echo ""
    echo "target_url:  Base URL of the application to test"
    echo "log_dir:     Path to application log directory (optional)"
    exit 1
fi

TARGET="$1"
LOG_DIR="${2:-}"

EVIDENCE_DIR="/tmp/au2-logging-detect-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$EVIDENCE_DIR"

echo "============================================"
echo "AU-2 Missing Audit Logging — Detection"
echo "============================================"
echo ""
echo "[*] Target:       $TARGET"
echo "[*] Log dir:      ${LOG_DIR:-not provided}"
echo "[*] Evidence dir: $EVIDENCE_DIR"
echo ""

FINDINGS=0

# --- Method 1: Generate Events and Check Logs ---

echo "[*] Method 1: Generate security events and check for log entries"
echo "----------------------------------------------"

TIMESTAMP_BEFORE=$(date -u +%Y-%m-%dT%H:%M:%SZ)

echo "[*] Generating test events..."

# Successful login
echo "[*]   Triggering successful login..."
curl -s -X POST "$TARGET/login" -d "username=admin&password=admin123" > "$EVIDENCE_DIR/login-success-response.json" 2>/dev/null || true

# Failed login attempts (brute force pattern)
echo "[*]   Triggering 5 failed login attempts (brute force pattern)..."
for i in 1 2 3 4 5; do
    curl -s -X POST "$TARGET/login" -d "username=admin&password=wrong$i" > /dev/null 2>/dev/null || true
done

# Sensitive data access
echo "[*]   Triggering sensitive data access..."
curl -s "$TARGET/data" > "$EVIDENCE_DIR/data-access-response.json" 2>/dev/null || true

# Authorization failure
echo "[*]   Triggering privilege escalation attempt..."
curl -s -X POST "$TARGET/admin/action" -d "action=delete_users&role=viewer" > "$EVIDENCE_DIR/authz-failure-response.json" 2>/dev/null || true

TIMESTAMP_AFTER=$(date -u +%Y-%m-%dT%H:%M:%SZ)
echo ""
echo "[*] Events generated between $TIMESTAMP_BEFORE and $TIMESTAMP_AFTER"
echo ""

# Check log files for evidence of these events
if [[ -n "$LOG_DIR" ]]; then
    echo "[*] Searching log directory for evidence of generated events..."

    # Find all log files
    LOG_FILES=$(find "$LOG_DIR" -name "*.log" -o -name "*.json" -o -name "*.jsonl" 2>/dev/null || true)

    if [[ -n "$LOG_FILES" ]]; then
        AUTH_EVENTS=0
        FAILED_LOGIN_EVENTS=0
        DATA_ACCESS_EVENTS=0
        AUTHZ_EVENTS=0

        while IFS= read -r logfile; do
            # Check for authentication events
            AUTH_EVENTS=$((AUTH_EVENTS + $(grep -ci "login\|auth\|authenticated" "$logfile" 2>/dev/null || echo "0")))
            FAILED_LOGIN_EVENTS=$((FAILED_LOGIN_EVENTS + $(grep -ci "failed.*login\|login.*failed\|authentication.*failed\|invalid.*credentials" "$logfile" 2>/dev/null || echo "0")))
            DATA_ACCESS_EVENTS=$((DATA_ACCESS_EVENTS + $(grep -ci "data.*access\|sensitive.*data\|record.*accessed" "$logfile" 2>/dev/null || echo "0")))
            AUTHZ_EVENTS=$((AUTHZ_EVENTS + $(grep -ci "forbidden\|unauthorized\|authorization.*fail\|privilege.*escalat" "$logfile" 2>/dev/null || echo "0")))
        done <<< "$LOG_FILES"

        if [[ "$AUTH_EVENTS" -eq 0 ]]; then
            echo "[ALERT] No authentication events found in logs"
            FINDINGS=$((FINDINGS + 1))
        else
            echo "[OK] Found $AUTH_EVENTS authentication event(s) in logs"
        fi

        if [[ "$FAILED_LOGIN_EVENTS" -eq 0 ]]; then
            echo "[ALERT] No failed login events found — brute force attacks would be invisible"
            FINDINGS=$((FINDINGS + 1))
        else
            echo "[OK] Found $FAILED_LOGIN_EVENTS failed login event(s) in logs"
        fi

        if [[ "$DATA_ACCESS_EVENTS" -eq 0 ]]; then
            echo "[ALERT] No data access events found — exfiltration would leave no trace"
            FINDINGS=$((FINDINGS + 1))
        else
            echo "[OK] Found $DATA_ACCESS_EVENTS data access event(s) in logs"
        fi

        if [[ "$AUTHZ_EVENTS" -eq 0 ]]; then
            echo "[ALERT] No authorization failure events found — privilege escalation invisible"
            FINDINGS=$((FINDINGS + 1))
        else
            echo "[OK] Found $AUTHZ_EVENTS authorization failure event(s) in logs"
        fi
    else
        echo "[ALERT] No log files found in $LOG_DIR"
        FINDINGS=$((FINDINGS + 1))
    fi
else
    echo "[SKIP] Log directory not provided — cannot verify log content"
    echo "       Pass log directory as second argument: ./detect.sh $TARGET /path/to/logs/"
fi
echo ""

# --- Method 2: Review Application Log Configuration ---

echo "[*] Method 2: Review application log configuration"
echo "----------------------------------------------"

if [[ -n "$LOG_DIR" ]]; then
    # Check for logging configuration files
    LOGGING_CONF=$(find "$LOG_DIR" -name "logging.conf*" -o -name "log_config*" -o -name "*logging*.yaml" -o -name "*logging*.json" 2>/dev/null || true)

    if [[ -n "$LOGGING_CONF" ]]; then
        echo "[*] Found logging configuration files:"
        echo "$LOGGING_CONF"

        while IFS= read -r conf; do
            echo ""
            echo "[*] Reviewing: $conf"

            # Check for disabled indicators
            if echo "$conf" | grep -qi "disabled" 2>/dev/null; then
                echo "[ALERT] Logging config has been disabled (renamed to .disabled)"
                FINDINGS=$((FINDINGS + 1))
            fi

            # Check log level
            if grep -qi "CRITICAL\|NONE\|OFF\|NOTSET" "$conf" 2>/dev/null; then
                echo "[ALERT] Log level is set to CRITICAL/NONE — most events are suppressed"
                FINDINGS=$((FINDINGS + 1))
            fi
        done <<< "$LOGGING_CONF"
    else
        echo "[ALERT] No logging configuration files found"
        FINDINGS=$((FINDINGS + 1))
    fi

    # Check source code for logging level
    APP_FILES=$(find "$LOG_DIR" -name "app.py" -o -name "*.py" 2>/dev/null | head -5 || true)
    if [[ -n "$APP_FILES" ]]; then
        while IFS= read -r pyfile; do
            if grep -q "logging.CRITICAL\|setLevel(logging.CRITICAL)\|level=logging.CRITICAL" "$pyfile" 2>/dev/null; then
                echo "[ALERT] Source code sets log level to CRITICAL: $pyfile"
                FINDINGS=$((FINDINGS + 1))
            fi

            if grep -q "werkzeug.*CRITICAL\|werkzeug.*disable" "$pyfile" 2>/dev/null; then
                echo "[ALERT] Flask request logging is disabled: $pyfile"
                FINDINGS=$((FINDINGS + 1))
            fi
        done <<< "$APP_FILES"
    fi
else
    echo "[SKIP] Log directory not provided"
fi
echo ""

# --- Method 3: Check for Structured Logging ---

echo "[*] Method 3: Check for structured (JSON) logging"
echo "----------------------------------------------"

if [[ -n "$LOG_DIR" ]]; then
    JSON_LOGS=$(find "$LOG_DIR" -name "*.jsonl" -o -name "*-json.log" 2>/dev/null || true)

    if [[ -z "$JSON_LOGS" ]]; then
        echo "[ALERT] No structured JSON log files found"
        echo "[*] Structured logging is required for SIEM integration (Splunk, Sentinel)"
        FINDINGS=$((FINDINGS + 1))
    else
        echo "[OK] Found structured log files:"
        echo "$JSON_LOGS"
    fi
else
    echo "[SKIP] Log directory not provided"
fi
echo ""

# --- Method 4: Splunk Query for Missing Events ---

echo "[*] Method 4: Splunk — query for missing auth events"
echo "----------------------------------------------"

if command -v splunk &>/dev/null; then
    echo "[*] Querying Splunk for authentication events in the last hour..."

    # Search for auth events
    SPLUNK_QUERY='search index=main sourcetype=app_audit event_type=authentication earliest=-1h | stats count by status'
    splunk search "$SPLUNK_QUERY" -output rawdata 2>&1 | tee "$EVIDENCE_DIR/splunk-auth-events.txt" || true

    AUTH_COUNT=$(grep -c "authentication" "$EVIDENCE_DIR/splunk-auth-events.txt" 2>/dev/null || echo "0")
    if [[ "$AUTH_COUNT" -eq 0 ]]; then
        echo "[ALERT] No authentication events found in Splunk in the last hour"
        FINDINGS=$((FINDINGS + 1))
    fi

    # Search for failed logins specifically
    SPLUNK_QUERY_FAILED='search index=main sourcetype=app_audit event_type=authentication status=failed earliest=-1h | stats count'
    splunk search "$SPLUNK_QUERY_FAILED" -output rawdata 2>&1 | tee "$EVIDENCE_DIR/splunk-failed-logins.txt" || true

    echo "[+] Splunk results saved to $EVIDENCE_DIR/splunk-*.txt"
else
    echo "[SKIP] Splunk CLI not installed."
    echo "       Manual check: run this KQL in Sentinel:"
    echo ""
    echo "       // KQL: Check for auth events in the last hour"
    echo "       AppAuditLogs"
    echo "       | where TimeGenerated > ago(1h)"
    echo "       | where EventType == 'authentication'"
    echo "       | summarize count() by Status"
    echo ""
    echo "       // KQL: Check for failed login patterns"
    echo "       AppAuditLogs"
    echo "       | where TimeGenerated > ago(1h)"
    echo "       | where EventType == 'authentication' and Status == 'failed'"
    echo "       | summarize FailedCount=count() by SourceIP, UserName"
    echo "       | where FailedCount >= 5"
fi
echo ""

# --- Method 5: Check SIEM Integration ---

echo "[*] Method 5: Verify SIEM integration and log shipping"
echo "----------------------------------------------"

# Check for common log shipping agents
SIEM_AGENTS=("splunk-forwarder" "filebeat" "fluentd" "fluentbit" "fluent-bit" "rsyslog" "syslog-ng" "omsagent" "azuremonitoragent")
AGENT_FOUND=false

for agent in "${SIEM_AGENTS[@]}"; do
    if command -v "$agent" &>/dev/null || pgrep -f "$agent" &>/dev/null || systemctl is-active "$agent" &>/dev/null 2>&1; then
        echo "[OK] Log shipping agent found: $agent"
        AGENT_FOUND=true
    fi
done

if [[ "$AGENT_FOUND" == "false" ]]; then
    echo "[ALERT] No SIEM log shipping agent detected"
    echo "[*] Without log shipping, even if the app logs events, they stay on the local disk"
    echo "[*] An attacker with host access can delete local logs to cover their tracks"
    FINDINGS=$((FINDINGS + 1))
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
    echo "[ALERT] Audit logging gaps detected!"
    echo ""
    echo "[*] Key risks:"
    echo "    - Breaches go undetected (IBM: breaches detected in <200 days cost \$3.93M less)"
    echo "    - SolarWinds 2020: went undetected 14 months due to insufficient logging"
    echo "    - Brute force attacks are invisible without failed login logging"
    echo "    - Data exfiltration leaves no trace without access logging"
    echo "    - Incident response is impossible without an audit trail"
    echo "    - AU-2 compliance: every framework requires security event logging"
    echo ""
    echo "[*] Run fix.sh to enable structured JSON logging with full audit trail."
else
    echo "[OK] No audit logging gaps detected."
fi

echo ""
echo "[*] Evidence saved to: $EVIDENCE_DIR"
echo "[*] Files:"
ls -la "$EVIDENCE_DIR/"
