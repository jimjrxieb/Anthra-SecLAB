#!/usr/bin/env bash
set -euo pipefail

# AU-2 Missing Audit Logging — Fix
#
# Enables structured JSON logging with comprehensive audit coverage:
#   1. Authentication events (success/failure with source IP and username)
#   2. Failed login tracking with brute force detection
#   3. Data access logging (who accessed what, when, classification level)
#   4. Authorization failure logging (privilege escalation attempts)
#   5. Structured JSON format for SIEM ingestion
#   6. Log shipping configuration for Splunk and Sentinel
#   7. KQL/SPL detection queries for alerting
#
# CSF 2.0: DE.AE-07 (Threat intel integrated)
# CIS v8: 8.2 (Collect Audit Logs)
# NIST: AU-2 (Audit Events)
#
# REQUIREMENTS:
#   - Python 3.8+ with pip
#   - Access to the vulnerable app directory
#
# USAGE:
#   ./fix.sh [app_dir] [port]
#
# EXAMPLE:
#   ./fix.sh /tmp/au2-logging-evidence-*/unlogged-app 5001

# --- Argument Validation ---

APP_DIR="${1:-}"
PORT="${2:-5001}"

if [[ -z "$APP_DIR" ]]; then
    LATEST=$(ls -td /tmp/au2-logging-evidence-*/unlogged-app 2>/dev/null | head -1 || true)
    if [[ -n "$LATEST" ]]; then
        APP_DIR="$LATEST"
        echo "[*] Auto-detected app directory: $APP_DIR"
    else
        echo "Usage: $0 <app_dir> [port]"
        echo "Example: $0 /tmp/au2-logging-evidence-20260408-120000/unlogged-app 5001"
        exit 1
    fi
fi

if [[ ! -f "$APP_DIR/app.py" ]]; then
    echo "[ERROR] app.py not found in $APP_DIR"
    exit 1
fi

EVIDENCE_DIR="/tmp/au2-logging-fix-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$EVIDENCE_DIR"

echo "============================================"
echo "AU-2 Missing Audit Logging — Fix"
echo "============================================"
echo ""
echo "[*] App dir:      $APP_DIR"
echo "[*] Port:         $PORT"
echo "[*] Evidence dir: $EVIDENCE_DIR"
echo ""

# --- Record Pre-Fix State ---

echo "[*] Recording pre-fix state..."
cp "$APP_DIR/app.py" "$EVIDENCE_DIR/app-before-fix.py"
echo "[+] Saved unlogged source as evidence"
echo ""

# --- Stop Application ---

echo "[*] Stopping application..."
PID_FILE=$(dirname "$APP_DIR")/app.pid
if [[ -f "$PID_FILE" ]]; then
    OLD_PID=$(cat "$PID_FILE")
    if kill -0 "$OLD_PID" 2>/dev/null; then
        kill "$OLD_PID" 2>/dev/null || true
        sleep 1
        echo "[+] Stopped (PID: $OLD_PID)"
    fi
fi

if command -v lsof &>/dev/null; then
    PIDS=$(lsof -ti :"$PORT" 2>/dev/null || true)
    if [[ -n "$PIDS" ]]; then
        echo "$PIDS" | xargs kill 2>/dev/null || true
        sleep 1
    fi
fi
echo ""

# --- Patch Application With Structured Logging ---

echo "[*] Patching application with structured JSON audit logging..."

LOG_DIR="$APP_DIR/logs"
mkdir -p "$LOG_DIR"

cat > "$APP_DIR/app.py" << PYEOF
"""
AU-2 Fix Scenario: Application With Comprehensive Audit Logging

All security-relevant events are logged in structured JSON format:
  1. Authentication events (success/failure) with source IP and user agent
  2. Data access events with classification level and record count
  3. Authorization failures with attempted action and actual role
  4. All events include correlation ID, timestamp, and source IP
  5. Logs are written to both file and stdout for SIEM shipping
"""
import json
import logging
import logging.handlers
import os
import sqlite3
import time
import uuid
from datetime import datetime, timezone

from flask import Flask, request, jsonify, g

app = Flask(__name__)
DB_PATH = os.path.join(os.path.dirname(__file__), "app.db")
LOG_DIR = os.path.join(os.path.dirname(__file__), "logs")
os.makedirs(LOG_DIR, exist_ok=True)


# --- Structured JSON Logger ---

class JSONFormatter(logging.Formatter):
    """Structured JSON log formatter for SIEM ingestion."""

    def format(self, record):
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        # Add extra fields if present
        for key in ["event_type", "status", "username", "source_ip",
                     "user_agent", "endpoint", "method", "correlation_id",
                     "record_count", "classification", "action", "role",
                     "response_code", "duration_ms"]:
            if hasattr(record, key):
                log_entry[key] = getattr(record, key)
        return json.dumps(log_entry)


def setup_logging():
    """Configure structured JSON logging to file and stdout."""
    logger = logging.getLogger("audit")
    logger.setLevel(logging.INFO)

    # JSON file handler — rotated daily, 30 days retention
    audit_log_path = os.path.join(LOG_DIR, "audit.jsonl")
    file_handler = logging.handlers.TimedRotatingFileHandler(
        audit_log_path, when="midnight", backupCount=30, encoding="utf-8"
    )
    file_handler.setFormatter(JSONFormatter())
    logger.addHandler(file_handler)

    # Stdout handler — for container/SIEM log shipping
    stdout_handler = logging.StreamHandler()
    stdout_handler.setFormatter(JSONFormatter())
    logger.addHandler(stdout_handler)

    return logger


audit_logger = setup_logging()

# Also configure Flask's request logger
app_logger = logging.getLogger("app")
app_logger.setLevel(logging.INFO)
app_handler = logging.handlers.TimedRotatingFileHandler(
    os.path.join(LOG_DIR, "app.jsonl"), when="midnight", backupCount=30, encoding="utf-8"
)
app_handler.setFormatter(JSONFormatter())
app_logger.addHandler(app_handler)


# --- Request Middleware ---

@app.before_request
def before_request():
    """Set correlation ID and start timer for every request."""
    g.correlation_id = str(uuid.uuid4())
    g.start_time = time.time()


@app.after_request
def after_request(response):
    """Log every request with timing and status."""
    duration_ms = round((time.time() - g.start_time) * 1000, 2)
    app_logger.info(
        "HTTP request",
        extra={
            "event_type": "http_request",
            "method": request.method,
            "endpoint": request.path,
            "source_ip": request.remote_addr,
            "user_agent": request.headers.get("User-Agent", ""),
            "response_code": response.status_code,
            "correlation_id": g.correlation_id,
            "duration_ms": duration_ms,
        },
    )
    return response


def get_db():
    """Get database connection."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initialize database with sample data."""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            email TEXT NOT NULL,
            role TEXT DEFAULT 'user'
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sensitive_data (
            id INTEGER PRIMARY KEY,
            record_type TEXT NOT NULL,
            content TEXT NOT NULL,
            classification TEXT DEFAULT 'CONFIDENTIAL'
        )
    """)

    cursor.executemany(
        "INSERT OR IGNORE INTO users (id, username, password, email, role) VALUES (?, ?, ?, ?, ?)",
        [
            (1, "admin", "admin123", "admin@example.com", "admin"),
            (2, "analyst", "analyst1", "analyst@example.com", "analyst"),
            (3, "viewer", "viewer1", "viewer@example.com", "viewer"),
        ],
    )

    cursor.executemany(
        "INSERT OR IGNORE INTO sensitive_data (id, record_type, content, classification) VALUES (?, ?, ?, ?)",
        [
            (1, "PII", "SSN: 123-45-6789", "CONFIDENTIAL"),
            (2, "financial", "Account: 4111-1111-1111-1111", "RESTRICTED"),
            (3, "medical", "Diagnosis: Type 2 Diabetes", "PHI"),
        ],
    )

    conn.commit()
    conn.close()


@app.route("/")
def index():
    return jsonify({
        "app": "AU-2 Logged App",
        "status": "AUDIT LOGGING ENABLED",
        "endpoints": [
            "POST /login — authentication (logged)",
            "GET /data — sensitive data access (logged)",
            "POST /admin/action — admin action (logged)",
        ],
    })


@app.route("/login", methods=["POST"])
def login():
    """Authentication endpoint with comprehensive logging."""
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    conn = get_db()
    try:
        user = conn.execute(
            "SELECT * FROM users WHERE username = ? AND password = ?",
            (username, password),
        ).fetchone()

        if user:
            # FIX: Log successful authentication
            audit_logger.info(
                f"Authentication successful for user '{username}'",
                extra={
                    "event_type": "authentication",
                    "status": "success",
                    "username": username,
                    "source_ip": request.remote_addr,
                    "user_agent": request.headers.get("User-Agent", ""),
                    "endpoint": "/login",
                    "method": "POST",
                    "correlation_id": g.correlation_id,
                    "role": user["role"],
                },
            )
            return jsonify({
                "status": "authenticated",
                "user": {"id": user["id"], "username": user["username"], "role": user["role"]},
            })
        else:
            # FIX: Log failed authentication — critical for brute force detection
            audit_logger.warning(
                f"Authentication failed for user '{username}'",
                extra={
                    "event_type": "authentication",
                    "status": "failed",
                    "username": username,
                    "source_ip": request.remote_addr,
                    "user_agent": request.headers.get("User-Agent", ""),
                    "endpoint": "/login",
                    "method": "POST",
                    "correlation_id": g.correlation_id,
                },
            )
            return jsonify({"status": "failed"}), 401
    finally:
        conn.close()


@app.route("/data")
def get_data():
    """Sensitive data access with audit logging."""
    conn = get_db()
    try:
        records = conn.execute("SELECT * FROM sensitive_data").fetchall()
        result = [dict(r) for r in records]

        # FIX: Log data access with classification levels
        classifications = list(set(r["classification"] for r in records))
        audit_logger.info(
            "Sensitive data accessed",
            extra={
                "event_type": "data_access",
                "status": "success",
                "source_ip": request.remote_addr,
                "user_agent": request.headers.get("User-Agent", ""),
                "endpoint": "/data",
                "method": "GET",
                "correlation_id": g.correlation_id,
                "record_count": len(result),
                "classification": ",".join(classifications),
            },
        )

        return jsonify({"count": len(result), "records": result})
    finally:
        conn.close()


@app.route("/admin/action", methods=["POST"])
def admin_action():
    """Admin action with authorization and audit logging."""
    action = request.form.get("action", "")
    user_role = request.form.get("role", "viewer")

    if user_role != "admin":
        # FIX: Log authorization failure — critical for privilege escalation detection
        audit_logger.warning(
            f"Authorization failed: user with role '{user_role}' attempted admin action '{action}'",
            extra={
                "event_type": "authorization",
                "status": "failed",
                "source_ip": request.remote_addr,
                "user_agent": request.headers.get("User-Agent", ""),
                "endpoint": "/admin/action",
                "method": "POST",
                "correlation_id": g.correlation_id,
                "action": action,
                "role": user_role,
            },
        )
        return jsonify({"error": "Forbidden"}), 403

    # FIX: Log successful admin action
    audit_logger.info(
        f"Admin action executed: '{action}'",
        extra={
            "event_type": "admin_action",
            "status": "success",
            "source_ip": request.remote_addr,
            "user_agent": request.headers.get("User-Agent", ""),
            "endpoint": "/admin/action",
            "method": "POST",
            "correlation_id": g.correlation_id,
            "action": action,
            "role": user_role,
        },
    )
    return jsonify({"status": "action executed", "action": action})


if __name__ == "__main__":
    init_db()
    audit_logger.info("Application started", extra={
        "event_type": "lifecycle",
        "status": "started",
        "endpoint": "N/A",
        "method": "N/A",
        "source_ip": "localhost",
        "correlation_id": "startup",
    })
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5001)), debug=False)
PYEOF

echo "[+] Application patched with structured JSON audit logging"
echo ""

# --- Save Fixed Code as Evidence ---

cp "$APP_DIR/app.py" "$EVIDENCE_DIR/app-after-fix.py"

# --- Create Diff ---

echo "[*] Generating before/after diff..."
diff -u "$EVIDENCE_DIR/app-before-fix.py" "$EVIDENCE_DIR/app-after-fix.py" \
    > "$EVIDENCE_DIR/fix-diff.patch" 2>/dev/null || true
echo "[+] Diff saved"
echo ""

# --- Create Log Shipping Configuration ---

echo "[*] Creating log shipping configurations..."

# Splunk Universal Forwarder config
cat > "$EVIDENCE_DIR/splunk-inputs.conf" << 'SPLUNKEOF'
# Splunk Universal Forwarder — inputs.conf
# Deploy to: $SPLUNK_HOME/etc/apps/au2_audit_logging/local/inputs.conf

[monitor:///opt/app/logs/audit.jsonl]
disabled = false
index = main
sourcetype = app_audit
host_segment = 1

[monitor:///opt/app/logs/app.jsonl]
disabled = false
index = main
sourcetype = app_requests
host_segment = 1
SPLUNKEOF

echo "[+] Splunk inputs.conf created"

# Splunk props.conf for JSON parsing
cat > "$EVIDENCE_DIR/splunk-props.conf" << 'SPLUNKEOF'
# Splunk — props.conf
# Deploy to: $SPLUNK_HOME/etc/apps/au2_audit_logging/local/props.conf

[app_audit]
KV_MODE = json
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%6N%z
TIME_PREFIX = "timestamp":"
MAX_TIMESTAMP_LOOKAHEAD = 40
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\r\n]+)

[app_requests]
KV_MODE = json
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%6N%z
TIME_PREFIX = "timestamp":"
MAX_TIMESTAMP_LOOKAHEAD = 40
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\r\n]+)
SPLUNKEOF

echo "[+] Splunk props.conf created"

# Filebeat config for Sentinel/ELK
cat > "$EVIDENCE_DIR/filebeat-config.yaml" << 'FILEBEATEOF'
# Filebeat configuration for Azure Sentinel / ELK
# Deploy to: /etc/filebeat/filebeat.yml

filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /opt/app/logs/audit.jsonl
    json.keys_under_root: true
    json.add_error_key: true
    fields:
      log_type: audit
      environment: production

  - type: log
    enabled: true
    paths:
      - /opt/app/logs/app.jsonl
    json.keys_under_root: true
    json.add_error_key: true
    fields:
      log_type: app_requests
      environment: production

# Output to Azure Sentinel (via Log Analytics)
# output.logstash:
#   hosts: ["<sentinel-workspace>.ods.opinsights.azure.com:443"]

# Output to Elasticsearch/ELK
# output.elasticsearch:
#   hosts: ["https://elasticsearch:9200"]
FILEBEATEOF

echo "[+] Filebeat config created"
echo ""

# --- Create Detection Queries ---

echo "[*] Creating SIEM detection queries..."

cat > "$EVIDENCE_DIR/detection-queries.md" << 'QUERYEOF'
# AU-2 Detection Queries

## Splunk SPL Queries

### Brute Force Detection (5+ failed logins from same IP in 10 minutes)
```spl
index=main sourcetype=app_audit event_type=authentication status=failed
| bin _time span=10m
| stats count as FailedAttempts values(username) as TargetUsers by source_ip _time
| where FailedAttempts >= 5
| sort -FailedAttempts
```

### Successful Login After Failed Attempts (credential stuffing indicator)
```spl
index=main sourcetype=app_audit event_type=authentication
| sort _time
| streamstats window=10 count(eval(status="failed")) as RecentFailures by source_ip
| where status="success" AND RecentFailures >= 3
| table _time source_ip username RecentFailures
```

### Sensitive Data Access Monitoring
```spl
index=main sourcetype=app_audit event_type=data_access
| stats count as AccessCount sum(record_count) as TotalRecords values(classification) as Classifications by source_ip
| where TotalRecords > 100 OR AccessCount > 10
| sort -TotalRecords
```

### Privilege Escalation Attempts
```spl
index=main sourcetype=app_audit event_type=authorization status=failed
| stats count as Attempts values(action) as Actions by source_ip role
| where Attempts >= 3
| sort -Attempts
```

### After-Hours Access (outside 6 AM - 10 PM local time)
```spl
index=main sourcetype=app_audit event_type=authentication status=success
| eval hour=strftime(_time, "%H")
| where hour < 6 OR hour > 22
| table _time source_ip username endpoint
```

## Microsoft Sentinel KQL Queries

### Brute Force Detection
```kql
AppAuditLogs
| where TimeGenerated > ago(1h)
| where EventType == "authentication" and Status == "failed"
| summarize FailedAttempts=count(), TargetUsers=make_set(Username) by SourceIP, bin(TimeGenerated, 10m)
| where FailedAttempts >= 5
| sort by FailedAttempts desc
```

### Successful Login After Failures
```kql
let FailedLogins = AppAuditLogs
    | where TimeGenerated > ago(1h)
    | where EventType == "authentication" and Status == "failed"
    | summarize FailCount=count() by SourceIP, Username;
let SuccessLogins = AppAuditLogs
    | where TimeGenerated > ago(1h)
    | where EventType == "authentication" and Status == "success";
SuccessLogins
| join kind=inner FailedLogins on SourceIP, Username
| where FailCount >= 3
| project TimeGenerated, SourceIP, Username, FailCount
```

### Sensitive Data Access Anomaly
```kql
AppAuditLogs
| where TimeGenerated > ago(24h)
| where EventType == "data_access"
| summarize AccessCount=count(), TotalRecords=sum(RecordCount) by SourceIP, bin(TimeGenerated, 1h)
| where TotalRecords > 100
| sort by TotalRecords desc
```

### Privilege Escalation Attempts
```kql
AppAuditLogs
| where TimeGenerated > ago(1h)
| where EventType == "authorization" and Status == "failed"
| summarize Attempts=count(), Actions=make_set(Action) by SourceIP, Role
| where Attempts >= 3
```

### Create Sentinel Analytics Rule (brute force alert)
```kql
// Schedule: Every 10 minutes, lookback 10 minutes
AppAuditLogs
| where TimeGenerated > ago(10m)
| where EventType == "authentication" and Status == "failed"
| summarize FailedAttempts=count() by SourceIP, Username
| where FailedAttempts >= 5
// Severity: Medium
// MITRE: T1110 - Brute Force
```
QUERYEOF

echo "[+] Detection queries saved to $EVIDENCE_DIR/detection-queries.md"
echo ""

# --- Restart Fixed Application ---

echo "[*] Restarting application with audit logging enabled..."
export PORT="$PORT"

cd "$APP_DIR"
nohup "$APP_DIR/venv/bin/python" "$APP_DIR/app.py" > "$(dirname "$APP_DIR")/app-fixed.log" 2>&1 &
NEW_PID=$!
echo "$NEW_PID" > "$(dirname "$APP_DIR")/app.pid"

sleep 2

if kill -0 "$NEW_PID" 2>/dev/null; then
    echo "[+] Logged application started (PID: $NEW_PID)"
else
    echo "[ERROR] Application failed to start."
    exit 1
fi
echo ""

# --- Verify Logging Works ---

echo "[*] Verifying audit logging..."

# Generate test events
curl -s -X POST "http://localhost:$PORT/login" -d "username=admin&password=admin123" > /dev/null 2>&1 || true
curl -s -X POST "http://localhost:$PORT/login" -d "username=admin&password=wrong" > /dev/null 2>&1 || true
curl -s "http://localhost:$PORT/data" > /dev/null 2>&1 || true
curl -s -X POST "http://localhost:$PORT/admin/action" -d "action=test&role=viewer" > /dev/null 2>&1 || true

sleep 1

# Check that events were logged
AUDIT_LOG="$LOG_DIR/audit.jsonl"
if [[ -f "$AUDIT_LOG" ]]; then
    AUDIT_LINES=$(wc -l < "$AUDIT_LOG" 2>/dev/null || echo "0")
    echo "[OK] Audit log has $AUDIT_LINES entries"

    # Verify specific event types
    AUTH_SUCCESS=$(grep -c '"status": "success".*authentication\|authentication.*"status": "success"' "$AUDIT_LOG" 2>/dev/null || echo "0")
    AUTH_FAILED=$(grep -c '"status": "failed".*authentication\|authentication.*"status": "failed"' "$AUDIT_LOG" 2>/dev/null || echo "0")
    DATA_ACCESS=$(grep -c '"event_type": "data_access"' "$AUDIT_LOG" 2>/dev/null || echo "0")
    AUTHZ_FAILED=$(grep -c '"event_type": "authorization"' "$AUDIT_LOG" 2>/dev/null || echo "0")

    echo "[OK] Auth success events: $AUTH_SUCCESS"
    echo "[OK] Auth failed events: $AUTH_FAILED"
    echo "[OK] Data access events: $DATA_ACCESS"
    echo "[OK] Authorization failure events: $AUTHZ_FAILED"
else
    echo "[WARN] Audit log file not found — check application startup"
fi

echo ""
echo "============================================"
echo "Fix Summary"
echo "============================================"
echo ""
echo "[+] Structured JSON logging enabled (audit.jsonl, app.jsonl)"
echo "[+] Authentication events: success and failure with source IP, user agent"
echo "[+] Data access events: record count, classification level"
echo "[+] Authorization failures: attempted action, actual role"
echo "[+] Every request logged: method, endpoint, response code, duration"
echo "[+] Correlation IDs: trace events across a single request"
echo "[+] Log rotation: daily, 30-day retention"
echo "[+] Splunk inputs.conf + props.conf created for log shipping"
echo "[+] Filebeat config created for Sentinel/ELK integration"
echo "[+] Detection queries created: brute force, data exfiltration, privilege escalation"
echo ""
echo "[*] Run validate.sh to confirm logging is complete."
echo "[*] Evidence saved to: $EVIDENCE_DIR"
