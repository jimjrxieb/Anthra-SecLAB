#!/usr/bin/env bash
set -euo pipefail

# AU-2 Missing Audit Logging — Break
#
# Disables application audit logging to simulate a production environment
# with no visibility into security-relevant events. Renames log configuration,
# sets log level to CRITICAL (suppressing auth events, failed logins, data
# access), and removes structured logging. This simulates the blind spot that
# allowed SolarWinds (2020) to go undetected for 14 months.
#
# REQUIREMENTS:
#   - Python 3.8+ with pip
#   - Network access to bind a port
#
# USAGE:
#   ./break.sh [port]
#
# EXAMPLE:
#   ./break.sh 5001
#   (Starts application with logging disabled on port 5001)
#
# WARNING: This script is for authorized security testing only.
#          Unauthorized use is illegal under the CFAA and equivalent laws.

# --- Argument Validation ---

PORT="${1:-5001}"

if ! [[ "$PORT" =~ ^[0-9]+$ ]] || [[ "$PORT" -lt 1 ]] || [[ "$PORT" -gt 65535 ]]; then
    echo "[ERROR] Invalid port number: $PORT"
    echo "Expected: integer between 1 and 65535"
    exit 1
fi

EVIDENCE_DIR="/tmp/au2-logging-evidence-$(date +%Y%m%d-%H%M%S)"
APP_DIR="$EVIDENCE_DIR/unlogged-app"
mkdir -p "$APP_DIR"

echo "============================================"
echo "AU-2 Missing Audit Logging — Break"
echo "============================================"
echo ""
echo "[*] Port:         $PORT"
echo "[*] Evidence dir: $EVIDENCE_DIR"
echo "[*] App dir:      $APP_DIR"
echo ""

# --- Record Pre-Break State ---

echo "[*] Recording pre-break state..."
echo "Break started: $(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$EVIDENCE_DIR/timeline.txt"
echo ""

# --- Create Application With Logging Disabled ---

echo "[*] Creating application with audit logging disabled..."

cat > "$APP_DIR/requirements.txt" << 'EOF'
flask==3.0.0
EOF

cat > "$APP_DIR/app.py" << 'PYEOF'
"""
AU-2 Break Scenario: Application With No Audit Logging

This application has DELIBERATELY disabled logging to simulate a production
environment with zero security visibility. DO NOT deploy in production.

Missing controls:
  1. No authentication event logging (login success/failure)
  2. No data access logging (who accessed what, when)
  3. No authorization failure logging (privilege escalation attempts)
  4. Log level set to CRITICAL — only crashes are logged
  5. No structured logging format (no JSON, no parseable fields)
  6. No log shipping to SIEM (Splunk/Sentinel)
  7. No alerting on suspicious patterns
"""
import logging
import sqlite3
import os

from flask import Flask, request, jsonify

app = Flask(__name__)
DB_PATH = os.path.join(os.path.dirname(__file__), "app.db")

# VULNERABILITY: Log level set to CRITICAL — suppresses all security events
logging.basicConfig(level=logging.CRITICAL)
logger = logging.getLogger(__name__)
logger.setLevel(logging.CRITICAL)

# VULNERABILITY: Disable Flask's request logging entirely
log = logging.getLogger("werkzeug")
log.setLevel(logging.CRITICAL)


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
    # VULNERABILITY: No request logging
    return jsonify({
        "app": "AU-2 Unlogged App",
        "status": "NO LOGGING",
        "endpoints": [
            "POST /login — authentication (no login logging)",
            "GET /data — sensitive data access (no access logging)",
            "POST /admin/action — admin action (no authorization logging)",
        ],
    })


@app.route("/login", methods=["POST"])
def login():
    """Authentication endpoint with NO logging."""
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    conn = get_db()
    try:
        user = conn.execute(
            "SELECT * FROM users WHERE username = ? AND password = ?",
            (username, password),
        ).fetchone()

        if user:
            # VULNERABILITY: Successful login — not logged
            # An attacker who compromises credentials operates invisibly
            return jsonify({
                "status": "authenticated",
                "user": {"id": user["id"], "username": user["username"], "role": user["role"]},
            })
        else:
            # VULNERABILITY: Failed login — not logged
            # Brute force attacks are invisible — no alerts fire
            return jsonify({"status": "failed"}), 401
    finally:
        conn.close()


@app.route("/data")
def get_data():
    """Sensitive data access with NO logging."""
    # VULNERABILITY: Data access is not logged
    # An attacker exfiltrating data leaves no trace
    conn = get_db()
    try:
        records = conn.execute("SELECT * FROM sensitive_data").fetchall()
        return jsonify({
            "count": len(records),
            "records": [dict(r) for r in records],
        })
    finally:
        conn.close()


@app.route("/admin/action", methods=["POST"])
def admin_action():
    """Admin action with NO authorization logging."""
    action = request.form.get("action", "")
    user_role = request.form.get("role", "viewer")

    if user_role != "admin":
        # VULNERABILITY: Authorization failure — not logged
        # Privilege escalation attempts are invisible
        return jsonify({"error": "Forbidden"}), 403

    # VULNERABILITY: Admin actions — not logged
    # Destructive actions leave no audit trail
    return jsonify({"status": "action executed", "action": action})


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5001)), debug=False)
PYEOF

echo "[+] Application created with logging disabled"
echo ""

# --- Disable Any Existing Log Config ---

echo "[*] Ensuring no log configuration files exist..."

# Create a disabled log config to show what "broken" looks like
cat > "$APP_DIR/logging.conf.disabled" << 'EOF'
# DISABLED: This log config has been renamed to .disabled
# No logging is active. All security events are invisible.
# This file was renamed by AU-2 break.sh to simulate a misconfigured environment.
[loggers]
keys=root

[handlers]
keys=

[formatters]
keys=

[logger_root]
level=CRITICAL
handlers=
EOF

echo "[+] Log configuration disabled"
echo ""

# --- Install Dependencies and Start ---

echo "[*] Setting up Python virtual environment..."
python3 -m venv "$APP_DIR/venv"
source "$APP_DIR/venv/bin/activate"

echo "[*] Installing Flask..."
pip install -q flask==3.0.0 2>&1 | tail -1 || true
echo "[+] Dependencies installed"
echo ""

echo "[*] Starting application with logging disabled..."
export PORT="$PORT"

cd "$APP_DIR"
nohup "$APP_DIR/venv/bin/python" "$APP_DIR/app.py" > "$EVIDENCE_DIR/app.log" 2>&1 &
APP_PID=$!
echo "$APP_PID" > "$EVIDENCE_DIR/app.pid"

sleep 2

if kill -0 "$APP_PID" 2>/dev/null; then
    echo "[+] Unlogged application started (PID: $APP_PID)"
    echo "[*] To stop: kill $APP_PID"
else
    echo "[ERROR] Application failed to start. Check $EVIDENCE_DIR/app.log"
    exit 1
fi
echo ""

# --- Generate Activity That Should Be Logged But Is Not ---

echo "[*] Generating security events that would normally be logged..."

# Successful login
curl -s -X POST "http://localhost:$PORT/login" -d "username=admin&password=admin123" > /dev/null 2>&1 || true
echo "  [!] Successful admin login — NOT LOGGED"

# Failed login attempts (brute force pattern)
for i in 1 2 3 4 5; do
    curl -s -X POST "http://localhost:$PORT/login" -d "username=admin&password=wrong$i" > /dev/null 2>&1 || true
done
echo "  [!] 5 failed login attempts (brute force) — NOT LOGGED"

# Sensitive data access
curl -s "http://localhost:$PORT/data" > /dev/null 2>&1 || true
echo "  [!] Sensitive data accessed (PII, financial, PHI) — NOT LOGGED"

# Authorization failure (privilege escalation attempt)
curl -s -X POST "http://localhost:$PORT/admin/action" -d "action=delete_all&role=viewer" > /dev/null 2>&1 || true
echo "  [!] Privilege escalation attempt (viewer -> admin) — NOT LOGGED"

echo ""
echo "[*] Checking app.log for any evidence of these events..."
LOG_LINES=$(wc -l < "$EVIDENCE_DIR/app.log" 2>/dev/null || echo "0")
echo "[!] App log has $LOG_LINES lines — expected 0 security event entries"
echo ""

echo "============================================"
echo "Break Summary"
echo "============================================"
echo ""
echo "[!] Application is running on port $PORT with NO audit logging"
echo "[!] Log level set to CRITICAL — only crashes are visible"
echo "[!] Authentication events (success/failure) are NOT logged"
echo "[!] Data access events are NOT logged"
echo "[!] Authorization failures are NOT logged"
echo "[!] Admin actions are NOT logged"
echo "[!] No structured logging format (no JSON, no SIEM-parseable output)"
echo "[!] No log shipping to Splunk/Sentinel"
echo "[!] No alerting rules for suspicious patterns"
echo ""
echo "[*] This configuration means:"
echo "    - Brute force attacks are invisible (SolarWinds went 14 months undetected)"
echo "    - Data exfiltration leaves no trace"
echo "    - Privilege escalation attempts cannot be reviewed"
echo "    - Incident response is impossible — no evidence exists"
echo "    - Compliance audit will fail (AU-2 requires event logging)"
echo ""
echo "[*] Run detect.sh to confirm the logging gaps, then fix.sh to remediate."
echo "[*] Evidence saved to: $EVIDENCE_DIR"
