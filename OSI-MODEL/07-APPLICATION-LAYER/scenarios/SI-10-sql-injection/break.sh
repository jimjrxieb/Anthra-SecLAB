#!/usr/bin/env bash
set -euo pipefail

# SI-10 SQL Injection — Break
#
# Deploys a deliberately vulnerable Flask application with string-concatenated
# SQL queries. The app has a /search endpoint that takes user input and injects
# it directly into a SQLite query without parameterization or input validation.
# This simulates the exact vulnerability pattern behind Heartland Payment
# Systems (2008), TalkTalk (2015), and thousands of other SQL injection breaches.
#
# REQUIREMENTS:
#   - Python 3.8+ with pip
#   - Network access to bind a port
#
# USAGE:
#   ./break.sh [port]
#
# EXAMPLE:
#   ./break.sh 5000
#   (Starts vulnerable Flask app on port 5000)
#
# WARNING: This script is for authorized security testing only.
#          Unauthorized use is illegal under the CFAA and equivalent laws.

# --- Argument Validation ---

PORT="${1:-5000}"

if ! [[ "$PORT" =~ ^[0-9]+$ ]] || [[ "$PORT" -lt 1 ]] || [[ "$PORT" -gt 65535 ]]; then
    echo "[ERROR] Invalid port number: $PORT"
    echo "Expected: integer between 1 and 65535"
    exit 1
fi

EVIDENCE_DIR="/tmp/si10-sqli-evidence-$(date +%Y%m%d-%H%M%S)"
APP_DIR="$EVIDENCE_DIR/vuln-app"
mkdir -p "$APP_DIR"

echo "============================================"
echo "SI-10 SQL Injection — Break"
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

# --- Create Vulnerable Application ---

echo "[*] Creating vulnerable Flask application..."

cat > "$APP_DIR/requirements.txt" << 'EOF'
flask==3.0.0
EOF

cat > "$APP_DIR/app.py" << 'PYEOF'
"""
SI-10 Break Scenario: Vulnerable Flask Application

This application contains DELIBERATE SQL injection vulnerabilities for
security testing purposes. DO NOT deploy in production.

Vulnerabilities:
  1. /search — string concatenation in SQL query (classic SQLi)
  2. /login — string concatenation in authentication query (auth bypass)
  3. /user/<id> — unsanitized path parameter in SQL query
  4. No input validation on any endpoint
  5. No WAF or rate limiting
  6. Error messages expose database structure
"""
import sqlite3
import os

from flask import Flask, request, jsonify

app = Flask(__name__)
DB_PATH = os.path.join(os.path.dirname(__file__), "app.db")


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
            role TEXT DEFAULT 'user',
            ssn TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT,
            price REAL,
            category TEXT
        )
    """)

    # Sample data
    cursor.executemany(
        "INSERT OR IGNORE INTO users (id, username, password, email, role, ssn) VALUES (?, ?, ?, ?, ?, ?)",
        [
            (1, "admin", "admin123", "admin@example.com", "admin", "123-45-6789"),
            (2, "jdoe", "password1", "jdoe@example.com", "user", "987-65-4321"),
            (3, "asmith", "letmein", "asmith@example.com", "user", "555-12-3456"),
        ],
    )

    cursor.executemany(
        "INSERT OR IGNORE INTO products (id, name, description, price, category) VALUES (?, ?, ?, ?, ?)",
        [
            (1, "Widget A", "Standard widget", 9.99, "widgets"),
            (2, "Widget B", "Premium widget", 19.99, "widgets"),
            (3, "Gadget X", "Basic gadget", 14.99, "gadgets"),
        ],
    )

    conn.commit()
    conn.close()


@app.route("/")
def index():
    return jsonify({
        "app": "SI-10 Vulnerable App",
        "status": "VULNERABLE",
        "endpoints": [
            "GET /search?q=<term> — product search (SQLi in query param)",
            "POST /login — authentication (SQLi in username/password)",
            "GET /user/<id> — user lookup (SQLi in path param)",
        ],
    })


@app.route("/search")
def search():
    """VULNERABLE: String concatenation in SQL query."""
    query = request.args.get("q", "")

    # VULNERABILITY: Direct string concatenation — classic SQL injection
    # An attacker can input: ' OR '1'='1' --
    # Or: ' UNION SELECT username,password,email,ssn,role FROM users --
    conn = get_db()
    try:
        sql = "SELECT * FROM products WHERE name LIKE '%" + query + "%' OR description LIKE '%" + query + "%'"
        results = conn.execute(sql).fetchall()
        return jsonify({
            "query": query,
            "sql": sql,  # VULNERABILITY: Exposing SQL query in response
            "count": len(results),
            "results": [dict(r) for r in results],
        })
    except Exception as e:
        # VULNERABILITY: Exposing database errors to the user
        return jsonify({"error": str(e), "sql": sql}), 500
    finally:
        conn.close()


@app.route("/login", methods=["POST"])
def login():
    """VULNERABLE: String concatenation in authentication query."""
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # VULNERABILITY: Authentication bypass via SQL injection
    # An attacker can input username: admin' --
    # This comments out the password check entirely
    conn = get_db()
    try:
        sql = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
        user = conn.execute(sql).fetchone()
        if user:
            return jsonify({
                "status": "authenticated",
                "user": dict(user),  # VULNERABILITY: Returns all fields including SSN
                "sql": sql,
            })
        else:
            return jsonify({"status": "failed", "sql": sql}), 401
    except Exception as e:
        return jsonify({"error": str(e), "sql": sql}), 500
    finally:
        conn.close()


@app.route("/user/<user_id>")
def get_user(user_id):
    """VULNERABLE: Unsanitized path parameter in SQL query."""
    conn = get_db()
    try:
        # VULNERABILITY: No type validation, no parameterization
        sql = "SELECT * FROM users WHERE id = " + user_id
        user = conn.execute(sql).fetchone()
        if user:
            return jsonify({"user": dict(user), "sql": sql})
        else:
            return jsonify({"error": "User not found", "sql": sql}), 404
    except Exception as e:
        return jsonify({"error": str(e), "sql": sql}), 500
    finally:
        conn.close()


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
PYEOF

echo "[+] Vulnerable Flask application created"
echo ""

# --- Install Dependencies ---

echo "[*] Setting up Python virtual environment..."
python3 -m venv "$APP_DIR/venv"
source "$APP_DIR/venv/bin/activate"

echo "[*] Installing Flask..."
pip install -q flask==3.0.0 2>&1 | tail -1 || true
echo "[+] Dependencies installed"
echo ""

# --- Start the Vulnerable Application ---

echo "[*] Initializing database and starting vulnerable application..."
export PORT="$PORT"

cd "$APP_DIR"
nohup "$APP_DIR/venv/bin/python" "$APP_DIR/app.py" > "$EVIDENCE_DIR/app.log" 2>&1 &
APP_PID=$!
echo "$APP_PID" > "$EVIDENCE_DIR/app.pid"

# Wait for startup
sleep 2

# Verify it is running
if kill -0 "$APP_PID" 2>/dev/null; then
    echo "[+] Vulnerable application started (PID: $APP_PID)"
    echo "[*] To stop: kill $APP_PID"
else
    echo "[ERROR] Application failed to start. Check $EVIDENCE_DIR/app.log"
    exit 1
fi

echo ""

# --- Save Evidence ---

echo "[*] Saving vulnerable source code as evidence..."
cp "$APP_DIR/app.py" "$EVIDENCE_DIR/vuln-app-source.py"

# Test the endpoint
echo "[*] Testing vulnerable endpoint..."
RESPONSE=$(curl -s "http://localhost:$PORT/" 2>/dev/null || echo "Connection failed")
echo "$RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$RESPONSE"
echo ""

echo "============================================"
echo "Break Summary"
echo "============================================"
echo ""
echo "[!] Vulnerable Flask application is running on port $PORT"
echo "[!] SQL injection in /search endpoint (string concatenation)"
echo "[!] SQL injection in /login endpoint (authentication bypass)"
echo "[!] SQL injection in /user/<id> endpoint (path parameter)"
echo "[!] Database error messages exposed to users"
echo "[!] SQL queries exposed in API responses"
echo "[!] No input validation on any endpoint"
echo "[!] Sensitive data (SSN) in database accessible via UNION attacks"
echo ""
echo "[*] This application is vulnerable to:"
echo "    - Classic SQL injection via search parameter"
echo "    - Authentication bypass via login injection"
echo "    - UNION-based data exfiltration (user SSNs, passwords)"
echo "    - Error-based SQL injection (database structure revealed)"
echo "    - Blind SQL injection via boolean and time-based techniques"
echo ""
echo "[*] Example attack: curl 'http://localhost:$PORT/search?q=%27%20OR%201=1%20--'"
echo "[*] Example UNION:  curl 'http://localhost:$PORT/search?q=%27%20UNION%20SELECT%201,username,password,ssn,role%20FROM%20users%20--'"
echo ""
echo "[*] Run detect.sh to confirm the exposure, then fix.sh to remediate."
echo "[*] Evidence saved to: $EVIDENCE_DIR"
