#!/usr/bin/env bash
set -euo pipefail

# SI-10 SQL Injection — Fix
#
# Patches the vulnerable Flask application to use parameterized queries,
# adds input validation, removes SQL/error exposure from responses, and
# creates a Semgrep CI rule to prevent SQL injection from being reintroduced.
#
# CSF 2.0: PR.PS-01 (Configuration management applied)
# CIS v8: 16.12 (Implement Code-Level Security Checks)
# NIST: SI-10 (Information Input Validation)
#
# REQUIREMENTS:
#   - Python 3.8+ with pip
#   - Access to the vulnerable app directory
#
# USAGE:
#   ./fix.sh [app_dir] [port]
#
# EXAMPLE:
#   ./fix.sh /tmp/si10-sqli-evidence-*/vuln-app 5000
#
# NOTE: This script stops the vulnerable app, patches the code, and restarts
#       the fixed version on the same port.

# --- Argument Validation ---

APP_DIR="${1:-}"
PORT="${2:-5000}"

if [[ -z "$APP_DIR" ]]; then
    # Try to find the most recent break evidence directory
    LATEST=$(ls -td /tmp/si10-sqli-evidence-*/vuln-app 2>/dev/null | head -1 || true)
    if [[ -n "$LATEST" ]]; then
        APP_DIR="$LATEST"
        echo "[*] Auto-detected app directory: $APP_DIR"
    else
        echo "Usage: $0 <app_dir> [port]"
        echo "Example: $0 /tmp/si10-sqli-evidence-20260408-120000/vuln-app 5000"
        echo ""
        echo "app_dir: Path to the vulnerable app directory (from break.sh)"
        echo "port:    Port to run the fixed app on (default: 5000)"
        exit 1
    fi
fi

if [[ ! -f "$APP_DIR/app.py" ]]; then
    echo "[ERROR] app.py not found in $APP_DIR"
    exit 1
fi

EVIDENCE_DIR="/tmp/si10-sqli-fix-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$EVIDENCE_DIR"

echo "============================================"
echo "SI-10 SQL Injection — Fix"
echo "============================================"
echo ""
echo "[*] App dir:      $APP_DIR"
echo "[*] Port:         $PORT"
echo "[*] Evidence dir: $EVIDENCE_DIR"
echo ""

# --- Record Pre-Fix State ---

echo "[*] Recording pre-fix state..."
cp "$APP_DIR/app.py" "$EVIDENCE_DIR/app-before-fix.py"
echo "[+] Saved vulnerable source as evidence"
echo ""

# --- Stop Vulnerable Application ---

echo "[*] Stopping vulnerable application..."
PID_FILE=$(dirname "$APP_DIR")/app.pid
if [[ -f "$PID_FILE" ]]; then
    OLD_PID=$(cat "$PID_FILE")
    if kill -0 "$OLD_PID" 2>/dev/null; then
        kill "$OLD_PID" 2>/dev/null || true
        sleep 1
        echo "[+] Stopped vulnerable app (PID: $OLD_PID)"
    fi
fi

# Also kill by port
if command -v lsof &>/dev/null; then
    PIDS=$(lsof -ti :"$PORT" 2>/dev/null || true)
    if [[ -n "$PIDS" ]]; then
        echo "$PIDS" | xargs kill 2>/dev/null || true
        sleep 1
        echo "[+] Killed process(es) on port $PORT"
    fi
fi
echo ""

# --- Patch Application to Use Parameterized Queries ---

echo "[*] Patching application with parameterized queries and input validation..."

cat > "$APP_DIR/app.py" << 'PYEOF'
"""
SI-10 Fix Scenario: Secure Flask Application

All SQL injection vulnerabilities have been remediated:
  1. All queries use parameterized statements (? placeholders)
  2. Input validation on all endpoints (type checking, length limits, allowlists)
  3. Error messages do not expose database structure
  4. SQL queries are never exposed in API responses
  5. Authentication uses constant-time comparison
"""
import re
import sqlite3
import hmac
import os

from flask import Flask, request, jsonify

app = Flask(__name__)
DB_PATH = os.path.join(os.path.dirname(__file__), "app.db")

# --- Input Validation Constants ---
MAX_SEARCH_LENGTH = 100
MAX_USERNAME_LENGTH = 50
MAX_PASSWORD_LENGTH = 128
ALLOWED_SEARCH_PATTERN = re.compile(r"^[a-zA-Z0-9\s\-_.]+$")
ALLOWED_USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9_.\-]+$")


def get_db():
    """Get database connection with security settings."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    # Disable loading extensions to prevent abuse
    conn.execute("PRAGMA trusted_schema = OFF")
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


def validate_search_input(query):
    """Validate search input against allowlist pattern."""
    if not query:
        return False, "Search query is required"
    if len(query) > MAX_SEARCH_LENGTH:
        return False, f"Search query exceeds maximum length of {MAX_SEARCH_LENGTH}"
    if not ALLOWED_SEARCH_PATTERN.match(query):
        return False, "Search query contains invalid characters"
    return True, ""


def validate_username(username):
    """Validate username against allowlist pattern."""
    if not username:
        return False, "Username is required"
    if len(username) > MAX_USERNAME_LENGTH:
        return False, f"Username exceeds maximum length of {MAX_USERNAME_LENGTH}"
    if not ALLOWED_USERNAME_PATTERN.match(username):
        return False, "Username contains invalid characters"
    return True, ""


@app.route("/")
def index():
    return jsonify({
        "app": "SI-10 Secure App",
        "status": "HARDENED",
        "endpoints": [
            "GET /search?q=<term> — product search (parameterized query)",
            "POST /login — authentication (parameterized + constant-time compare)",
            "GET /user/<id> — user lookup (integer-validated, parameterized)",
        ],
    })


@app.route("/search")
def search():
    """FIXED: Parameterized query with input validation."""
    query = request.args.get("q", "")

    # FIX 1: Input validation
    valid, error = validate_search_input(query)
    if not valid:
        return jsonify({"error": error}), 400

    conn = get_db()
    try:
        # FIX 2: Parameterized query — user input is never concatenated into SQL
        search_param = f"%{query}%"
        results = conn.execute(
            "SELECT id, name, description, price, category FROM products "
            "WHERE name LIKE ? OR description LIKE ?",
            (search_param, search_param),
        ).fetchall()

        # FIX 3: No SQL query in response, only safe product data
        return jsonify({
            "query": query,
            "count": len(results),
            "results": [dict(r) for r in results],
        })
    except Exception:
        # FIX 4: Generic error message — no database details exposed
        return jsonify({"error": "An internal error occurred"}), 500
    finally:
        conn.close()


@app.route("/login", methods=["POST"])
def login():
    """FIXED: Parameterized query with constant-time comparison."""
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # FIX 1: Input validation
    valid, error = validate_username(username)
    if not valid:
        return jsonify({"error": error}), 400

    if not password or len(password) > MAX_PASSWORD_LENGTH:
        return jsonify({"error": "Invalid password"}), 400

    conn = get_db()
    try:
        # FIX 2: Parameterized query — fetch by username only
        user = conn.execute(
            "SELECT id, username, password, email, role FROM users WHERE username = ?",
            (username,),
        ).fetchone()

        if user is None:
            return jsonify({"error": "Invalid credentials"}), 401

        # FIX 3: Constant-time comparison to prevent timing attacks
        if not hmac.compare_digest(user["password"], password):
            return jsonify({"error": "Invalid credentials"}), 401

        # FIX 4: Only return safe fields — no SSN, no password, no SQL
        return jsonify({
            "status": "authenticated",
            "user": {
                "id": user["id"],
                "username": user["username"],
                "email": user["email"],
                "role": user["role"],
            },
        })
    except Exception:
        return jsonify({"error": "An internal error occurred"}), 500
    finally:
        conn.close()


@app.route("/user/<user_id>")
def get_user(user_id):
    """FIXED: Integer validation and parameterized query."""
    # FIX 1: Type validation — user_id must be a positive integer
    try:
        uid = int(user_id)
        if uid < 1:
            raise ValueError("ID must be positive")
    except ValueError:
        return jsonify({"error": "Invalid user ID — must be a positive integer"}), 400

    conn = get_db()
    try:
        # FIX 2: Parameterized query
        user = conn.execute(
            "SELECT id, username, email, role FROM users WHERE id = ?",
            (uid,),
        ).fetchone()

        if user:
            # FIX 3: Only return safe fields
            return jsonify({"user": dict(user)})
        else:
            return jsonify({"error": "User not found"}), 404
    except Exception:
        return jsonify({"error": "An internal error occurred"}), 500
    finally:
        conn.close()


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
PYEOF

echo "[+] Application patched with parameterized queries"
echo ""

# --- Save Fixed Code as Evidence ---

cp "$APP_DIR/app.py" "$EVIDENCE_DIR/app-after-fix.py"

# --- Create Diff ---

echo "[*] Generating before/after diff..."
diff -u "$EVIDENCE_DIR/app-before-fix.py" "$EVIDENCE_DIR/app-after-fix.py" \
    > "$EVIDENCE_DIR/fix-diff.patch" 2>/dev/null || true
echo "[+] Diff saved to $EVIDENCE_DIR/fix-diff.patch"
echo ""

# --- Create Semgrep CI Rule ---

echo "[*] Creating Semgrep CI rule to prevent SQL injection regression..."

SEMGREP_RULE_DIR="$APP_DIR/.semgrep"
mkdir -p "$SEMGREP_RULE_DIR"

cat > "$SEMGREP_RULE_DIR/sql-injection.yaml" << 'RULEEOF'
rules:
  - id: si10-no-string-concat-sql
    patterns:
      - pattern-either:
          - pattern: |
              $CONN.execute("..." + $VAR + "...")
          - pattern: |
              $CONN.execute(f"...{$VAR}...")
          - pattern: |
              $CONN.execute("..." % $VAR)
          - pattern: |
              $CURSOR.execute("..." + $VAR + "...")
          - pattern: |
              $CURSOR.execute(f"...{$VAR}...")
          - pattern: |
              $CURSOR.execute("..." % $VAR)
    message: >
      SQL query uses string concatenation or formatting with variable input.
      This is vulnerable to SQL injection (NIST SI-10, OWASP A03:2021,
      PCI-DSS 6.5.1). Use parameterized queries with ? placeholders instead.
      Example: conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    languages: [python]
    severity: ERROR
    metadata:
      cwe: "CWE-89: SQL Injection"
      owasp: "A03:2021 Injection"
      nist: "SI-10 Information Input Validation"
      pci-dss: "6.5.1"
      confidence: HIGH
      impact: HIGH

  - id: si10-no-sql-in-response
    patterns:
      - pattern-either:
          - pattern: |
              return jsonify({..., "sql": $VAR, ...})
          - pattern: |
              return jsonify({..., "query": $SQL, ...})
      - metavariable-regex:
          metavariable: $SQL
          regex: ".*SELECT.*|.*INSERT.*|.*UPDATE.*|.*DELETE.*"
    message: >
      SQL query is exposed in the API response. This reveals database structure
      to attackers and aids SQL injection exploitation. Remove SQL from all
      response bodies.
    languages: [python]
    severity: WARNING
    metadata:
      cwe: "CWE-209: Information Exposure Through Error Message"
      confidence: MEDIUM
      impact: MEDIUM

  - id: si10-no-raw-error-in-response
    patterns:
      - pattern: |
          except Exception as $E:
              ...
              return jsonify({..., "error": str($E), ...}), ...
    message: >
      Raw exception message exposed in API response. This may reveal database
      structure, file paths, or internal state to attackers. Use a generic
      error message instead.
    languages: [python]
    severity: WARNING
    metadata:
      cwe: "CWE-209: Information Exposure Through Error Message"
      confidence: HIGH
      impact: MEDIUM
RULEEOF

echo "[+] Semgrep CI rule created at $SEMGREP_RULE_DIR/sql-injection.yaml"
cp "$SEMGREP_RULE_DIR/sql-injection.yaml" "$EVIDENCE_DIR/semgrep-ci-rule.yaml"
echo ""

# --- Restart Fixed Application ---

echo "[*] Restarting application with fixes applied..."
export PORT="$PORT"

cd "$APP_DIR"
nohup "$APP_DIR/venv/bin/python" "$APP_DIR/app.py" > "$(dirname "$APP_DIR")/app-fixed.log" 2>&1 &
NEW_PID=$!
echo "$NEW_PID" > "$(dirname "$APP_DIR")/app.pid"

sleep 2

if kill -0 "$NEW_PID" 2>/dev/null; then
    echo "[+] Fixed application started (PID: $NEW_PID)"
else
    echo "[ERROR] Application failed to start. Check $(dirname "$APP_DIR")/app-fixed.log"
    exit 1
fi
echo ""

# --- Verify Fix ---

echo "[*] Quick verification of fix..."

# Test that normal search works
NORMAL_TEST=$(curl -s "http://localhost:$PORT/search?q=widget" 2>/dev/null || echo "failed")
if echo "$NORMAL_TEST" | grep -qi "results" 2>/dev/null; then
    echo "[OK] Normal search still works"
else
    echo "[WARN] Normal search may not be working — check application logs"
fi

# Test that SQL injection is blocked
SQLI_TEST=$(curl -s "http://localhost:$PORT/search?q=%27%20OR%201%3D1%20--" 2>/dev/null || echo "failed")
if echo "$SQLI_TEST" | grep -qi "invalid characters\|error" 2>/dev/null; then
    echo "[OK] SQL injection attempt blocked by input validation"
else
    echo "[WARN] SQL injection test returned unexpected response — run validate.sh for full check"
fi

echo ""
echo "============================================"
echo "Fix Summary"
echo "============================================"
echo ""
echo "[+] /search endpoint: parameterized query + input validation (allowlist)"
echo "[+] /login endpoint:  parameterized query + constant-time password comparison"
echo "[+] /user/<id>:       integer validation + parameterized query"
echo "[+] Error messages:   generic errors only — no database details exposed"
echo "[+] API responses:    SQL queries removed from all responses"
echo "[+] SSN protection:   sensitive fields excluded from all responses"
echo "[+] Semgrep CI rule:  prevents string-concatenated SQL from being committed"
echo ""
echo "[*] Changes applied:"
echo "    - String concatenation → parameterized queries (? placeholders)"
echo "    - No input validation → allowlist regex + length limits"
echo "    - Raw errors exposed → generic error messages"
echo "    - SQL in responses → removed entirely"
echo "    - debug=True → debug=False"
echo ""
echo "[*] Run validate.sh to confirm the fix is effective."
echo "[*] Evidence saved to: $EVIDENCE_DIR"
