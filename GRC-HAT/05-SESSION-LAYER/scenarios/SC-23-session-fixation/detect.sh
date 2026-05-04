#!/usr/bin/env bash
set -euo pipefail

# SC-23 Session Fixation — Detect
#
# Detects session fixation vulnerabilities by:
#   1. Capturing the session cookie before authentication
#   2. Performing a login request
#   3. Checking if the session cookie changed after authentication
#   4. Testing if externally-set session IDs are accepted
#
# REQUIREMENTS:
#   - curl
#   - A target application with a login endpoint
#
# USAGE:
#   ./detect.sh <target_url> <login_endpoint> [username] [password]
#
# EXAMPLE:
#   ./detect.sh http://localhost:8080 /login testuser testpass
#   ./detect.sh https://app.example.com /api/auth/login admin admin123
#
# WARNING: This script is for authorized security testing only.
#          Unauthorized use is illegal under the CFAA and equivalent laws.
#
# CSF 2.0: PR.AA-03 (Users and services authenticated)
# CIS v8: 16.8 (Separate Production and Non-Production)
# NIST: SC-23 (Session Authenticity)
#

# --- Argument Validation ---

if [[ $# -lt 2 ]]; then
    echo "Usage: $0 <target_url> <login_endpoint> [username] [password]"
    echo "Example: $0 http://localhost:8080 /login testuser testpass"
    echo ""
    echo "target_url:      Base URL of the application"
    echo "login_endpoint:  Path to the login endpoint (e.g., /login, /api/auth)"
    echo "username:        Test username (default: testuser)"
    echo "password:        Test password (default: testpass)"
    exit 1
fi

TARGET="$1"
LOGIN_PATH="$2"
USERNAME="${3:-testuser}"
PASSWORD="${4:-testpass}"
LOGIN_URL="${TARGET}${LOGIN_PATH}"

EVIDENCE_DIR="/tmp/sc23-session-fixation-detect-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$EVIDENCE_DIR"

echo "============================================"
echo "SC-23 Session Fixation — Detection"
echo "============================================"
echo ""
echo "[*] Target:       $TARGET"
echo "[*] Login URL:    $LOGIN_URL"
echo "[*] Username:     $USERNAME"
echo "[*] Evidence dir: $EVIDENCE_DIR"
echo ""

FINDINGS=0

# --- Method 1: Session Cookie Comparison (Before/After Login) ---

echo "[*] Method 1: Session cookie comparison — before and after login"
echo "----------------------------------------------"

if command -v curl &>/dev/null; then
    # Step 1: Get initial session cookie (before authentication)
    echo "[*] Step 1: Requesting initial page to get pre-auth session cookie..."
    COOKIE_JAR_BEFORE="$EVIDENCE_DIR/cookies-before.jar"
    curl -s -c "$COOKIE_JAR_BEFORE" -D "$EVIDENCE_DIR/headers-before.txt" \
        "$TARGET" > /dev/null 2>&1 || true

    # Extract session cookie value
    PRE_AUTH_COOKIE=$(grep -v "^#" "$COOKIE_JAR_BEFORE" 2>/dev/null | \
        grep -iE "session|sid|token|jsessionid|phpsessid|connect\.sid|__host" | \
        awk '{print $NF}' | head -1 || echo "")

    if [[ -n "$PRE_AUTH_COOKIE" ]]; then
        echo "[+] Pre-auth session cookie: ${PRE_AUTH_COOKIE:0:20}..."
        echo "$PRE_AUTH_COOKIE" > "$EVIDENCE_DIR/pre-auth-cookie.txt"
    else
        echo "[INFO] No session cookie set on initial request"
        echo "[INFO] Application may only set cookies at login — testing with login request"
    fi

    # Step 2: Perform login with the existing cookie
    echo "[*] Step 2: Performing login with credentials..."
    COOKIE_JAR_AFTER="$EVIDENCE_DIR/cookies-after.jar"

    # Try form-based login first
    curl -s -b "$COOKIE_JAR_BEFORE" -c "$COOKIE_JAR_AFTER" \
        -D "$EVIDENCE_DIR/headers-after-login.txt" \
        -d "username=$USERNAME&password=$PASSWORD" \
        -X POST "$LOGIN_URL" > /dev/null 2>&1 || true

    # Extract post-auth session cookie
    POST_AUTH_COOKIE=$(grep -v "^#" "$COOKIE_JAR_AFTER" 2>/dev/null | \
        grep -iE "session|sid|token|jsessionid|phpsessid|connect\.sid|__host" | \
        awk '{print $NF}' | head -1 || echo "")

    # Also check Set-Cookie in login response headers
    LOGIN_SET_COOKIE=$(grep -i "set-cookie" "$EVIDENCE_DIR/headers-after-login.txt" 2>/dev/null || echo "")

    if [[ -n "$POST_AUTH_COOKIE" ]]; then
        echo "[+] Post-auth session cookie: ${POST_AUTH_COOKIE:0:20}..."
        echo "$POST_AUTH_COOKIE" > "$EVIDENCE_DIR/post-auth-cookie.txt"
    else
        echo "[INFO] No session cookie found after login"
    fi

    # Step 3: Compare cookies
    echo ""
    echo "[*] Step 3: Comparing pre-auth and post-auth session cookies..."

    if [[ -n "$PRE_AUTH_COOKIE" ]] && [[ -n "$POST_AUTH_COOKIE" ]]; then
        if [[ "$PRE_AUTH_COOKIE" == "$POST_AUTH_COOKIE" ]]; then
            echo "[ALERT] Session cookie DID NOT CHANGE after login!"
            echo "[ALERT] Pre-auth:  $PRE_AUTH_COOKIE"
            echo "[ALERT] Post-auth: $POST_AUTH_COOKIE"
            echo "[ALERT] This is a session fixation vulnerability (CWE-384)"
            FINDINGS=$((FINDINGS + 1))
        else
            echo "[OK] Session cookie changed after login — session was regenerated"
            echo "[*] Pre-auth:  ${PRE_AUTH_COOKIE:0:20}..."
            echo "[*] Post-auth: ${POST_AUTH_COOKIE:0:20}..."
        fi
    elif [[ -z "$PRE_AUTH_COOKIE" ]] && [[ -n "$POST_AUTH_COOKIE" ]]; then
        echo "[OK] No pre-auth cookie existed — session created at login (acceptable)"
    elif [[ -z "$LOGIN_SET_COOKIE" ]] && [[ -n "$PRE_AUTH_COOKIE" ]]; then
        echo "[ALERT] Login response has no Set-Cookie header but pre-auth cookie exists"
        echo "[ALERT] Session was likely NOT regenerated"
        FINDINGS=$((FINDINGS + 1))
    else
        echo "[INFO] Could not determine session behavior — manual testing required"
    fi

    # Check if login response includes Set-Cookie
    echo ""
    echo "[*] Checking login response for Set-Cookie header..."
    if [[ -n "$LOGIN_SET_COOKIE" ]]; then
        echo "[+] Login response includes Set-Cookie:"
        echo "    $LOGIN_SET_COOKIE"
    else
        echo "[WARN] Login response does NOT include Set-Cookie header"
        echo "[WARN] If a pre-auth session existed, this indicates missing session regeneration"
    fi
else
    echo "[SKIP] curl not installed"
fi
echo ""

# --- Method 2: External Session ID Injection ---

echo "[*] Method 2: External session ID injection test"
echo "----------------------------------------------"

if command -v curl &>/dev/null; then
    echo "[*] Testing if application accepts an externally-set session cookie..."

    # Generate a fake session ID
    FAKE_SESSION="attacker-controlled-$(date +%s)-fixation-test"
    echo "[*] Injecting fake session ID: $FAKE_SESSION"

    # Try to set the cookie and see if the app accepts it
    INJECT_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" \
        -b "session_id=$FAKE_SESSION" \
        "$TARGET" 2>/dev/null || echo "000")

    INJECT_HEADERS=$(curl -si -b "session_id=$FAKE_SESSION" \
        "$TARGET" 2>/dev/null || echo "")

    # Check if the server echoed back our fake session ID
    if echo "$INJECT_HEADERS" | grep -qi "$FAKE_SESSION"; then
        echo "[ALERT] Server accepted and echoed back the injected session ID!"
        echo "[ALERT] Application is vulnerable to session fixation via cookie injection"
        FINDINGS=$((FINDINGS + 1))
    else
        echo "[OK] Server did not echo back the injected session ID"
    fi

    # Also try URL-based session ID injection
    echo "[*] Testing URL-based session ID injection..."
    URL_INJECT=$(curl -s -o /dev/null -w "%{http_code}" \
        "${TARGET}?JSESSIONID=$FAKE_SESSION" 2>/dev/null || echo "000")
    URL_INJECT2=$(curl -s -o /dev/null -w "%{http_code}" \
        "${TARGET};jsessionid=$FAKE_SESSION" 2>/dev/null || echo "000")

    if [[ "$URL_INJECT" == "200" ]] || [[ "$URL_INJECT2" == "200" ]]; then
        echo "[WARN] Application accepts URL-based session IDs (check if session is actually used)"
    else
        echo "[OK] URL-based session ID injection returned non-200 status"
    fi

    echo "$INJECT_HEADERS" > "$EVIDENCE_DIR/injection-test.txt" 2>/dev/null || true
else
    echo "[SKIP] curl not installed"
fi
echo ""

# --- Method 3: Session Cookie Attribute Analysis ---

echo "[*] Method 3: Session cookie security attributes"
echo "----------------------------------------------"

if [[ -f "$EVIDENCE_DIR/headers-before.txt" ]] || [[ -f "$EVIDENCE_DIR/headers-after-login.txt" ]]; then
    HEADER_FILE="$EVIDENCE_DIR/headers-after-login.txt"
    [[ -f "$HEADER_FILE" ]] || HEADER_FILE="$EVIDENCE_DIR/headers-before.txt"

    COOKIES=$(grep -i "set-cookie" "$HEADER_FILE" 2>/dev/null || echo "")

    if [[ -n "$COOKIES" ]]; then
        echo "[*] Analyzing session cookie attributes..."
        echo "$COOKIES" | tee "$EVIDENCE_DIR/cookie-attributes.txt"
        echo ""

        # Check for __Host- prefix (strongest cookie protection)
        if echo "$COOKIES" | grep -q "__Host-"; then
            echo "  [OK] Cookie uses __Host- prefix (origin-bound)"
        else
            echo "  [WARN] Cookie does not use __Host- prefix"
        fi

        # Check for HttpOnly
        if echo "$COOKIES" | grep -qi "httponly"; then
            echo "  [OK] HttpOnly flag present"
        else
            echo "  [ALERT] HttpOnly flag MISSING — cookie accessible via JavaScript"
            FINDINGS=$((FINDINGS + 1))
        fi

        # Check for Secure
        if echo "$COOKIES" | grep -qi "secure"; then
            echo "  [OK] Secure flag present"
        else
            echo "  [ALERT] Secure flag MISSING — cookie sent over HTTP"
            FINDINGS=$((FINDINGS + 1))
        fi

        # Check for SameSite
        if echo "$COOKIES" | grep -qi "samesite=strict\|samesite=lax"; then
            echo "  [OK] SameSite attribute set"
        else
            echo "  [ALERT] SameSite attribute MISSING — cross-site request possible"
            FINDINGS=$((FINDINGS + 1))
        fi

        # Check for Path restriction
        if echo "$COOKIES" | grep -qi "path=/"; then
            echo "  [OK] Path attribute set"
        else
            echo "  [WARN] Path attribute not explicitly set"
        fi
    else
        echo "[INFO] No Set-Cookie headers found in responses"
    fi
else
    echo "[INFO] No response headers captured — run with a reachable target"
fi
echo ""

# --- Method 4: Burp Suite / OWASP ZAP Reference ---

echo "[*] Method 4: Manual testing tools reference"
echo "----------------------------------------------"
echo ""
echo "[*] For deeper analysis, use Burp Suite Community Edition:"
echo "    1. Configure browser to proxy through Burp (127.0.0.1:8080)"
echo "    2. Navigate to the login page — note the session cookie in Burp"
echo "    3. Log in — check if Burp shows a new Set-Cookie header"
echo "    4. Compare session IDs: if identical, session fixation is confirmed"
echo ""
echo "[*] OWASP ZAP automated scan:"
echo "    zap-cli quick-scan --self-contained -t $TARGET"
echo "    Look for alert: 'Session Fixation' (CWE-384)"
echo ""

# --- Evidence Summary ---

echo "============================================"
echo "Detection Summary"
echo "============================================"
echo ""
echo "[*] Total findings: $FINDINGS"
echo ""

if [[ "$FINDINGS" -gt 0 ]]; then
    echo "[ALERT] Session fixation vulnerability detected!"
    echo ""
    echo "[*] Key risks:"
    echo "    - Attacker can set a known session ID before victim authenticates"
    echo "    - After victim logs in, attacker uses the same session ID"
    echo "    - Attacker gets full authenticated access as the victim"
    echo "    - MFA does not protect against this — the victim completes MFA, attacker gets the session"
    echo ""
    echo "[*] OWASP ASVS 3.7.1: 'Verify that the application generates a new session"
    echo "    token on user authentication'"
    echo ""
    echo "[*] Run fix.sh to implement session regeneration on authentication."
else
    echo "[OK] No session fixation vulnerability detected."
    echo "[*] Session appears to be regenerated on authentication."
fi

echo ""
echo "[*] Evidence saved to: $EVIDENCE_DIR"
echo "[*] Files:"
ls -la "$EVIDENCE_DIR/"
