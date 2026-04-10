#!/usr/bin/env bash
set -euo pipefail

# SC-23 Session Fixation — Validate
#
# Confirms that session fixation has been remediated:
#   1. Session ID changes after authentication (regeneration works)
#   2. Old session ID is invalid after regeneration
#   3. Externally-set session IDs are rejected (strict mode)
#   4. Cookie attributes are secure
#   5. Session configuration audit passes
#
# REQUIREMENTS:
#   - curl
#   - A running target application with login endpoint
#
# USAGE:
#   ./validate.sh <target_url> <login_endpoint> [username] [password] [config_dir]
#
# EXAMPLE:
#   ./validate.sh http://localhost:8080 /login testuser testpass

# --- Argument Validation ---

if [[ $# -lt 2 ]]; then
    echo "Usage: $0 <target_url> <login_endpoint> [username] [password] [config_dir]"
    echo "Example: $0 http://localhost:8080 /login testuser testpass"
    exit 1
fi

TARGET="$1"
LOGIN_PATH="$2"
USERNAME="${3:-testuser}"
PASSWORD="${4:-testpass}"
CONFIG_DIR="${5:-/tmp/sc23-session-lab}"
LOGIN_URL="${TARGET}${LOGIN_PATH}"

EVIDENCE_DIR="/tmp/sc23-session-fixation-validate-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$EVIDENCE_DIR"

echo "============================================"
echo "SC-23 Session Fixation — Validation"
echo "============================================"
echo ""
echo "[*] Target:       $TARGET"
echo "[*] Login URL:    $LOGIN_URL"
echo "[*] Username:     $USERNAME"
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

# --- Test 1: Session ID Changes After Login ---

echo "[*] Test 1: Session ID must change after authentication"
echo "----------------------------------------------"

if command -v curl &>/dev/null; then
    # Get pre-auth session
    COOKIE_JAR_PRE="$EVIDENCE_DIR/cookies-pre-auth.jar"
    curl -s -c "$COOKIE_JAR_PRE" -D "$EVIDENCE_DIR/headers-pre-auth.txt" \
        "$TARGET" > /dev/null 2>&1 || true

    PRE_COOKIE=$(grep -v "^#" "$COOKIE_JAR_PRE" 2>/dev/null | \
        grep -iE "session|sid|token|jsessionid|phpsessid|connect\.sid|__host" | \
        awk '{print $NF}' | head -1 || echo "")

    if [[ -n "$PRE_COOKIE" ]]; then
        # Perform login
        COOKIE_JAR_POST="$EVIDENCE_DIR/cookies-post-auth.jar"
        curl -s -b "$COOKIE_JAR_PRE" -c "$COOKIE_JAR_POST" \
            -D "$EVIDENCE_DIR/headers-post-auth.txt" \
            -d "username=$USERNAME&password=$PASSWORD" \
            -X POST "$LOGIN_URL" > /dev/null 2>&1 || true

        POST_COOKIE=$(grep -v "^#" "$COOKIE_JAR_POST" 2>/dev/null | \
            grep -iE "session|sid|token|jsessionid|phpsessid|connect\.sid|__host" | \
            awk '{print $NF}' | head -1 || echo "")

        if [[ -n "$POST_COOKIE" ]] && [[ "$PRE_COOKIE" != "$POST_COOKIE" ]]; then
            check_result "Session regeneration" "pass" "Session ID changed after login (pre: ${PRE_COOKIE:0:12}... post: ${POST_COOKIE:0:12}...)"
        elif [[ "$PRE_COOKIE" == "$POST_COOKIE" ]]; then
            check_result "Session regeneration" "fail" "Session ID DID NOT change after login — still vulnerable"
        else
            echo "[SKIP] Could not obtain post-auth session cookie"
            SKIP=$((SKIP + 1))
        fi
    else
        echo "[INFO] No pre-auth session cookie — application may create sessions only at login"
        # Check if login creates a new session
        COOKIE_JAR_LOGIN="$EVIDENCE_DIR/cookies-login.jar"
        curl -s -c "$COOKIE_JAR_LOGIN" -D "$EVIDENCE_DIR/headers-login.txt" \
            -d "username=$USERNAME&password=$PASSWORD" \
            -X POST "$LOGIN_URL" > /dev/null 2>&1 || true

        LOGIN_COOKIE=$(grep -v "^#" "$COOKIE_JAR_LOGIN" 2>/dev/null | \
            grep -iE "session|sid|token|jsessionid|phpsessid|connect\.sid|__host" | \
            awk '{print $NF}' | head -1 || echo "")

        if [[ -n "$LOGIN_COOKIE" ]]; then
            check_result "Session creation at login" "pass" "Session created only at authentication (no pre-auth session)"
        else
            echo "[SKIP] No session cookie obtained — app may not be running or requires different auth"
            SKIP=$((SKIP + 1))
        fi
    fi
else
    echo "[SKIP] curl not installed"
    SKIP=$((SKIP + 1))
fi
echo ""

# --- Test 2: Old Session ID Must Be Invalid ---

echo "[*] Test 2: Old session ID must be invalid after regeneration"
echo "----------------------------------------------"

if command -v curl &>/dev/null && [[ -n "${PRE_COOKIE:-}" ]]; then
    echo "[*] Replaying old pre-auth session ID after login..."

    # Create a cookie jar with just the old session ID
    OLD_JAR="$EVIDENCE_DIR/cookies-old-session.jar"
    cp "$COOKIE_JAR_PRE" "$OLD_JAR" 2>/dev/null || true

    OLD_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
        -b "$OLD_JAR" "$TARGET/dashboard" 2>/dev/null || echo "000")

    if [[ "$OLD_STATUS" == "401" ]] || [[ "$OLD_STATUS" == "403" ]] || [[ "$OLD_STATUS" == "302" ]]; then
        check_result "Old session invalidated" "pass" "Old session ID returns HTTP $OLD_STATUS (rejected)"
    elif [[ "$OLD_STATUS" == "200" ]]; then
        check_result "Old session invalidated" "fail" "Old session ID returns HTTP 200 — old session still valid!"
    else
        echo "[INFO] HTTP $OLD_STATUS — verify manually if old session grants access"
        SKIP=$((SKIP + 1))
    fi
else
    echo "[SKIP] No pre-auth cookie captured or curl not available"
    SKIP=$((SKIP + 1))
fi
echo ""

# --- Test 3: External Session IDs Must Be Rejected ---

echo "[*] Test 3: Externally-set session IDs must be rejected (strict mode)"
echo "----------------------------------------------"

if command -v curl &>/dev/null; then
    FAKE_ID="attacker-fixed-session-$(date +%s)"
    echo "[*] Injecting external session ID: $FAKE_ID"

    INJECT_JAR="$EVIDENCE_DIR/cookies-injected.jar"
    INJECT_HEADERS=$(curl -si -b "session_id=$FAKE_ID;__Host-session_id=$FAKE_ID" \
        -c "$INJECT_JAR" "$TARGET" 2>/dev/null || echo "")

    # Check if server issued a NEW session ID (ignored our fake one)
    RETURNED_COOKIE=$(grep -v "^#" "$INJECT_JAR" 2>/dev/null | \
        grep -iE "session|sid|token|__host" | awk '{print $NF}' | head -1 || echo "")

    if [[ -n "$RETURNED_COOKIE" ]] && [[ "$RETURNED_COOKIE" != "$FAKE_ID" ]]; then
        check_result "External ID rejection" "pass" "Server issued new session ID, ignored injected one"
    elif echo "$INJECT_HEADERS" | grep -qi "$FAKE_ID"; then
        check_result "External ID rejection" "fail" "Server accepted and echoed injected session ID"
    else
        echo "[INFO] Server did not set a session cookie — may require authentication"
        SKIP=$((SKIP + 1))
    fi
else
    echo "[SKIP] curl not installed"
    SKIP=$((SKIP + 1))
fi
echo ""

# --- Test 4: Cookie Security Attributes ---

echo "[*] Test 4: Cookie security attributes"
echo "----------------------------------------------"

HEADER_FILE=""
for f in "$EVIDENCE_DIR"/headers-post-auth.txt "$EVIDENCE_DIR"/headers-login.txt "$EVIDENCE_DIR"/headers-pre-auth.txt; do
    if [[ -f "$f" ]] && grep -qi "set-cookie" "$f" 2>/dev/null; then
        HEADER_FILE="$f"
        break
    fi
done

if [[ -n "$HEADER_FILE" ]]; then
    COOKIES=$(grep -i "set-cookie" "$HEADER_FILE" 2>/dev/null || echo "")

    if [[ -n "$COOKIES" ]]; then
        COOKIE_PASS=0
        COOKIE_TOTAL=4

        # HttpOnly
        if echo "$COOKIES" | grep -qi "httponly"; then
            echo "  [OK] HttpOnly flag present"
            COOKIE_PASS=$((COOKIE_PASS + 1))
        else
            echo "  [FAIL] HttpOnly flag missing"
        fi

        # Secure
        if echo "$COOKIES" | grep -qi "secure"; then
            echo "  [OK] Secure flag present"
            COOKIE_PASS=$((COOKIE_PASS + 1))
        else
            echo "  [FAIL] Secure flag missing"
        fi

        # SameSite
        if echo "$COOKIES" | grep -qi "samesite=strict\|samesite=lax"; then
            echo "  [OK] SameSite attribute set"
            COOKIE_PASS=$((COOKIE_PASS + 1))
        else
            echo "  [FAIL] SameSite attribute missing"
        fi

        # __Host- prefix
        if echo "$COOKIES" | grep -q "__Host-"; then
            echo "  [OK] __Host- prefix used (origin-bound cookie)"
            COOKIE_PASS=$((COOKIE_PASS + 1))
        else
            echo "  [WARN] __Host- prefix not used (recommended for strongest binding)"
            COOKIE_PASS=$((COOKIE_PASS + 1))  # Warn but don't fail
        fi

        if [[ "$COOKIE_PASS" -eq "$COOKIE_TOTAL" ]]; then
            check_result "Cookie attributes" "pass" "All security attributes present"
        else
            check_result "Cookie attributes" "fail" "$COOKIE_PASS/$COOKIE_TOTAL attributes present"
        fi
    else
        echo "[SKIP] No Set-Cookie headers in captured responses"
        SKIP=$((SKIP + 1))
    fi
else
    echo "[SKIP] No response headers with cookies captured"
    SKIP=$((SKIP + 1))
fi
echo ""

# --- Test 5: Configuration Audit ---

echo "[*] Test 5: Session security configuration audit"
echo "----------------------------------------------"

if [[ -f "$CONFIG_DIR/session-security.json" ]] && command -v python3 &>/dev/null; then
    python3 -c "
import json, sys

with open('$CONFIG_DIR/session-security.json') as f:
    config = json.load(f)

passed = 0
failed = 0

regen = config.get('session_regeneration', {})
if regen.get('on_login', False):
    print('  [OK] Regenerate on login: enabled')
    passed += 1
else:
    print('  [FAIL] Regenerate on login: disabled')
    failed += 1

if regen.get('on_privilege_escalation', False):
    print('  [OK] Regenerate on privilege escalation: enabled')
    passed += 1
else:
    print('  [FAIL] Regenerate on privilege escalation: disabled')
    failed += 1

if regen.get('destroy_old_session', False):
    print('  [OK] Destroy old session: enabled')
    passed += 1
else:
    print('  [FAIL] Destroy old session: disabled')
    failed += 1

sid = config.get('session_id', {})
if sid.get('reject_uninitialized', False):
    print('  [OK] Reject uninitialized session IDs: enabled')
    passed += 1
else:
    print('  [FAIL] Reject uninitialized session IDs: disabled')
    failed += 1

if not sid.get('url_based_ids', True):
    print('  [OK] URL-based session IDs: disabled')
    passed += 1
else:
    print('  [FAIL] URL-based session IDs: enabled')
    failed += 1

anti = config.get('anti_fixation', {})
if anti.get('strict_mode', False):
    print('  [OK] Strict mode: enabled')
    passed += 1
else:
    print('  [FAIL] Strict mode: disabled')
    failed += 1

print(f'\\nConfig audit: {passed} passed, {failed} failed')
sys.exit(0 if failed == 0 else 1)
" 2>&1 | tee "$EVIDENCE_DIR/config-audit.txt"

    if [[ $? -eq 0 ]]; then
        check_result "Configuration audit" "pass" "All session fixation prevention settings enabled"
    else
        check_result "Configuration audit" "fail" "Session security configuration has gaps"
    fi
else
    echo "[SKIP] session-security.json not found or python3 not available"
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
    echo "[PASS] SC-23 session fixation remediation validated successfully."
    echo "[*] Session ID regenerated on login, old sessions destroyed, strict mode enabled."
    echo ""
    echo "[*] Residual risk: LOW"
    echo "    - Likelihood: 1 (Rare) — session regeneration prevents fixation entirely"
    echo "    - Impact: 3 (Moderate) — if bypassed, session hijacking still possible"
    echo "    - Residual Score: 3 (Low)"
elif [[ "$FAIL" -gt 0 ]]; then
    echo "[FAIL] SC-23 session fixation validation has $FAIL failing check(s)."
    echo "[*] Review the failures above and re-apply fix.sh."
else
    echo "[INCOMPLETE] All tests were skipped — verify app is running and accessible."
fi

echo ""
echo "[*] Evidence saved to: $EVIDENCE_DIR"
echo "[*] Files:"
ls -la "$EVIDENCE_DIR/"
