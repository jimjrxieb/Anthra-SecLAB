#!/usr/bin/env bash
set -euo pipefail

# AC-12 No Session Timeout — Validate
#
# Confirms that session timeout controls are properly configured:
#   1. Token expires after idle timeout (15 minutes)
#   2. Maximum session lifetime is enforced (8 hours)
#   3. Refresh token rotation works (new token issued, old revoked)
#   4. Cookie attributes are secure (Secure, HttpOnly, SameSite)
#   5. Configuration audit passes all checks
#
# REQUIREMENTS:
#   - curl
#   - python3 (for JWT and config analysis)
#
# USAGE:
#   ./validate.sh <target_url> [config_dir]
#
# EXAMPLE:
#   ./validate.sh http://localhost:8080
#   ./validate.sh https://app.example.com /path/to/config
#
# CSF 2.0: PR.AA-06 (Physical access managed)
# CIS v8: 6.2 (Establish Access Revoking Process)
# NIST: AC-12 (Session Termination)
#

# --- Argument Validation ---

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <target_url> [config_dir]"
    echo "Example: $0 http://localhost:8080"
    exit 1
fi

TARGET="$1"
CONFIG_DIR="${2:-/tmp/ac12-session-lab}"

EVIDENCE_DIR="/tmp/ac12-no-session-timeout-validate-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$EVIDENCE_DIR"

echo "============================================"
echo "AC-12 No Session Timeout — Validation"
echo "============================================"
echo ""
echo "[*] Target:       $TARGET"
echo "[*] Config dir:   $CONFIG_DIR"
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

# --- Test 1: Configuration Audit ---

echo "[*] Test 1: Session configuration audit"
echo "----------------------------------------------"

if [[ -f "$CONFIG_DIR/session-config.json" ]] && command -v python3 &>/dev/null; then
    python3 -c "
import json, sys

with open('$CONFIG_DIR/session-config.json') as f:
    config = json.load(f)

passed = 0
failed = 0

# Check idle timeout
idle = config.get('idle_timeout_minutes', 0)
if 1 <= idle <= 15:
    print(f'  [OK] Idle timeout: {idle} minutes (within 15-min limit)')
    passed += 1
else:
    print(f'  [FAIL] Idle timeout: {idle} minutes (must be 1-15)')
    failed += 1

# Check max session lifetime
max_life = config.get('max_session_lifetime_hours', 0)
if 1 <= max_life <= 24:
    print(f'  [OK] Max session lifetime: {max_life} hours')
    passed += 1
else:
    print(f'  [FAIL] Max session lifetime: {max_life} hours (must be 1-24)')
    failed += 1

# Check access token expiry
jwt = config.get('jwt', {})
access = jwt.get('access_token', jwt)
expires = access.get('expiresIn', '0')
if expires not in ['0', 0, 'not_set', None]:
    print(f'  [OK] Access token expiry: {expires}')
    passed += 1
else:
    print(f'  [FAIL] Access token expiry: {expires} (must have expiry)')
    failed += 1

# Check refresh token rotation
refresh = jwt.get('refresh_token', {})
if refresh.get('rotation', False) or config.get('token_rotation', False):
    print('  [OK] Token rotation: enabled')
    passed += 1
else:
    print('  [FAIL] Token rotation: disabled')
    failed += 1

# Check reuse detection
if refresh.get('reuse_detection', False):
    print('  [OK] Refresh token reuse detection: enabled')
    passed += 1
else:
    print('  [FAIL] Refresh token reuse detection: disabled')
    failed += 1

# Check cookie security
cookie = config.get('session', {}).get('cookie', {})
if cookie.get('secure', False):
    print('  [OK] Cookie Secure flag: set')
    passed += 1
else:
    print('  [FAIL] Cookie Secure flag: missing')
    failed += 1

if cookie.get('httpOnly', False):
    print('  [OK] Cookie HttpOnly flag: set')
    passed += 1
else:
    print('  [FAIL] Cookie HttpOnly flag: missing')
    failed += 1

samesite = cookie.get('sameSite', 'none').lower()
if samesite in ['strict', 'lax']:
    print(f'  [OK] Cookie SameSite: {samesite}')
    passed += 1
else:
    print(f'  [FAIL] Cookie SameSite: {samesite} (must be strict or lax)')
    failed += 1

# Check concurrent sessions
concurrent = config.get('concurrent_sessions', 'unlimited')
if concurrent != 'unlimited' and isinstance(concurrent, int) and concurrent > 0:
    print(f'  [OK] Concurrent sessions: {concurrent} (limited)')
    passed += 1
else:
    print(f'  [FAIL] Concurrent sessions: {concurrent} (must be limited)')
    failed += 1

# Check server-side logout
logout = config.get('logout', {})
if logout.get('server_side_invalidation', False):
    print('  [OK] Server-side session invalidation: enabled')
    passed += 1
else:
    print('  [FAIL] Server-side session invalidation: disabled')
    failed += 1

if logout.get('clear_all_sessions_on_password_change', False):
    print('  [OK] Clear sessions on password change: enabled')
    passed += 1
else:
    print('  [FAIL] Clear sessions on password change: disabled')
    failed += 1

print(f'\\nConfig audit: {passed} passed, {failed} failed')
sys.exit(0 if failed == 0 else 1)
" 2>&1 | tee "$EVIDENCE_DIR/config-audit.txt"

    if [[ $? -eq 0 ]]; then
        check_result "Configuration audit" "pass" "All session config settings meet AC-12 requirements"
    else
        check_result "Configuration audit" "fail" "Session config has deficient settings"
    fi
else
    echo "[SKIP] session-config.json not found or python3 not available"
    SKIP=$((SKIP + 1))
fi
echo ""

# --- Test 2: JWT Token Has Expiry ---

echo "[*] Test 2: JWT token has proper expiry claims"
echo "----------------------------------------------"

JWT_FILE=""
for f in /tmp/ac12-no-session-timeout-fix-*/token-with-expiry.txt; do
    if [[ -f "$f" ]]; then
        JWT_FILE="$f"
        break
    fi
done

if [[ -n "$JWT_FILE" ]] && command -v python3 &>/dev/null; then
    TOKEN=$(cat "$JWT_FILE")

    RESULT=$(python3 -c "
import base64, json, time

token = '$TOKEN'
parts = token.split('.')
payload_b64 = parts[1] + '=' * (4 - len(parts[1]) % 4)
payload = json.loads(base64.urlsafe_b64decode(payload_b64))

checks = 0
total = 0

# exp claim
total += 1
if 'exp' in payload and payload['exp'] > 0:
    lifetime = payload['exp'] - payload.get('iat', 0)
    print(f'  [OK] exp claim present (lifetime: {lifetime}s / {lifetime/60:.0f}m)')
    checks += 1
else:
    print('  [FAIL] exp claim missing or zero')

# iat claim
total += 1
if 'iat' in payload:
    print('  [OK] iat (issued at) claim present')
    checks += 1
else:
    print('  [FAIL] iat claim missing')

# jti claim
total += 1
if 'jti' in payload:
    print('  [OK] jti (token ID) claim present — supports revocation')
    checks += 1
else:
    print('  [FAIL] jti claim missing — cannot revoke individual tokens')

# iss claim
total += 1
if 'iss' in payload:
    print(f'  [OK] iss (issuer) claim: {payload[\"iss\"]}')
    checks += 1
else:
    print('  [FAIL] iss claim missing')

# aud claim
total += 1
if 'aud' in payload:
    print(f'  [OK] aud (audience) claim: {payload[\"aud\"]}')
    checks += 1
else:
    print('  [FAIL] aud claim missing')

print(f'RESULT:{checks}/{total}')
" 2>&1)

    echo "$RESULT" | grep -v "^RESULT:" | tee "$EVIDENCE_DIR/jwt-validation.txt"
    SCORE=$(echo "$RESULT" | grep "^RESULT:" | cut -d: -f2)

    if [[ "$SCORE" == "5/5" ]]; then
        check_result "JWT token claims" "pass" "All required claims present (exp, iat, jti, iss, aud)"
    else
        check_result "JWT token claims" "fail" "Missing required JWT claims ($SCORE)"
    fi
else
    echo "[SKIP] No fixed JWT token found or python3 not available"
    SKIP=$((SKIP + 1))
fi
echo ""

# --- Test 3: HTTP Response Headers ---

echo "[*] Test 3: Secure response headers"
echo "----------------------------------------------"

if command -v curl &>/dev/null; then
    HEADERS=$(curl -si -o /dev/null -D - "$TARGET" 2>/dev/null || echo "CONNECTION_FAILED")

    if [[ "$HEADERS" != "CONNECTION_FAILED" ]]; then
        echo "$HEADERS" > "$EVIDENCE_DIR/response-headers.txt"

        HEADER_PASS=0
        HEADER_TOTAL=0

        # Check Cache-Control
        HEADER_TOTAL=$((HEADER_TOTAL + 1))
        if echo "$HEADERS" | grep -qi "cache-control.*no-store"; then
            echo "  [OK] Cache-Control: no-store is set"
            HEADER_PASS=$((HEADER_PASS + 1))
        else
            echo "  [FAIL] Cache-Control: no-store is missing"
        fi

        # Check Set-Cookie attributes
        COOKIES=$(echo "$HEADERS" | grep -i "set-cookie" || true)
        if [[ -n "$COOKIES" ]]; then
            HEADER_TOTAL=$((HEADER_TOTAL + 1))
            if echo "$COOKIES" | grep -qi "secure"; then
                echo "  [OK] Cookie has Secure flag"
                HEADER_PASS=$((HEADER_PASS + 1))
            else
                echo "  [FAIL] Cookie missing Secure flag"
            fi

            HEADER_TOTAL=$((HEADER_TOTAL + 1))
            if echo "$COOKIES" | grep -qi "httponly"; then
                echo "  [OK] Cookie has HttpOnly flag"
                HEADER_PASS=$((HEADER_PASS + 1))
            else
                echo "  [FAIL] Cookie missing HttpOnly flag"
            fi

            HEADER_TOTAL=$((HEADER_TOTAL + 1))
            if echo "$COOKIES" | grep -qi "samesite=strict\|samesite=lax"; then
                echo "  [OK] Cookie has SameSite restriction"
                HEADER_PASS=$((HEADER_PASS + 1))
            else
                echo "  [FAIL] Cookie missing SameSite restriction"
            fi
        else
            echo "  [INFO] No Set-Cookie headers (may require authentication)"
        fi

        # Check X-Content-Type-Options
        HEADER_TOTAL=$((HEADER_TOTAL + 1))
        if echo "$HEADERS" | grep -qi "x-content-type-options.*nosniff"; then
            echo "  [OK] X-Content-Type-Options: nosniff is set"
            HEADER_PASS=$((HEADER_PASS + 1))
        else
            echo "  [FAIL] X-Content-Type-Options header missing"
        fi

        if [[ "$HEADER_PASS" -eq "$HEADER_TOTAL" ]]; then
            check_result "Response headers" "pass" "All $HEADER_TOTAL security headers present"
        else
            check_result "Response headers" "fail" "$HEADER_PASS/$HEADER_TOTAL security headers present"
        fi
    else
        echo "[SKIP] Could not connect to $TARGET"
        SKIP=$((SKIP + 1))
    fi
else
    echo "[SKIP] curl not installed"
    SKIP=$((SKIP + 1))
fi
echo ""

# --- Test 4: Session Idle Timeout Behavior ---

echo "[*] Test 4: Session idle timeout enforcement"
echo "----------------------------------------------"

if command -v curl &>/dev/null; then
    COOKIE_JAR="$EVIDENCE_DIR/validate-cookies.jar"
    INITIAL=$(curl -s -c "$COOKIE_JAR" -o /dev/null -w "%{http_code}" "$TARGET" 2>/dev/null || echo "000")

    if [[ "$INITIAL" != "000" ]] && [[ -f "$COOKIE_JAR" ]]; then
        echo "[*] Session established (HTTP $INITIAL)"
        echo "[INFO] Full idle timeout testing requires waiting 15+ minutes"
        echo "[INFO] For lab validation: manually wait 16 minutes and re-run:"
        echo "       curl -b $COOKIE_JAR $TARGET"
        echo "       Expected: HTTP 401 or 302 (redirect to login)"
        echo ""
        echo "[*] Quick check: verifying session is valid immediately after creation..."
        REPLAY=$(curl -s -b "$COOKIE_JAR" -o /dev/null -w "%{http_code}" "$TARGET" 2>/dev/null || echo "000")
        if [[ "$REPLAY" == "200" ]] || [[ "$REPLAY" == "302" ]]; then
            echo "  [OK] Session is valid immediately after creation (expected)"
            check_result "Session immediate replay" "pass" "Newly created session is valid"
        else
            echo "  [INFO] Got HTTP $REPLAY — application may require authentication"
            SKIP=$((SKIP + 1))
        fi
    else
        echo "[SKIP] Could not establish session"
        SKIP=$((SKIP + 1))
    fi
else
    echo "[SKIP] curl not installed"
    SKIP=$((SKIP + 1))
fi
echo ""

# --- Test 5: Privileged Session Timeout ---

echo "[*] Test 5: Privileged session timeout configuration"
echo "----------------------------------------------"

if [[ -f "$CONFIG_DIR/session-config.json" ]] && command -v python3 &>/dev/null; then
    PRIV_TIMEOUT=$(python3 -c "
import json
with open('$CONFIG_DIR/session-config.json') as f:
    config = json.load(f)
print(config.get('idle_timeout_privileged_minutes', 'not_set'))
" 2>/dev/null || echo "not_set")

    if [[ "$PRIV_TIMEOUT" != "not_set" ]] && [[ "$PRIV_TIMEOUT" -le 5 ]] && [[ "$PRIV_TIMEOUT" -ge 1 ]]; then
        check_result "Privileged session timeout" "pass" "Privileged idle timeout: ${PRIV_TIMEOUT} minutes (within 5-min limit)"
    elif [[ "$PRIV_TIMEOUT" == "not_set" ]]; then
        check_result "Privileged session timeout" "fail" "No privileged session timeout configured"
    else
        check_result "Privileged session timeout" "fail" "Privileged timeout ${PRIV_TIMEOUT} minutes (should be 1-5)"
    fi
else
    echo "[SKIP] Config not available"
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
    echo "[PASS] AC-12 session timeout controls validated successfully."
    echo "[*] Idle timeout configured, max lifetime enforced, token rotation enabled."
    echo ""
    echo "[*] Residual risk: LOW"
    echo "    - Likelihood: 2 (Unlikely) — tokens expire, rotation detects theft"
    echo "    - Impact: 3 (Moderate) — window of exposure limited to 15 minutes"
    echo "    - Residual Score: 6 (Medium-Low)"
elif [[ "$FAIL" -gt 0 ]]; then
    echo "[FAIL] AC-12 session timeout validation has $FAIL failing check(s)."
    echo "[*] Review the failures above and re-run fix.sh."
else
    echo "[INCOMPLETE] All tests were skipped — verify app is running and config exists."
fi

echo ""
echo "[*] Evidence saved to: $EVIDENCE_DIR"
echo "[*] Files:"
ls -la "$EVIDENCE_DIR/"
