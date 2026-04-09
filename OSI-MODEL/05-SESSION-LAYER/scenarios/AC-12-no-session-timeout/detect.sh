#!/usr/bin/env bash
set -euo pipefail

# AC-12 No Session Timeout — Detect
#
# Detects missing session timeout controls using:
#   1. curl — inspect response headers for session cookie attributes
#   2. JWT decode — check for missing or zero expiry claims
#   3. Session persistence test — verify token works after extended wait
#   4. Configuration audit — check for missing timeout settings
#
# REQUIREMENTS:
#   - curl
#   - python3 (for JWT decoding)
#   - A running target application (optional — config audit works without it)
#
# USAGE:
#   ./detect.sh <target_url> [config_dir]
#
# EXAMPLE:
#   ./detect.sh http://localhost:8080
#   ./detect.sh https://app.example.com /path/to/config

# --- Argument Validation ---

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <target_url> [config_dir]"
    echo "Example: $0 http://localhost:8080"
    echo ""
    echo "target_url:  Base URL of the application to test"
    echo "config_dir:  Optional path to application config directory"
    exit 1
fi

TARGET="$1"
CONFIG_DIR="${2:-/tmp/ac12-session-lab}"

EVIDENCE_DIR="/tmp/ac12-no-session-timeout-detect-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$EVIDENCE_DIR"

echo "============================================"
echo "AC-12 No Session Timeout — Detection"
echo "============================================"
echo ""
echo "[*] Target:       $TARGET"
echo "[*] Config dir:   $CONFIG_DIR"
echo "[*] Evidence dir: $EVIDENCE_DIR"
echo ""

FINDINGS=0

# --- Method 1: HTTP Response Header Analysis ---

echo "[*] Method 1: HTTP response header analysis"
echo "----------------------------------------------"

if command -v curl &>/dev/null; then
    echo "[*] Fetching response headers..."
    HEADERS=$(curl -si -o /dev/null -D - "$TARGET" 2>/dev/null || echo "CONNECTION_FAILED")

    if [[ "$HEADERS" == "CONNECTION_FAILED" ]]; then
        echo "[INFO] Could not connect to $TARGET — skipping header checks"
        echo "[INFO] Running config-only detection"
    else
        echo "$HEADERS" > "$EVIDENCE_DIR/response-headers.txt"

        # Check Set-Cookie headers for security attributes
        echo "[*] Analyzing Set-Cookie headers..."
        COOKIES=$(echo "$HEADERS" | grep -i "set-cookie" || true)

        if [[ -n "$COOKIES" ]]; then
            echo "$COOKIES" | tee "$EVIDENCE_DIR/cookies.txt"
            echo ""

            # Check for Max-Age or Expires
            if echo "$COOKIES" | grep -qi "max-age\|expires"; then
                echo "[OK] Cookie has Max-Age or Expires attribute"
            else
                echo "[ALERT] Cookie has NO Max-Age or Expires — session cookie with no timeout"
                FINDINGS=$((FINDINGS + 1))
            fi

            # Check for Secure flag
            if echo "$COOKIES" | grep -qi "secure"; then
                echo "[OK] Cookie has Secure flag"
            else
                echo "[ALERT] Cookie MISSING Secure flag — transmittable over HTTP"
                FINDINGS=$((FINDINGS + 1))
            fi

            # Check for HttpOnly flag
            if echo "$COOKIES" | grep -qi "httponly"; then
                echo "[OK] Cookie has HttpOnly flag"
            else
                echo "[ALERT] Cookie MISSING HttpOnly flag — accessible via JavaScript (XSS risk)"
                FINDINGS=$((FINDINGS + 1))
            fi

            # Check for SameSite attribute
            if echo "$COOKIES" | grep -qi "samesite=strict\|samesite=lax"; then
                echo "[OK] Cookie has SameSite restriction"
            else
                echo "[ALERT] Cookie MISSING SameSite=Strict or SameSite=Lax — CSRF risk"
                FINDINGS=$((FINDINGS + 1))
            fi
        else
            echo "[INFO] No Set-Cookie headers in response (may require authentication)"
        fi

        echo ""

        # Check for Cache-Control on authenticated endpoints
        echo "[*] Checking Cache-Control headers..."
        if echo "$HEADERS" | grep -qi "cache-control.*no-store\|cache-control.*no-cache"; then
            echo "[OK] Cache-Control prevents caching of authenticated responses"
        else
            echo "[ALERT] No Cache-Control: no-store header — authenticated pages may be cached"
            FINDINGS=$((FINDINGS + 1))
        fi
    fi
else
    echo "[SKIP] curl not installed."
fi
echo ""

# --- Method 2: JWT Token Analysis ---

echo "[*] Method 2: JWT token expiry analysis"
echo "----------------------------------------------"

# Check for JWT tokens in evidence from break.sh
JWT_FILE=""
for f in /tmp/ac12-no-session-timeout-evidence-*/token-no-expiry.txt; do
    if [[ -f "$f" ]]; then
        JWT_FILE="$f"
        break
    fi
done

if [[ -n "$JWT_FILE" ]] && command -v python3 &>/dev/null; then
    TOKEN=$(cat "$JWT_FILE")
    echo "[*] Analyzing JWT token from break scenario..."
    echo "[*] Token: ${TOKEN:0:50}..."

    python3 -c "
import base64, json, sys

token = '$TOKEN'
parts = token.split('.')
if len(parts) != 3:
    print('[ERROR] Invalid JWT format')
    sys.exit(1)

# Decode payload (add padding)
payload_b64 = parts[1] + '=' * (4 - len(parts[1]) % 4)
payload = json.loads(base64.urlsafe_b64decode(payload_b64))

print('[*] JWT Payload:')
print(json.dumps(payload, indent=2))
print()

findings = 0

# Check for exp claim
if 'exp' not in payload:
    print('[ALERT] JWT has NO exp (expiration) claim — token never expires')
    findings += 1
elif payload['exp'] == 0:
    print('[ALERT] JWT exp claim is 0 — token never expires')
    findings += 1
else:
    import time
    remaining = payload['exp'] - time.time()
    if remaining > 86400:  # More than 24 hours
        print(f'[WARN] JWT expires in {remaining/3600:.1f} hours — unusually long lifetime')
    else:
        print(f'[OK] JWT expires in {remaining/3600:.1f} hours')

# Check for iat (issued at)
if 'iat' not in payload:
    print('[ALERT] JWT has no iat (issued at) claim — cannot enforce max lifetime')
    findings += 1

# Check for nbf (not before)
if 'nbf' not in payload:
    print('[INFO] JWT has no nbf (not before) claim')

# Check for jti (JWT ID)
if 'jti' not in payload:
    print('[ALERT] JWT has no jti (JWT ID) claim — cannot revoke individual tokens')
    findings += 1

print(f'\\n[*] JWT findings: {findings}')
" 2>&1 | tee "$EVIDENCE_DIR/jwt-analysis.txt"

    # Count Python findings
    JWT_FINDINGS=$(grep -c "^\[ALERT\]" "$EVIDENCE_DIR/jwt-analysis.txt" 2>/dev/null || echo "0")
    FINDINGS=$((FINDINGS + JWT_FINDINGS))
else
    echo "[INFO] No JWT token from break scenario or python3 not available"
    echo "[*] To test: obtain a JWT from the application and decode with:"
    echo "    echo '<token>' | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool"
fi
echo ""

# --- Method 3: Session Persistence Test ---

echo "[*] Method 3: Session persistence test"
echo "----------------------------------------------"

if command -v curl &>/dev/null; then
    echo "[*] Testing if session persists without activity..."
    echo "[*] Step 1: Obtain initial session..."

    COOKIE_JAR="$EVIDENCE_DIR/cookies.jar"
    INITIAL_RESPONSE=$(curl -s -c "$COOKIE_JAR" -D "$EVIDENCE_DIR/initial-headers.txt" \
        "$TARGET" 2>/dev/null || echo "CONNECTION_FAILED")

    if [[ "$INITIAL_RESPONSE" != "CONNECTION_FAILED" ]] && [[ -f "$COOKIE_JAR" ]]; then
        echo "[+] Initial session obtained"
        echo "[*] Cookie jar contents:"
        cat "$COOKIE_JAR" | grep -v "^#" | grep -v "^$" || echo "  (no cookies set)"
        echo ""

        echo "[*] Step 2: Wait 5 seconds (simulating idle period)..."
        sleep 5

        echo "[*] Step 3: Replay session after idle period..."
        REPLAY_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -b "$COOKIE_JAR" \
            "$TARGET" 2>/dev/null || echo "000")

        if [[ "$REPLAY_STATUS" == "200" ]] || [[ "$REPLAY_STATUS" == "302" ]]; then
            echo "[INFO] Session still valid after 5 seconds (expected — testing timeout absence)"
            echo "[*] In a real test, wait longer than the expected idle timeout"
            echo "[*] AC-12 requires: 15-minute idle timeout for normal sessions"
            echo "[*] AC-12 requires: 2-minute idle timeout for high-privilege sessions"
        elif [[ "$REPLAY_STATUS" == "401" ]] || [[ "$REPLAY_STATUS" == "403" ]]; then
            echo "[OK] Session was invalidated — timeout may be configured"
        else
            echo "[INFO] Got HTTP $REPLAY_STATUS — check application behavior"
        fi
    else
        echo "[INFO] Could not establish session — app may not be running"
    fi
else
    echo "[SKIP] curl not installed"
fi
echo ""

# --- Method 4: Configuration Audit ---

echo "[*] Method 4: Application configuration audit"
echo "----------------------------------------------"

if [[ -f "$CONFIG_DIR/session-config.json" ]]; then
    echo "[*] Analyzing $CONFIG_DIR/session-config.json..."

    if command -v python3 &>/dev/null; then
        python3 -c "
import json

with open('$CONFIG_DIR/session-config.json') as f:
    config = json.load(f)

findings = 0

# Check JWT expiry
jwt = config.get('jwt', {})
expires = jwt.get('expiresIn', 'not_set')
if expires == '0' or expires == 0 or expires == 'not_set':
    print('[ALERT] JWT expiresIn is 0 or not set — tokens never expire')
    findings += 1
else:
    print(f'[OK] JWT expiresIn: {expires}')

# Check idle timeout
idle = config.get('idle_timeout_minutes', 0)
if idle == 0:
    print('[ALERT] idle_timeout_minutes is 0 — no idle timeout configured')
    findings += 1
elif idle > 15:
    print(f'[WARN] idle_timeout_minutes is {idle} — exceeds NIST recommendation of 15 minutes')
    findings += 1
else:
    print(f'[OK] idle_timeout_minutes: {idle}')

# Check max session lifetime
max_life = config.get('max_session_lifetime_hours', 0)
if max_life == 0:
    print('[ALERT] max_session_lifetime_hours is 0 — no maximum session lifetime')
    findings += 1
elif max_life > 24:
    print(f'[WARN] max_session_lifetime_hours is {max_life} — exceeds 24-hour recommendation')
    findings += 1
else:
    print(f'[OK] max_session_lifetime_hours: {max_life}')

# Check token rotation
if not config.get('token_rotation', False):
    print('[ALERT] token_rotation is disabled — stolen tokens cannot be detected')
    findings += 1
else:
    print('[OK] Token rotation enabled')

# Check refresh tokens
if not config.get('refresh_token_enabled', False):
    print('[ALERT] refresh_token_enabled is false — no refresh rotation mechanism')
    findings += 1
else:
    print('[OK] Refresh tokens enabled')

# Check concurrent sessions
concurrent = config.get('concurrent_sessions', 'unlimited')
if concurrent == 'unlimited':
    print('[ALERT] concurrent_sessions is unlimited — no session limit per user')
    findings += 1
else:
    print(f'[OK] concurrent_sessions: {concurrent}')

# Check cookie attributes
cookie = config.get('session', {}).get('cookie', {})
if not cookie.get('secure', False):
    print('[ALERT] Cookie secure flag is false — cookie sent over HTTP')
    findings += 1
if not cookie.get('httpOnly', False):
    print('[ALERT] Cookie httpOnly flag is false — accessible to JavaScript')
    findings += 1

print(f'\\n[*] Configuration findings: {findings}')
" 2>&1 | tee "$EVIDENCE_DIR/config-audit.txt"

        CONFIG_FINDINGS=$(grep -c "^\[ALERT\]" "$EVIDENCE_DIR/config-audit.txt" 2>/dev/null || echo "0")
        FINDINGS=$((FINDINGS + CONFIG_FINDINGS))
    else
        echo "[INFO] python3 not available for config parsing"
    fi
else
    echo "[INFO] No session-config.json found at $CONFIG_DIR"
    echo "[*] Run break.sh first to create the vulnerable configuration"
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
    echo "[ALERT] Session timeout controls are MISSING or INSUFFICIENT!"
    echo ""
    echo "[*] Key risks:"
    echo "    - No token expiry: stolen tokens work forever"
    echo "    - No idle timeout: unattended sessions remain authenticated"
    echo "    - No max lifetime: sessions persist across password changes"
    echo "    - No token rotation: compromised tokens cannot be detected"
    echo "    - Missing cookie flags: tokens exposed to XSS and HTTP interception"
    echo ""
    echo "[*] Microsoft reports 99.9% of compromised accounts lacked MFA"
    echo "[*] Session theft is the #2 account takeover vector (after credential stuffing)"
    echo ""
    echo "[*] Run fix.sh to set 15min idle timeout, 8hr max lifetime, and token rotation."
else
    echo "[OK] No session timeout issues detected."
fi

echo ""
echo "[*] Evidence saved to: $EVIDENCE_DIR"
echo "[*] Files:"
ls -la "$EVIDENCE_DIR/"
