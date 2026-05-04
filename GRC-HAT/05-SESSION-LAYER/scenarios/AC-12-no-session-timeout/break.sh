#!/usr/bin/env bash
set -euo pipefail

# AC-12 No Session Timeout — Break
#
# Modifies a sample web application configuration to disable session timeouts.
# Sets token expiry to 0 (never expires), removes idle timeout settings, and
# disables session lifetime limits. This simulates a production misconfiguration
# where authenticated sessions persist indefinitely — enabling token theft,
# session replay, and account takeover.
#
# REQUIREMENTS:
#   - A running web application with configurable session settings
#   - nginx (for header-based demonstration) or a Node.js/Python app
#   - curl for verification
#
# USAGE:
#   ./break.sh [app_url] [config_dir]
#
# EXAMPLE:
#   ./break.sh http://localhost:8080 /etc/nginx/conf.d
#   ./break.sh http://localhost:3000 ./app-config
#
# WARNING: This script is for authorized security testing only.
#          Unauthorized use is illegal under the CFAA and equivalent laws.
#
# CSF 2.0: PR.AA-06 (Physical access managed)
# CIS v8: 17.8 (Conduct Post-Incident Reviews)
# NIST: AC-12 (Session Termination)
#

# --- Argument Validation ---

APP_URL="${1:-http://localhost:8080}"
CONFIG_DIR="${2:-/tmp/ac12-session-lab}"

EVIDENCE_DIR="/tmp/ac12-no-session-timeout-evidence-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$EVIDENCE_DIR"
mkdir -p "$CONFIG_DIR"

echo "============================================"
echo "AC-12 No Session Timeout — Break"
echo "============================================"
echo ""
echo "[*] App URL:      $APP_URL"
echo "[*] Config dir:   $CONFIG_DIR"
echo "[*] Evidence dir: $EVIDENCE_DIR"
echo ""

# --- Record Pre-Break State ---

echo "[*] Recording pre-break state..."

# Capture current session headers if app is running
if curl -sf -o /dev/null "$APP_URL" 2>/dev/null; then
    curl -si "$APP_URL" 2>/dev/null | grep -iE "set-cookie|cache-control|expires|session|token" \
        > "$EVIDENCE_DIR/headers-before.txt" 2>/dev/null || true
    echo "[+] Captured current response headers"
else
    echo "[INFO] App not reachable at $APP_URL — will create config-only demonstration"
fi
echo ""

# --- Create Vulnerable Application Config ---

echo "[*] Creating vulnerable session configuration..."

# Method 1: nginx proxy configuration with no session controls
if command -v nginx &>/dev/null; then
    echo "[*] Configuring nginx with no session timeout headers..."

    NGINX_CONF="/etc/nginx/conf.d/ac12-no-timeout.conf"

    if [[ $EUID -eq 0 ]]; then
        cat > "$NGINX_CONF" << 'NGINXEOF'
# AC12-BREAK: No session timeout configuration
# DO NOT use in production — for security testing only

server {
    listen 8080;
    server_name session-lab.anthra.local;

    location / {
        proxy_pass http://127.0.0.1:3000;

        # VULNERABILITY: No Cache-Control headers for authenticated responses
        # Browsers may cache authenticated pages indefinitely

        # VULNERABILITY: No session-related security headers
        # No idle timeout enforcement at proxy level
        # No max session lifetime enforcement

        # VULNERABILITY: Cookies set without expiry or security attributes
        proxy_cookie_path / "/; SameSite=None";
        # Missing: Secure flag, HttpOnly flag, Max-Age, Expires
    }
}
NGINXEOF
        echo "[+] Wrote vulnerable nginx config to $NGINX_CONF"
        cp "$NGINX_CONF" "$EVIDENCE_DIR/nginx-no-timeout.conf"

        nginx -t 2>&1 || echo "[WARN] nginx config test failed (expected if backend not running)"
    else
        echo "[INFO] Not root — writing nginx config to evidence dir only"
        cat > "$EVIDENCE_DIR/nginx-no-timeout.conf" << 'NGINXEOF'
# AC12-BREAK: No session timeout configuration (example)
server {
    listen 8080;
    server_name session-lab.anthra.local;
    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_cookie_path / "/; SameSite=None";
    }
}
NGINXEOF
    fi
fi

# Method 2: Application-level configuration (Express.js style)
echo "[*] Creating vulnerable application session config..."

cat > "$CONFIG_DIR/session-config.json" << 'JSONEOF'
{
  "_comment": "AC12-BREAK: Vulnerable session configuration — no timeouts",
  "session": {
    "secret": "keyboard-cat-not-rotated-since-2019",
    "name": "session_id",
    "cookie": {
      "maxAge": null,
      "secure": false,
      "httpOnly": false,
      "sameSite": "none"
    },
    "rolling": false,
    "resave": true,
    "saveUninitialized": true
  },
  "jwt": {
    "expiresIn": "0",
    "algorithm": "HS256",
    "issuer": "anthra-lab",
    "_note": "expiresIn 0 means token never expires"
  },
  "idle_timeout_minutes": 0,
  "max_session_lifetime_hours": 0,
  "token_rotation": false,
  "refresh_token_enabled": false,
  "concurrent_sessions": "unlimited"
}
JSONEOF

echo "[+] Wrote vulnerable session config to $CONFIG_DIR/session-config.json"
cp "$CONFIG_DIR/session-config.json" "$EVIDENCE_DIR/session-config-broken.json"

# Method 3: Create a JWT with no expiry for testing
echo ""
echo "[*] Generating a JWT token with no expiration..."

if command -v python3 &>/dev/null; then
    python3 -c "
import base64, json, hmac, hashlib

header = base64.urlsafe_b64encode(json.dumps({'alg': 'HS256', 'typ': 'JWT'}).encode()).rstrip(b'=')
payload = base64.urlsafe_b64encode(json.dumps({
    'sub': 'user@anthra.local',
    'iat': 1712534400,
    'role': 'admin'
}).encode()).rstrip(b'=')
sig_input = header + b'.' + payload
signature = base64.urlsafe_b64encode(
    hmac.new(b'keyboard-cat-not-rotated-since-2019', sig_input, hashlib.sha256).digest()
).rstrip(b'=')
token = (header + b'.' + payload + b'.' + signature).decode()
print(token)
" > "$EVIDENCE_DIR/token-no-expiry.txt" 2>/dev/null || echo "[INFO] Python3 not available for JWT generation"

    if [[ -f "$EVIDENCE_DIR/token-no-expiry.txt" ]]; then
        echo "[+] Generated JWT with NO expiry claim (no 'exp' field)"
        echo "[+] Token saved to $EVIDENCE_DIR/token-no-expiry.txt"
        echo "[!] This token is valid forever — it can be replayed at any time"
    fi
else
    echo "[INFO] python3 not available — skipping JWT generation"
fi

echo ""
echo "============================================"
echo "Break Summary"
echo "============================================"
echo ""
echo "[!] Session configuration is now VULNERABLE:"
echo "[!]   - Token expiry: DISABLED (expiresIn: 0 / no exp claim)"
echo "[!]   - Idle timeout: DISABLED (idle_timeout_minutes: 0)"
echo "[!]   - Max session lifetime: DISABLED (max_session_lifetime_hours: 0)"
echo "[!]   - Token rotation: DISABLED"
echo "[!]   - Refresh tokens: DISABLED"
echo "[!]   - Cookie Secure flag: MISSING"
echo "[!]   - Cookie HttpOnly flag: MISSING"
echo "[!]   - Concurrent sessions: UNLIMITED"
echo ""
echo "[*] This configuration is vulnerable to:"
echo "    - Token theft via XSS (no HttpOnly flag)"
echo "    - Session replay (no expiry, no rotation)"
echo "    - Account takeover (stolen token works forever)"
echo "    - Session hijacking over HTTP (no Secure flag)"
echo "    - Credential stuffing persistence (no session limit)"
echo ""
echo "[*] Run detect.sh to confirm the exposure, then fix.sh to remediate."
echo "[*] Evidence saved to: $EVIDENCE_DIR"
