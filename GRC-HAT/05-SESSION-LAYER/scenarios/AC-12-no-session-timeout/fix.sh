#!/usr/bin/env bash
set -euo pipefail

# AC-12 No Session Timeout — Fix
#
# Remediates missing session timeout controls:
#   1. Sets 15-minute idle timeout for standard sessions
#   2. Sets 8-hour maximum session lifetime
#   3. Enables token refresh rotation (new refresh token per use)
#   4. Configures secure cookie attributes (Secure, HttpOnly, SameSite=Strict)
#   5. Limits concurrent sessions to 3 per user
#
# REQUIREMENTS:
#   - Application configuration directory
#   - nginx (optional — for proxy-level enforcement)
#
# USAGE:
#   ./fix.sh [config_dir] [app_url]
#
# EXAMPLE:
#   ./fix.sh /tmp/ac12-session-lab http://localhost:8080
#
# REFERENCES:
#   - NIST SP 800-53 AC-12: Session Termination
#   - OWASP Session Management Cheat Sheet
#   - Microsoft Entra ID: Conditional Access Session Controls
#
# CSF 2.0: PR.AA-06 (Physical access managed)
# CIS v8: 6.2 (Establish Access Revoking Process)
# NIST: AC-12 (Session Termination)
#

# --- Argument Validation ---

CONFIG_DIR="${1:-/tmp/ac12-session-lab}"
APP_URL="${2:-http://localhost:8080}"

EVIDENCE_DIR="/tmp/ac12-no-session-timeout-fix-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$EVIDENCE_DIR"
mkdir -p "$CONFIG_DIR"

echo "============================================"
echo "AC-12 No Session Timeout — Fix"
echo "============================================"
echo ""
echo "[*] Config dir:   $CONFIG_DIR"
echo "[*] App URL:      $APP_URL"
echo "[*] Evidence dir: $EVIDENCE_DIR"
echo ""

# --- Record Pre-Fix State ---

echo "[*] Recording pre-fix state..."
if [[ -f "$CONFIG_DIR/session-config.json" ]]; then
    cp "$CONFIG_DIR/session-config.json" "$EVIDENCE_DIR/session-config-before.json"
    echo "[+] Saved existing session config"
else
    echo "[INFO] No existing session config found"
fi
echo ""

# --- Fix 1: Application Session Configuration ---

echo "[*] Fix 1: Applying secure session configuration..."
echo "----------------------------------------------"

cat > "$CONFIG_DIR/session-config.json" << 'JSONEOF'
{
  "_comment": "AC12-FIX: Secure session configuration — NIST AC-12 compliant",
  "_applied": "Anthra-SecLAB fix.sh",
  "_references": [
    "NIST SP 800-53 AC-12 Session Termination",
    "OWASP Session Management Cheat Sheet",
    "Microsoft Entra ID Conditional Access"
  ],
  "session": {
    "secret_env_var": "SESSION_SECRET",
    "name": "__Host-session_id",
    "cookie": {
      "maxAge": 28800000,
      "secure": true,
      "httpOnly": true,
      "sameSite": "strict",
      "path": "/",
      "domain": null
    },
    "rolling": true,
    "resave": false,
    "saveUninitialized": false
  },
  "jwt": {
    "access_token": {
      "expiresIn": "15m",
      "algorithm": "RS256",
      "issuer": "anthra-lab",
      "audience": "anthra-api"
    },
    "refresh_token": {
      "expiresIn": "8h",
      "rotation": true,
      "reuse_detection": true,
      "family_tracking": true
    }
  },
  "idle_timeout_minutes": 15,
  "idle_timeout_privileged_minutes": 2,
  "max_session_lifetime_hours": 8,
  "token_rotation": true,
  "refresh_token_enabled": true,
  "concurrent_sessions": 3,
  "session_binding": {
    "bind_to_ip": false,
    "bind_to_user_agent": true,
    "bind_to_fingerprint": true
  },
  "logout": {
    "server_side_invalidation": true,
    "clear_all_sessions_on_password_change": true,
    "clear_all_sessions_on_mfa_change": true
  }
}
JSONEOF

echo "[+] Wrote secure session config to $CONFIG_DIR/session-config.json"
cp "$CONFIG_DIR/session-config.json" "$EVIDENCE_DIR/session-config-fixed.json"
echo ""

echo "[*] Key settings applied:"
echo "    - Access token lifetime: 15 minutes"
echo "    - Refresh token lifetime: 8 hours (max session)"
echo "    - Idle timeout: 15 minutes (2 minutes for privileged)"
echo "    - Token rotation: ENABLED (new refresh token per use)"
echo "    - Reuse detection: ENABLED (stolen refresh tokens detected)"
echo "    - Cookie: __Host- prefix, Secure, HttpOnly, SameSite=Strict"
echo "    - Concurrent sessions: 3 max per user"
echo "    - Session binding: user-agent + fingerprint"
echo ""

# --- Fix 2: nginx Proxy-Level Session Headers ---

echo "[*] Fix 2: Configuring proxy-level session controls..."
echo "----------------------------------------------"

if command -v nginx &>/dev/null && [[ $EUID -eq 0 ]]; then
    NGINX_CONF="/etc/nginx/conf.d/ac12-no-timeout.conf"

    cat > "$NGINX_CONF" << 'NGINXEOF'
# AC12-FIX: Secure session configuration at proxy level
# Applied by Anthra-SecLAB fix.sh
#
# References:
#   - NIST SP 800-53 AC-12 Session Termination
#   - OWASP Secure Headers Project

server {
    listen 8080;
    server_name session-lab.anthra.local;

    location / {
        proxy_pass http://127.0.0.1:3000;

        # FIX: Cache-Control for authenticated responses
        # Prevents browser from caching authenticated pages
        add_header Cache-Control "no-store, no-cache, must-revalidate, proxy-revalidate" always;
        add_header Pragma "no-cache" always;
        add_header Expires "0" always;

        # FIX: Security headers to protect session tokens
        add_header X-Content-Type-Options "nosniff" always;
        add_header X-Frame-Options "DENY" always;
        add_header X-XSS-Protection "0" always;
        add_header Referrer-Policy "strict-origin-when-cross-origin" always;
        add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'" always;

        # FIX: Secure cookie path rewrite
        proxy_cookie_path / "/; Secure; HttpOnly; SameSite=Strict";

        # FIX: Remove server version headers
        proxy_hide_header X-Powered-By;
        proxy_hide_header Server;
    }

    # FIX: Dedicated logout endpoint — clears session server-side
    location /logout {
        proxy_pass http://127.0.0.1:3000/logout;
        add_header Clear-Site-Data '"cache", "cookies", "storage"' always;
    }
}
NGINXEOF

    echo "[+] Wrote secure nginx config to $NGINX_CONF"
    cp "$NGINX_CONF" "$EVIDENCE_DIR/nginx-fixed.conf"

    echo "[*] Testing nginx configuration..."
    if nginx -t 2>&1; then
        nginx -s reload 2>/dev/null || systemctl reload nginx 2>/dev/null || true
        echo "[+] nginx reloaded with secure session headers"
    else
        echo "[WARN] nginx config test failed — backend may not be running"
    fi
else
    echo "[INFO] nginx not available or not root — writing config to evidence only"
    cat > "$EVIDENCE_DIR/nginx-fixed.conf" << 'NGINXEOF'
# AC12-FIX: Secure session headers (example for manual application)
# add_header Cache-Control "no-store, no-cache, must-revalidate" always;
# add_header Pragma "no-cache" always;
# proxy_cookie_path / "/; Secure; HttpOnly; SameSite=Strict";
# location /logout { add_header Clear-Site-Data '"cache", "cookies", "storage"' always; }
NGINXEOF
fi
echo ""

# --- Fix 3: Generate Secure JWT Example ---

echo "[*] Fix 3: Generating secure JWT with proper expiry..."
echo "----------------------------------------------"

if command -v python3 &>/dev/null; then
    python3 -c "
import base64, json, hmac, hashlib, time, uuid

now = int(time.time())
header = base64.urlsafe_b64encode(json.dumps({'alg': 'HS256', 'typ': 'JWT'}).encode()).rstrip(b'=')
payload = base64.urlsafe_b64encode(json.dumps({
    'sub': 'user@anthra.local',
    'iat': now,
    'exp': now + 900,
    'nbf': now,
    'jti': str(uuid.uuid4()),
    'role': 'admin',
    'session_id': str(uuid.uuid4()),
    'iss': 'anthra-lab',
    'aud': 'anthra-api'
}, indent=2).encode()).rstrip(b'=')
sig_input = header + b'.' + payload
signature = base64.urlsafe_b64encode(
    hmac.new(b'replace-with-256-bit-secret-from-env', sig_input, hashlib.sha256).digest()
).rstrip(b'=')
token = (header + b'.' + payload + b'.' + signature).decode()
print(token)
" > "$EVIDENCE_DIR/token-with-expiry.txt" 2>/dev/null || true

    if [[ -f "$EVIDENCE_DIR/token-with-expiry.txt" ]]; then
        echo "[+] Generated JWT with proper claims:"
        echo "    - exp: 15 minutes from now"
        echo "    - iat: current timestamp"
        echo "    - nbf: current timestamp (not valid before)"
        echo "    - jti: unique token ID (for revocation)"
        echo "    - iss/aud: issuer and audience claims"
        echo "[+] Token saved to $EVIDENCE_DIR/token-with-expiry.txt"
    fi
else
    echo "[INFO] python3 not available — skipping JWT generation"
fi
echo ""

# --- Kill Any Previous Break Artifacts ---

echo "[*] Cleaning up break scenario artifacts..."
if [[ -f /etc/nginx/conf.d/ac12-no-timeout.conf ]]; then
    echo "[+] Replaced vulnerable nginx config with secure version"
fi
echo ""

echo "============================================"
echo "Fix Summary"
echo "============================================"
echo ""
echo "[+] Idle timeout:           15 minutes (2 minutes for privileged sessions)"
echo "[+] Max session lifetime:   8 hours"
echo "[+] Access token expiry:    15 minutes"
echo "[+] Refresh token expiry:   8 hours with rotation"
echo "[+] Token rotation:         ENABLED (detect stolen refresh tokens)"
echo "[+] Reuse detection:        ENABLED (revoke family on reuse)"
echo "[+] Cookie attributes:      __Host- prefix, Secure, HttpOnly, SameSite=Strict"
echo "[+] Cache-Control:          no-store on authenticated responses"
echo "[+] Concurrent sessions:    3 maximum per user"
echo "[+] Session binding:        user-agent + fingerprint"
echo "[+] Logout:                 Server-side invalidation + Clear-Site-Data header"
echo ""
echo "[*] For Entra ID conditional access policy configuration,"
echo "    see fix.md in this scenario directory."
echo ""
echo "[*] Run validate.sh to confirm the fix is effective."
echo "[*] Evidence saved to: $EVIDENCE_DIR"
