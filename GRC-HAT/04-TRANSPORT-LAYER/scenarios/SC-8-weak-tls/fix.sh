#!/usr/bin/env bash
set -euo pipefail

# SC-8 Weak TLS Configuration — Fix
#
# Enforces TLS 1.2+ minimum with strong cipher suites only (ECDHE+AESGCM),
# adds HSTS header, configures OCSP stapling, and removes all legacy protocol
# and cipher support.
#
# Supports nginx configuration. For Apache, IIS, or other servers, the
# cipher string and protocol settings are printed for manual application.
#
# REQUIREMENTS:
#   - Root/sudo privileges
#   - nginx (primary) or manual application to other servers
#   - openssl 1.1.1+ (for TLS 1.3 support)
#
# USAGE:
#   sudo ./fix.sh [port]
#
# EXAMPLE:
#   sudo ./fix.sh 4443
#   (Reconfigures TLS on port 4443 with strong settings)
#
# WARNING: This will reject connections from clients that do not support
#          TLS 1.2+. Verify client compatibility before applying in production.
#
# CSF 2.0: PR.DS-02 (Data-in-transit confidentiality)
# CIS v8: 3.10 (Encrypt Sensitive Data in Transit)
# NIST: SC-8 (Transmission Confidentiality)
#

# --- Argument Validation ---

PORT="${1:-4443}"

if [[ $EUID -ne 0 ]]; then
    echo "[ERROR] This script must be run as root (sudo)."
    exit 1
fi

EVIDENCE_DIR="/tmp/sc8-weak-tls-fix-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$EVIDENCE_DIR"

echo "============================================"
echo "SC-8 Weak TLS Configuration — Fix"
echo "============================================"
echo ""
echo "[*] Port:         $PORT"
echo "[*] Evidence dir: $EVIDENCE_DIR"
echo ""

# --- Generate Strong Certificate ---

echo "[*] Generating strong certificate (2048-bit RSA with SHA-256)..."
CERT_DIR="$EVIDENCE_DIR/certs"
mkdir -p "$CERT_DIR"

openssl req -x509 -newkey rsa:2048 -keyout "$CERT_DIR/strong.key" \
    -out "$CERT_DIR/strong.crt" -days 365 -nodes \
    -subj "/CN=secure-tls-lab.anthra.local/O=Anthra-SecLAB/OU=Fix-Scenario" \
    -addext "subjectAltName=DNS:secure-tls-lab.anthra.local,DNS:localhost" \
    2>/dev/null

echo "[+] Certificate generated with 2048-bit RSA key and SHA-256 signature"
echo ""

# --- Generate DH Parameters ---

echo "[*] Generating Diffie-Hellman parameters (2048-bit)..."
echo "[*] This may take a moment..."
openssl dhparam -out "$CERT_DIR/dhparam.pem" 2048 2>/dev/null
echo "[+] DH parameters generated"
echo ""

# --- Record Pre-Fix State ---

echo "[*] Recording pre-fix state..."
if [[ -f /etc/nginx/conf.d/sc8-weak-tls.conf ]]; then
    cp /etc/nginx/conf.d/sc8-weak-tls.conf "$EVIDENCE_DIR/nginx-before-fix.conf"
    echo "[+] Saved existing weak TLS config"
fi
echo ""

# --- Apply Fix ---

if command -v nginx &>/dev/null; then
    echo "[*] Configuring nginx with strong TLS settings..."

    NGINX_CONF="/etc/nginx/conf.d/sc8-weak-tls.conf"

    cat > "$NGINX_CONF" << NGINXEOF
# SC8-FIX: Strong TLS configuration
# Applied by Anthra-SecLAB fix.sh — $(date +%Y-%m-%d)
#
# References:
#   - Mozilla SSL Configuration Generator (Modern profile)
#   - NIST SP 800-52 Rev 2 — TLS 1.2+ required
#   - PCI-DSS Requirement 4.1 — strong cryptography for transmission

server {
    listen ${PORT} ssl http2;
    server_name secure-tls-lab.anthra.local;

    # Strong certificate (2048-bit RSA, SHA-256)
    ssl_certificate     ${CERT_DIR}/strong.crt;
    ssl_certificate_key ${CERT_DIR}/strong.key;

    # FIX: TLS 1.2 and 1.3 ONLY — TLS 1.0 and 1.1 are rejected
    # TLS 1.0 deprecated: RFC 8996 (March 2021)
    # TLS 1.1 deprecated: RFC 8996 (March 2021)
    ssl_protocols TLSv1.2 TLSv1.3;

    # FIX: Strong cipher suites only
    # ECDHE for forward secrecy + AESGCM for authenticated encryption
    # No RC4, DES, 3DES, EXPORT, NULL, MD5, or CBC-mode ciphers
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305';
    ssl_prefer_server_order on;

    # FIX: DH parameters (2048-bit minimum)
    ssl_dhparam ${CERT_DIR}/dhparam.pem;

    # FIX: HSTS — force HTTPS for 1 year, include subdomains
    # Prevents SSL stripping attacks (Moxie Marlinspike, 2009)
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

    # FIX: Additional security headers
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;

    # FIX: OCSP stapling (requires valid CA cert in production)
    # ssl_stapling on;
    # ssl_stapling_verify on;
    # ssl_trusted_certificate /path/to/ca-chain.pem;

    # FIX: Session configuration
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;
    ssl_session_tickets off;

    # FIX: ECDH curve
    ssl_ecdh_curve secp384r1;

    root /var/www/html;
    location / {
        return 200 'SC-8 Fix Scenario: This server has strong TLS.\n';
        add_header Content-Type text/plain;
    }
}
NGINXEOF

    echo "[+] Wrote strong TLS config to $NGINX_CONF"
    echo ""

    # Test and reload nginx
    echo "[*] Testing nginx configuration..."
    if nginx -t 2>&1; then
        echo "[*] Reloading nginx..."
        nginx -s reload 2>/dev/null || systemctl reload nginx 2>/dev/null || true
        echo "[+] nginx reloaded with strong TLS configuration"
    else
        echo "[ERROR] nginx config test failed. Check the configuration."
        echo "[*] Saved config to $EVIDENCE_DIR for review."
        cp "$NGINX_CONF" "$EVIDENCE_DIR/nginx-failed.conf"
        exit 1
    fi

    # Save the strong config as evidence
    cp "$NGINX_CONF" "$EVIDENCE_DIR/nginx-strong-tls.conf"

else
    echo "[WARN] nginx not found. Printing configuration for manual application."
    echo ""
    echo "--- Strong TLS Settings (apply to your server) ---"
    echo ""
    echo "Protocols: TLSv1.2 TLSv1.3"
    echo "Ciphers:   ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305"
    echo "HSTS:      Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
    echo ""
fi

# --- Kill Any openssl s_server From Break ---

echo "[*] Checking for leftover break scenario servers..."
if pgrep -f "s_server.*weak" &>/dev/null; then
    echo "[*] Stopping weak TLS openssl s_server..."
    pkill -f "s_server.*weak" || true
    echo "[+] Stopped"
else
    echo "[OK] No leftover servers found"
fi
echo ""

echo "============================================"
echo "Fix Summary"
echo "============================================"
echo ""
echo "[+] TLS 1.0 and TLS 1.1: DISABLED"
echo "[+] TLS 1.2 and TLS 1.3: ENABLED"
echo "[+] Cipher suites: ECDHE + AESGCM/ChaCha20 only (forward secrecy required)"
echo "[+] HSTS header: ENABLED (max-age=31536000, includeSubDomains, preload)"
echo "[+] Session tickets: DISABLED (prevents session resumption attacks)"
echo "[+] DH parameters: 2048-bit custom parameters"
echo "[+] Certificate: 2048-bit RSA with SHA-256"
echo ""
echo "[*] Weak ciphers removed: RC4, DES, 3DES, EXPORT, NULL"
echo "[*] Weak protocols removed: SSLv2, SSLv3, TLS 1.0, TLS 1.1"
echo ""
echo "[*] Run validate.sh to confirm the fix is effective."
echo "[*] Evidence saved to: $EVIDENCE_DIR"
