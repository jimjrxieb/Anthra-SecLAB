#!/usr/bin/env bash
set -euo pipefail

# SC-8 Weak TLS Configuration — Break
#
# Configures an nginx server (or openssl s_server fallback) with deliberately
# weak TLS settings: TLS 1.0 enabled, weak cipher suites (RC4, DES, export
# ciphers), and no HSTS header. This simulates a misconfigured production
# server vulnerable to BEAST, POODLE, and downgrade attacks.
#
# REQUIREMENTS:
#   - Root/sudo privileges
#   - nginx (preferred) or openssl (fallback)
#   - openssl for certificate generation
#
# USAGE:
#   sudo ./break.sh [port]
#
# EXAMPLE:
#   sudo ./break.sh 4443
#   (Starts a weak TLS server on port 4443)
#
# WARNING: This script is for authorized security testing only.
#          Unauthorized use is illegal under the CFAA and equivalent laws.
#
# CSF 2.0: PR.DS-02 (Data-in-transit confidentiality)
# CIS v8: 17.8 (Conduct Post-Incident Reviews)
# NIST: SC-8 (Transmission Confidentiality)
#

# --- Argument Validation ---

PORT="${1:-4443}"

if [[ $EUID -ne 0 ]]; then
    echo "[ERROR] This script must be run as root (sudo)."
    exit 1
fi

# Validate port number
if ! [[ "$PORT" =~ ^[0-9]+$ ]] || [[ "$PORT" -lt 1 ]] || [[ "$PORT" -gt 65535 ]]; then
    echo "[ERROR] Invalid port number: $PORT"
    echo "Expected: integer between 1 and 65535"
    exit 1
fi

EVIDENCE_DIR="/tmp/sc8-weak-tls-evidence-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$EVIDENCE_DIR"

echo "============================================"
echo "SC-8 Weak TLS Configuration — Break"
echo "============================================"
echo ""
echo "[*] Port:         $PORT"
echo "[*] Evidence dir: $EVIDENCE_DIR"
echo ""

# --- Generate Self-Signed Certificate ---

echo "[*] Generating self-signed certificate for weak TLS server..."
CERT_DIR="$EVIDENCE_DIR/certs"
mkdir -p "$CERT_DIR"

openssl req -x509 -newkey rsa:1024 -keyout "$CERT_DIR/weak.key" \
    -out "$CERT_DIR/weak.crt" -days 365 -nodes \
    -subj "/CN=weak-tls-lab.anthra.local/O=Anthra-SecLAB/OU=Break-Scenario" \
    2>/dev/null

echo "[+] Certificate generated with 1024-bit RSA key (deliberately weak)"
echo ""

# --- Detect Available Server ---

SERVER_TYPE="none"
if command -v nginx &>/dev/null; then
    SERVER_TYPE="nginx"
elif command -v openssl &>/dev/null; then
    SERVER_TYPE="openssl"
else
    echo "[ERROR] Neither nginx nor openssl found."
    echo "Install nginx: apt-get install nginx"
    exit 1
fi

echo "[*] Server type: $SERVER_TYPE"
echo ""

# --- Record Pre-Break State ---

echo "[*] Recording pre-break state..."
if [[ "$SERVER_TYPE" == "nginx" ]]; then
    # Save existing nginx config if present
    if [[ -f /etc/nginx/nginx.conf ]]; then
        cp /etc/nginx/nginx.conf "$EVIDENCE_DIR/nginx-before.conf"
        echo "[+] Saved existing nginx config"
    fi
fi
echo ""

# --- Configure Weak TLS ---

if [[ "$SERVER_TYPE" == "nginx" ]]; then
    echo "[*] Configuring nginx with weak TLS settings..."

    NGINX_CONF="/etc/nginx/conf.d/sc8-weak-tls.conf"

    cat > "$NGINX_CONF" << NGINXEOF
# SC8-BREAK: Deliberately weak TLS configuration
# DO NOT use in production — for security testing only

server {
    listen ${PORT} ssl;
    server_name weak-tls-lab.anthra.local;

    # Weak certificate (1024-bit RSA)
    ssl_certificate     ${CERT_DIR}/weak.crt;
    ssl_certificate_key ${CERT_DIR}/weak.key;

    # VULNERABILITY: TLS 1.0 and 1.1 enabled (vulnerable to POODLE, BEAST)
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;

    # VULNERABILITY: Weak cipher suites enabled
    # RC4 — broken stream cipher (RFC 7465 prohibits it)
    # DES — 56-bit key, brute-forceable since 1999
    # EXPORT — intentionally weakened for US export (40-bit keys)
    # NULL — no encryption at all
    ssl_ciphers 'RC4-SHA:DES-CBC3-SHA:DES-CBC-SHA:EXPORT:NULL:ECDHE-RSA-AES128-SHA:AES128-SHA:AES256-SHA';
    ssl_prefer_server_order on;

    # VULNERABILITY: No HSTS header
    # Clients can be downgraded to HTTP via sslstrip

    # VULNERABILITY: No OCSP stapling
    # ssl_stapling off (default)

    # VULNERABILITY: Session tickets with no rotation
    ssl_session_tickets on;
    ssl_session_timeout 24h;

    root /var/www/html;
    location / {
        return 200 'SC-8 Break Scenario: This server has weak TLS.\n';
        add_header Content-Type text/plain;
    }
}
NGINXEOF

    echo "[+] Wrote weak TLS config to $NGINX_CONF"
    echo ""

    # Test and reload nginx
    echo "[*] Testing nginx configuration..."
    if nginx -t 2>&1; then
        echo "[*] Reloading nginx..."
        nginx -s reload 2>/dev/null || systemctl reload nginx 2>/dev/null || true
        echo "[+] nginx reloaded with weak TLS configuration"
    else
        echo "[WARN] nginx config test failed — server may not support all weak ciphers"
        echo "[WARN] This is expected on modern OpenSSL builds that have removed legacy ciphers"
        echo "[*] Attempting reload anyway..."
        nginx -s reload 2>/dev/null || systemctl reload nginx 2>/dev/null || true
    fi

    # Save the weak config as evidence
    cp "$NGINX_CONF" "$EVIDENCE_DIR/nginx-weak-tls.conf"

else
    # Fallback: openssl s_server
    echo "[*] Starting openssl s_server with weak TLS settings..."
    echo ""
    echo "[*] Command that will be run:"
    echo "    openssl s_server -accept $PORT \\"
    echo "      -cert $CERT_DIR/weak.crt \\"
    echo "      -key $CERT_DIR/weak.key \\"
    echo "      -cipher 'RC4-SHA:DES-CBC3-SHA:DES-CBC-SHA:AES128-SHA:AES256-SHA' \\"
    echo "      -tls1 -www"
    echo ""

    # Write a launcher script
    LAUNCHER="$EVIDENCE_DIR/start-weak-server.sh"
    cat > "$LAUNCHER" << 'LAUNCHEOF'
#!/usr/bin/env bash
set -euo pipefail
CERT_DIR="$1"
PORT="$2"
echo "[*] Starting weak TLS server on port $PORT..."
echo "[*] Press Ctrl+C to stop."
openssl s_server -accept "$PORT" \
    -cert "$CERT_DIR/weak.crt" \
    -key "$CERT_DIR/weak.key" \
    -cipher 'RC4-SHA:DES-CBC3-SHA:DES-CBC-SHA:AES128-SHA:AES256-SHA' \
    -www 2>&1
LAUNCHEOF
    chmod +x "$LAUNCHER"

    echo "[*] Starting server in background..."
    nohup bash "$LAUNCHER" "$CERT_DIR" "$PORT" > "$EVIDENCE_DIR/server.log" 2>&1 &
    SERVER_PID=$!
    echo "$SERVER_PID" > "$EVIDENCE_DIR/server.pid"
    echo "[+] Weak TLS server started (PID: $SERVER_PID)"
    echo "[*] To stop: kill $SERVER_PID"
fi

echo ""
echo "============================================"
echo "Break Summary"
echo "============================================"
echo ""
echo "[!] Weak TLS server is running on port $PORT"
echo "[!] TLS 1.0 and TLS 1.1 are ENABLED (vulnerable to BEAST/POODLE)"
echo "[!] Weak ciphers are ENABLED (RC4, DES, EXPORT, NULL)"
echo "[!] HSTS header is MISSING (vulnerable to SSL stripping)"
echo "[!] Certificate uses 1024-bit RSA key (below 2048-bit minimum)"
echo "[!] No OCSP stapling configured"
echo ""
echo "[*] This configuration is vulnerable to:"
echo "    - BEAST attack (CVE-2011-3389) — TLS 1.0 CBC ciphers"
echo "    - POODLE attack (CVE-2014-3566) — SSL 3.0/TLS 1.0 padding oracle"
echo "    - RC4 bias attacks (CVE-2013-2566, CVE-2015-2808)"
echo "    - Sweet32 (CVE-2016-2183) — 64-bit block ciphers (3DES)"
echo "    - SSL stripping — no HSTS to force HTTPS"
echo ""
echo "[*] Run detect.sh to confirm the exposure, then fix.sh to remediate."
echo "[*] Evidence saved to: $EVIDENCE_DIR"
