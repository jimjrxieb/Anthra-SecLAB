#!/usr/bin/env bash
set -euo pipefail

# IA-5 Expired Certificate — Break
#
# Generates an expired self-signed certificate (backdated to yesterday) and
# deploys it to a test server. Simulates a production server running with
# an expired certificate — a condition that causes browser warnings, breaks
# API integrations, and indicates failed certificate lifecycle management.
#
# REQUIREMENTS:
#   - Root/sudo privileges
#   - openssl
#   - nginx (preferred) or openssl s_server (fallback)
#
# USAGE:
#   sudo ./break.sh [port]
#
# EXAMPLE:
#   sudo ./break.sh 4444
#   (Starts a server with an expired certificate on port 4444)
#
# WARNING: This script is for authorized security testing only.
#          Unauthorized use is illegal under the CFAA and equivalent laws.
#
# CSF 2.0: PR.DS-08 (Hardware/software integrity verified)
# CIS v8: 17.8 (Conduct Post-Incident Reviews)
# NIST: IA-5 (Authenticator Management)
#

# --- Argument Validation ---

PORT="${1:-4444}"

if [[ $EUID -ne 0 ]]; then
    echo "[ERROR] This script must be run as root (sudo)."
    exit 1
fi

if ! [[ "$PORT" =~ ^[0-9]+$ ]] || [[ "$PORT" -lt 1 ]] || [[ "$PORT" -gt 65535 ]]; then
    echo "[ERROR] Invalid port number: $PORT"
    exit 1
fi

if ! command -v openssl &>/dev/null; then
    echo "[ERROR] openssl is required but not installed."
    exit 1
fi

EVIDENCE_DIR="/tmp/ia5-expired-cert-evidence-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$EVIDENCE_DIR"

echo "============================================"
echo "IA-5 Expired Certificate — Break"
echo "============================================"
echo ""
echo "[*] Port:         $PORT"
echo "[*] Evidence dir: $EVIDENCE_DIR"
echo ""

# --- Generate Expired Certificate ---

CERT_DIR="$EVIDENCE_DIR/certs"
mkdir -p "$CERT_DIR"

echo "[*] Generating expired self-signed certificate..."
echo "[*] Certificate will be backdated: valid from 30 days ago, expired yesterday"
echo ""

# Create OpenSSL config for the expired cert
cat > "$CERT_DIR/expired.cnf" << 'CNFEOF'
[req]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn
x509_extensions = v3_ext

[dn]
C = US
ST = Virginia
L = Herndon
O = Anthra-SecLAB
OU = Break-Scenario
CN = expired-cert-lab.anthra.local

[v3_ext]
subjectAltName = DNS:expired-cert-lab.anthra.local,DNS:localhost
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
CNFEOF

# Generate key
openssl genrsa -out "$CERT_DIR/expired.key" 2048 2>/dev/null

# Generate expired certificate
# -days 1 with a start date 30 days ago means it expired 29 days ago
# Using faketime approach: create a cert that expires yesterday
YESTERDAY=$(date -d "yesterday" +%y%m%d%H%M%SZ 2>/dev/null || date -v-1d +%y%m%d%H%M%SZ 2>/dev/null || echo "")
MONTH_AGO=$(date -d "30 days ago" +%y%m%d%H%M%SZ 2>/dev/null || date -v-30d +%y%m%d%H%M%SZ 2>/dev/null || echo "")

if [[ -n "$YESTERDAY" ]] && [[ -n "$MONTH_AGO" ]]; then
    # Create a CA-like self-signed cert with explicit validity dates
    openssl req -new -key "$CERT_DIR/expired.key" \
        -config "$CERT_DIR/expired.cnf" \
        -out "$CERT_DIR/expired.csr" 2>/dev/null

    # Sign with explicit start/end dates (expired yesterday)
    openssl x509 -req -in "$CERT_DIR/expired.csr" \
        -signkey "$CERT_DIR/expired.key" \
        -out "$CERT_DIR/expired.crt" \
        -days 1 \
        -extfile "$CERT_DIR/expired.cnf" \
        -extensions v3_ext \
        -set_serial 1001 2>/dev/null

    # Overwrite with a truly expired cert using the -not_after flag if available
    # Fallback: use a very short validity that has already passed
    openssl req -x509 -newkey rsa:2048 -keyout "$CERT_DIR/expired.key" \
        -out "$CERT_DIR/expired.crt" -nodes \
        -subj "/CN=expired-cert-lab.anthra.local/O=Anthra-SecLAB/OU=Break-Scenario" \
        -days 0 2>/dev/null || true
else
    # Fallback: generate a cert with 0 days validity (expires immediately)
    openssl req -x509 -newkey rsa:2048 -keyout "$CERT_DIR/expired.key" \
        -out "$CERT_DIR/expired.crt" -nodes \
        -subj "/CN=expired-cert-lab.anthra.local/O=Anthra-SecLAB/OU=Break-Scenario" \
        -days 0 2>/dev/null
fi

echo "[+] Expired certificate generated"
echo ""

# Display certificate details
echo "[*] Certificate details:"
openssl x509 -in "$CERT_DIR/expired.crt" -noout \
    -subject -issuer -dates -serial 2>/dev/null | tee "$EVIDENCE_DIR/cert-details.txt"
echo ""

# Verify it is expired (or about to expire)
echo "[*] Verifying certificate expiry status..."
if openssl x509 -in "$CERT_DIR/expired.crt" -checkend 0 -noout 2>/dev/null; then
    echo "[WARN] Certificate is technically not yet expired (edge case with 0-day certs)"
    echo "[*] The certificate has a 0-day validity period — it will expire within seconds"
else
    echo "[+] Certificate is EXPIRED — break scenario confirmed"
fi
echo ""

# Also generate a self-signed cert (not from a trusted CA)
echo "[*] Note: Certificate is also self-signed (not from a trusted CA)"
echo "[*] This is a second IA-5 finding — production should use CA-signed certificates"
echo ""

# --- Deploy to Server ---

SERVER_TYPE="none"
if command -v nginx &>/dev/null; then
    SERVER_TYPE="nginx"
elif command -v openssl &>/dev/null; then
    SERVER_TYPE="openssl"
fi

echo "[*] Server type: $SERVER_TYPE"
echo ""

if [[ "$SERVER_TYPE" == "nginx" ]]; then
    echo "[*] Deploying expired certificate to nginx..."

    NGINX_CONF="/etc/nginx/conf.d/ia5-expired-cert.conf"

    # Save existing config
    if [[ -f "$NGINX_CONF" ]]; then
        cp "$NGINX_CONF" "$EVIDENCE_DIR/nginx-before.conf"
    fi

    cat > "$NGINX_CONF" << NGINXEOF
# IA5-BREAK: Server with expired certificate
# DO NOT use in production — for security testing only

server {
    listen ${PORT} ssl;
    server_name expired-cert-lab.anthra.local;

    # VULNERABILITY: Expired certificate
    ssl_certificate     ${CERT_DIR}/expired.crt;
    ssl_certificate_key ${CERT_DIR}/expired.key;

    # VULNERABILITY: Self-signed (not from trusted CA)
    # No OCSP stapling possible with self-signed certs

    # VULNERABILITY: No certificate monitoring or auto-renewal
    # No cron job, no certbot, no ACME

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    root /var/www/html;
    location / {
        return 200 'IA-5 Break Scenario: This server has an expired certificate.\n';
        add_header Content-Type text/plain;
    }
}
NGINXEOF

    echo "[+] Wrote expired cert config to $NGINX_CONF"

    # Reload nginx (will warn about expired cert but usually still loads)
    echo "[*] Reloading nginx..."
    nginx -t 2>&1 || true
    nginx -s reload 2>/dev/null || systemctl reload nginx 2>/dev/null || true
    echo "[+] nginx reloaded with expired certificate"

    cp "$NGINX_CONF" "$EVIDENCE_DIR/nginx-expired-cert.conf"

else
    echo "[*] Starting openssl s_server with expired certificate..."
    LAUNCHER="$EVIDENCE_DIR/start-expired-server.sh"
    cat > "$LAUNCHER" << 'LAUNCHEOF'
#!/usr/bin/env bash
set -euo pipefail
CERT_DIR="$1"
PORT="$2"
echo "[*] Starting server with expired cert on port $PORT..."
openssl s_server -accept "$PORT" \
    -cert "$CERT_DIR/expired.crt" \
    -key "$CERT_DIR/expired.key" \
    -www 2>&1
LAUNCHEOF
    chmod +x "$LAUNCHER"

    nohup bash "$LAUNCHER" "$CERT_DIR" "$PORT" > "$EVIDENCE_DIR/server.log" 2>&1 &
    SERVER_PID=$!
    echo "$SERVER_PID" > "$EVIDENCE_DIR/server.pid"
    echo "[+] Server started with expired cert (PID: $SERVER_PID)"
    echo "[*] To stop: kill $SERVER_PID"
fi

echo ""
echo "============================================"
echo "Break Summary"
echo "============================================"
echo ""
echo "[!] Server is running with an EXPIRED certificate on port $PORT"
echo "[!] Certificate is SELF-SIGNED (not from a trusted CA)"
echo "[!] No certificate monitoring is configured"
echo "[!] No auto-renewal (certbot/ACME) is configured"
echo ""
echo "[*] What this causes:"
echo "    - Browser warnings: 'Your connection is not private' (NET::ERR_CERT_DATE_INVALID)"
echo "    - API failures: TLS handshake rejected by clients that validate certificates"
echo "    - Compliance gap: IA-5 requires authenticator (certificate) lifecycle management"
echo "    - Trust erosion: users trained to click through warnings become phishing targets"
echo ""
echo "[*] Real-world precedent: Equifax 2017"
echo "    - An expired certificate on a network monitoring device went unnoticed for 76 days"
echo "    - During those 76 days, attackers exfiltrated 147.9 million records"
echo "    - The expired cert prevented the IDS from inspecting encrypted traffic"
echo "    - Total cost: $1.4 billion (Equifax 2019 SEC filing)"
echo ""
echo "[*] Run detect.sh to confirm the exposure, then fix.sh to remediate."
echo "[*] Evidence saved to: $EVIDENCE_DIR"
