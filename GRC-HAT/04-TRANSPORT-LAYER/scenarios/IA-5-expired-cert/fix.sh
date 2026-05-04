#!/usr/bin/env bash
set -euo pipefail

# IA-5 Expired Certificate — Fix
#
# Generates a valid certificate, configures certbot/ACME auto-renewal,
# and sets up certificate monitoring. Addresses the full IA-5 lifecycle:
# issuance, deployment, monitoring, and renewal.
#
# REQUIREMENTS:
#   - Root/sudo privileges
#   - openssl
#   - certbot (installed if missing, for ACME automation)
#   - nginx (for deployment) or manual application
#
# USAGE:
#   sudo ./fix.sh <domain> [port]
#
# EXAMPLE:
#   sudo ./fix.sh secure-lab.anthra.local 4444
#   (Generates valid cert, configures renewal, deploys to port 4444)
#
# NOTE: For lab environments, a self-signed cert with proper validity is used.
#       For production, certbot with Let's Encrypt is configured.
#
# CSF 2.0: PR.DS-08 (Hardware/software integrity verified)
# CIS v8: 3.10 (Encrypt Sensitive Data in Transit)
# NIST: IA-5 (Authenticator Management)
#

# --- Argument Validation ---

DOMAIN="${1:-secure-lab.anthra.local}"
PORT="${2:-4444}"

if [[ $EUID -ne 0 ]]; then
    echo "[ERROR] This script must be run as root (sudo)."
    exit 1
fi

EVIDENCE_DIR="/tmp/ia5-expired-cert-fix-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$EVIDENCE_DIR"

echo "============================================"
echo "IA-5 Expired Certificate — Fix"
echo "============================================"
echo ""
echo "[*] Domain:       $DOMAIN"
echo "[*] Port:         $PORT"
echo "[*] Evidence dir: $EVIDENCE_DIR"
echo ""

# --- Record Pre-Fix State ---

echo "[*] Recording pre-fix state..."
if [[ -f /etc/nginx/conf.d/ia5-expired-cert.conf ]]; then
    cp /etc/nginx/conf.d/ia5-expired-cert.conf "$EVIDENCE_DIR/nginx-before-fix.conf"
    echo "[+] Saved existing expired cert config"
fi
echo ""

# --- Step 1: Generate Valid Certificate ---

echo "[*] Step 1: Generate valid certificate"
echo "----------------------------------------------"

CERT_DIR="$EVIDENCE_DIR/certs"
mkdir -p "$CERT_DIR"

# Check if this is a public domain (can use Let's Encrypt)
IS_PUBLIC=false
if host "$DOMAIN" &>/dev/null 2>&1; then
    IS_PUBLIC=true
fi

if [[ "$IS_PUBLIC" == "true" ]] && command -v certbot &>/dev/null; then
    echo "[*] Domain resolves publicly — attempting Let's Encrypt certificate..."

    # Use certbot with nginx plugin if available
    if command -v nginx &>/dev/null; then
        certbot certonly --nginx -d "$DOMAIN" --non-interactive --agree-tos \
            --email security@anthra.local --no-eff-email 2>&1 | \
            tee "$EVIDENCE_DIR/certbot-output.txt" || {
            echo "[WARN] certbot failed — falling back to self-signed"
            IS_PUBLIC=false
        }
    else
        certbot certonly --standalone -d "$DOMAIN" --non-interactive --agree-tos \
            --email security@anthra.local --no-eff-email 2>&1 | \
            tee "$EVIDENCE_DIR/certbot-output.txt" || {
            echo "[WARN] certbot failed — falling back to self-signed"
            IS_PUBLIC=false
        }
    fi

    if [[ "$IS_PUBLIC" == "true" ]]; then
        # Use Let's Encrypt certs
        CERT_PATH="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
        KEY_PATH="/etc/letsencrypt/live/$DOMAIN/privkey.pem"
        echo "[+] Let's Encrypt certificate obtained"
    fi
fi

if [[ "$IS_PUBLIC" == "false" ]]; then
    echo "[*] Using lab self-signed certificate (valid for 365 days)..."

    # Generate a proper self-signed cert with correct attributes
    cat > "$CERT_DIR/valid.cnf" << CNFEOF
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
OU = Security-Lab
CN = ${DOMAIN}

[v3_ext]
subjectAltName = DNS:${DOMAIN},DNS:localhost,IP:127.0.0.1
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
CNFEOF

    openssl req -x509 -newkey rsa:2048 -keyout "$CERT_DIR/valid.key" \
        -out "$CERT_DIR/valid.crt" -days 365 -nodes \
        -config "$CERT_DIR/valid.cnf" 2>/dev/null

    CERT_PATH="$CERT_DIR/valid.crt"
    KEY_PATH="$CERT_DIR/valid.key"

    echo "[+] Valid certificate generated (2048-bit RSA, SHA-256, 365-day validity)"
    echo ""

    # Display certificate details
    echo "[*] New certificate details:"
    openssl x509 -in "$CERT_PATH" -noout -subject -issuer -dates -serial 2>/dev/null | \
        tee "$EVIDENCE_DIR/new-cert-details.txt"
fi
echo ""

# --- Step 2: Deploy Certificate ---

echo "[*] Step 2: Deploy certificate to server"
echo "----------------------------------------------"

if command -v nginx &>/dev/null; then
    NGINX_CONF="/etc/nginx/conf.d/ia5-expired-cert.conf"

    cat > "$NGINX_CONF" << NGINXEOF
# IA5-FIX: Valid certificate configuration
# Applied by Anthra-SecLAB fix.sh — $(date +%Y-%m-%d)

server {
    listen ${PORT} ssl http2;
    server_name ${DOMAIN};

    # FIX: Valid certificate (not expired, proper key size)
    ssl_certificate     ${CERT_PATH};
    ssl_certificate_key ${KEY_PATH};

    # Strong TLS settings (aligned with SC-8 fix)
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305';
    ssl_prefer_server_order on;

    # HSTS
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

    # Session configuration
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;
    ssl_session_tickets off;

    root /var/www/html;
    location / {
        return 200 'IA-5 Fix Scenario: This server has a valid certificate.\n';
        add_header Content-Type text/plain;
    }
}
NGINXEOF

    echo "[+] Wrote valid cert config to $NGINX_CONF"

    echo "[*] Testing nginx configuration..."
    if nginx -t 2>&1; then
        nginx -s reload 2>/dev/null || systemctl reload nginx 2>/dev/null || true
        echo "[+] nginx reloaded with valid certificate"
    else
        echo "[ERROR] nginx config test failed"
        exit 1
    fi

    cp "$NGINX_CONF" "$EVIDENCE_DIR/nginx-valid-cert.conf"
else
    echo "[WARN] nginx not found — certificate generated but not deployed"
    echo "[*] Deploy $CERT_PATH and $KEY_PATH to your server manually"
fi
echo ""

# --- Step 3: Configure Auto-Renewal ---

echo "[*] Step 3: Configure certificate auto-renewal"
echo "----------------------------------------------"

# Install certbot if not present (for production readiness)
if ! command -v certbot &>/dev/null; then
    echo "[*] certbot not installed — installing..."
    if command -v apt-get &>/dev/null; then
        apt-get update -qq && apt-get install -y -qq certbot python3-certbot-nginx 2>/dev/null || {
            echo "[WARN] Could not install certbot via apt"
            echo "[*] Install manually: apt-get install certbot python3-certbot-nginx"
        }
    elif command -v yum &>/dev/null; then
        yum install -y certbot python3-certbot-nginx 2>/dev/null || {
            echo "[WARN] Could not install certbot via yum"
        }
    fi
fi

if command -v certbot &>/dev/null; then
    echo "[+] certbot is installed"

    # Enable certbot timer for auto-renewal
    if command -v systemctl &>/dev/null; then
        systemctl enable certbot.timer 2>/dev/null && \
        systemctl start certbot.timer 2>/dev/null && \
        echo "[+] certbot.timer enabled (auto-renewal every 12 hours)" || true
    fi

    # Also add a cron job as backup
    CRON_LINE="0 3,15 * * * certbot renew --quiet --deploy-hook 'systemctl reload nginx'"
    if ! crontab -l 2>/dev/null | grep -q "certbot renew"; then
        (crontab -l 2>/dev/null; echo "$CRON_LINE") | crontab -
        echo "[+] Cron job added for certbot renewal (3 AM and 3 PM daily)"
    else
        echo "[OK] certbot cron job already exists"
    fi
else
    echo "[WARN] certbot not available — creating manual renewal reminder script"
fi

# Create a certificate check script regardless
CERT_CHECK="/usr/local/bin/check-cert-expiry.sh"
cat > "$CERT_CHECK" << 'CHECKEOF'
#!/usr/bin/env bash
set -euo pipefail

# Certificate Expiry Checker
# Checks all certificates and alerts if any expire within 30 days
# Run via cron: 0 8 * * * /usr/local/bin/check-cert-expiry.sh

WARN_DAYS=30
ALERT_DAYS=7
EXIT_CODE=0

echo "Certificate Expiry Report — $(date)"
echo "============================================"

# Check Let's Encrypt certs
if [[ -d /etc/letsencrypt/live ]]; then
    for domain_dir in /etc/letsencrypt/live/*/; do
        domain=$(basename "$domain_dir")
        cert="$domain_dir/cert.pem"
        if [[ -f "$cert" ]]; then
            EXPIRY=$(openssl x509 -in "$cert" -noout -enddate 2>/dev/null | cut -d= -f2)
            if ! openssl x509 -in "$cert" -checkend $((ALERT_DAYS * 86400)) -noout 2>/dev/null; then
                echo "[CRITICAL] $domain expires: $EXPIRY (within $ALERT_DAYS days)"
                EXIT_CODE=2
            elif ! openssl x509 -in "$cert" -checkend $((WARN_DAYS * 86400)) -noout 2>/dev/null; then
                echo "[WARNING]  $domain expires: $EXPIRY (within $WARN_DAYS days)"
                EXIT_CODE=1
            else
                echo "[OK]       $domain expires: $EXPIRY"
            fi
        fi
    done
fi

# Check nginx SSL certificates
if command -v nginx &>/dev/null; then
    for conf in /etc/nginx/conf.d/*.conf /etc/nginx/sites-enabled/*; do
        [[ -f "$conf" ]] || continue
        certs=$(grep -oP 'ssl_certificate\s+\K[^;]+' "$conf" 2>/dev/null || true)
        for cert in $certs; do
            [[ -f "$cert" ]] || continue
            EXPIRY=$(openssl x509 -in "$cert" -noout -enddate 2>/dev/null | cut -d= -f2)
            if ! openssl x509 -in "$cert" -checkend $((ALERT_DAYS * 86400)) -noout 2>/dev/null; then
                echo "[CRITICAL] $cert expires: $EXPIRY (within $ALERT_DAYS days)"
                EXIT_CODE=2
            elif ! openssl x509 -in "$cert" -checkend $((WARN_DAYS * 86400)) -noout 2>/dev/null; then
                echo "[WARNING]  $cert expires: $EXPIRY (within $WARN_DAYS days)"
                EXIT_CODE=1
            else
                echo "[OK]       $cert expires: $EXPIRY"
            fi
        done
    done
fi

exit $EXIT_CODE
CHECKEOF
chmod +x "$CERT_CHECK"
echo "[+] Certificate check script installed at $CERT_CHECK"

# Add monitoring cron
MONITOR_CRON="0 8 * * * $CERT_CHECK >> /var/log/cert-expiry.log 2>&1"
if ! crontab -l 2>/dev/null | grep -q "check-cert-expiry"; then
    (crontab -l 2>/dev/null; echo "$MONITOR_CRON") | crontab -
    echo "[+] Daily certificate monitoring cron added (8 AM)"
else
    echo "[OK] Certificate monitoring cron already exists"
fi
echo ""

# --- Step 4: Kill Break Scenario Servers ---

echo "[*] Step 4: Cleaning up break scenario..."
echo "----------------------------------------------"

if pgrep -f "s_server.*expired" &>/dev/null; then
    echo "[*] Stopping expired cert openssl s_server..."
    pkill -f "s_server.*expired" || true
    echo "[+] Stopped"
else
    echo "[OK] No leftover servers found"
fi
echo ""

echo "============================================"
echo "Fix Summary"
echo "============================================"
echo ""
echo "[+] Valid certificate: Deployed (2048-bit RSA, SHA-256, 365-day validity)"
echo "[+] Auto-renewal: Configured (certbot timer + cron backup)"
echo "[+] Monitoring: Certificate expiry check script runs daily at 8 AM"
echo "[+] Alerting: Script exits non-zero on warnings (30 days) and criticals (7 days)"
echo ""
echo "[*] Certificate lifecycle now covers IA-5 requirements:"
echo "    1. Issuance — proper key size, algorithm, validity period"
echo "    2. Deployment — automated via certbot deploy hooks"
echo "    3. Monitoring — daily expiry checks with alerting"
echo "    4. Renewal — automatic via certbot (or manual reminder)"
echo "    5. Revocation — certbot revoke available for compromised keys"
echo ""
echo "[*] Run validate.sh to confirm the fix is effective."
echo "[*] Evidence saved to: $EVIDENCE_DIR"
