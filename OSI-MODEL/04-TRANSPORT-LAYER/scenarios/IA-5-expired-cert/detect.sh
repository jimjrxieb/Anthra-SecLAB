#!/usr/bin/env bash
set -euo pipefail

# IA-5 Expired Certificate — Detect
#
# Detects expired and misconfigured certificates using:
#   1. openssl s_client — connect and check certificate validity
#   2. Certificate expiry date verification
#   3. Self-signed certificate detection
#   4. Certificate chain validation
#
# REQUIREMENTS:
#   - openssl
#   - nmap (optional, for ssl-cert script)
#
# USAGE:
#   ./detect.sh <target_host> [port]
#
# EXAMPLE:
#   ./detect.sh 10.0.1.50 4444
#   ./detect.sh expired-cert-lab.anthra.local

# --- Argument Validation ---

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <target_host> [port]"
    echo "Example: $0 10.0.1.50 4444"
    echo ""
    echo "target_host: Hostname or IP to check"
    echo "port:        TLS port (default: 443)"
    exit 1
fi

TARGET="$1"
PORT="${2:-443}"

EVIDENCE_DIR="/tmp/ia5-expired-cert-detect-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$EVIDENCE_DIR"

echo "============================================"
echo "IA-5 Expired Certificate — Detection"
echo "============================================"
echo ""
echo "[*] Target:       $TARGET"
echo "[*] Port:         $PORT"
echo "[*] Evidence dir: $EVIDENCE_DIR"
echo ""

FINDINGS=0

# --- Method 1: OpenSSL Certificate Check ---

echo "[*] Method 1: OpenSSL — certificate validity check"
echo "----------------------------------------------"

if command -v openssl &>/dev/null; then
    # Connect and extract certificate
    echo "[*] Connecting to $TARGET:$PORT..."
    CERT_OUTPUT=$(echo | openssl s_client -connect "$TARGET:$PORT" -servername "$TARGET" 2>&1 || true)
    echo "$CERT_OUTPUT" > "$EVIDENCE_DIR/s_client-output.txt"

    # Extract the certificate
    CERT_PEM=$(echo "$CERT_OUTPUT" | openssl x509 2>/dev/null || true)

    if [[ -z "$CERT_PEM" ]]; then
        echo "[ERROR] Could not retrieve certificate from $TARGET:$PORT"
        echo "[*] The server may not be running or may not support TLS."
    else
        echo "[+] Certificate retrieved successfully"
        echo ""

        # Save certificate
        echo "$CERT_PEM" > "$EVIDENCE_DIR/server-cert.pem"

        # --- Check 1: Expiry Date ---
        echo "[*] Check 1: Certificate expiry date"
        NOT_BEFORE=$(echo "$CERT_PEM" | openssl x509 -noout -startdate 2>/dev/null | cut -d= -f2)
        NOT_AFTER=$(echo "$CERT_PEM" | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)

        echo "    Not Before: $NOT_BEFORE"
        echo "    Not After:  $NOT_AFTER"

        # Check if expired
        if echo "$CERT_PEM" | openssl x509 -checkend 0 -noout 2>/dev/null; then
            echo "    [OK] Certificate is currently valid"

            # Check if expiring within 30 days
            if ! echo "$CERT_PEM" | openssl x509 -checkend 2592000 -noout 2>/dev/null; then
                echo "    [WARN] Certificate expires within 30 days!"
                FINDINGS=$((FINDINGS + 1))
            fi

            # Check if expiring within 90 days
            if ! echo "$CERT_PEM" | openssl x509 -checkend 7776000 -noout 2>/dev/null; then
                echo "    [WARN] Certificate expires within 90 days"
            fi
        else
            echo "    [ALERT] Certificate is EXPIRED!"
            FINDINGS=$((FINDINGS + 1))
        fi
        echo ""

        # --- Check 2: Self-Signed Detection ---
        echo "[*] Check 2: Self-signed certificate detection"
        ISSUER=$(echo "$CERT_PEM" | openssl x509 -noout -issuer 2>/dev/null)
        SUBJECT=$(echo "$CERT_PEM" | openssl x509 -noout -subject 2>/dev/null)

        echo "    Issuer:  $ISSUER"
        echo "    Subject: $SUBJECT"

        # Compare issuer and subject (self-signed if they match)
        ISSUER_CN=$(echo "$ISSUER" | grep -oP 'CN\s*=\s*\K[^/,]+' || echo "")
        SUBJECT_CN=$(echo "$SUBJECT" | grep -oP 'CN\s*=\s*\K[^/,]+' || echo "")

        if [[ "$ISSUER_CN" == "$SUBJECT_CN" ]] && [[ -n "$ISSUER_CN" ]]; then
            echo "    [ALERT] Certificate is SELF-SIGNED (Issuer CN == Subject CN)"
            echo "    [*] Self-signed certificates are not trusted by browsers or API clients"
            FINDINGS=$((FINDINGS + 1))
        else
            echo "    [OK] Certificate appears to be CA-signed"
        fi
        echo ""

        # --- Check 3: Certificate Chain ---
        echo "[*] Check 3: Certificate chain validation"
        VERIFY_RESULT=$(echo "$CERT_OUTPUT" | grep "Verify return code:" || echo "unknown")
        echo "    $VERIFY_RESULT"

        if echo "$VERIFY_RESULT" | grep -q "0 (ok)"; then
            echo "    [OK] Certificate chain validates successfully"
        elif echo "$VERIFY_RESULT" | grep -qi "expired\|certificate has expired"; then
            echo "    [ALERT] Certificate chain validation failed — certificate expired"
            FINDINGS=$((FINDINGS + 1))
        elif echo "$VERIFY_RESULT" | grep -qi "self.signed\|self signed"; then
            echo "    [ALERT] Certificate chain validation failed — self-signed certificate"
            FINDINGS=$((FINDINGS + 1))
        else
            echo "    [WARN] Certificate chain validation returned non-zero"
            FINDINGS=$((FINDINGS + 1))
        fi
        echo ""

        # --- Check 4: Key Size ---
        echo "[*] Check 4: Certificate key size"
        KEY_INFO=$(echo "$CERT_PEM" | openssl x509 -noout -text 2>/dev/null | grep "Public-Key:" || echo "unknown")
        echo "    $KEY_INFO"

        KEY_BITS=$(echo "$KEY_INFO" | grep -oP '\d+' || echo "0")
        if [[ "$KEY_BITS" -lt 2048 ]] && [[ "$KEY_BITS" -gt 0 ]]; then
            echo "    [ALERT] Key size $KEY_BITS bits is below 2048-bit minimum"
            FINDINGS=$((FINDINGS + 1))
        elif [[ "$KEY_BITS" -ge 2048 ]]; then
            echo "    [OK] Key size meets minimum requirement"
        fi
        echo ""

        # --- Check 5: Signature Algorithm ---
        echo "[*] Check 5: Signature algorithm"
        SIG_ALG=$(echo "$CERT_PEM" | openssl x509 -noout -text 2>/dev/null | grep "Signature Algorithm:" | head -1 || echo "unknown")
        echo "    $SIG_ALG"

        if echo "$SIG_ALG" | grep -qi "sha1\|md5"; then
            echo "    [ALERT] Weak signature algorithm (SHA-1 or MD5)"
            FINDINGS=$((FINDINGS + 1))
        elif echo "$SIG_ALG" | grep -qi "sha256\|sha384\|sha512"; then
            echo "    [OK] Strong signature algorithm"
        fi
        echo ""

        # --- Check 6: Subject Alternative Names ---
        echo "[*] Check 6: Subject Alternative Names (SAN)"
        SAN=$(echo "$CERT_PEM" | openssl x509 -noout -text 2>/dev/null | \
            grep -A 1 "Subject Alternative Name" | tail -1 || echo "none")
        echo "    SANs: $SAN"

        if [[ "$SAN" == "none" ]] || [[ -z "$SAN" ]]; then
            echo "    [WARN] No SANs found — modern browsers require SAN extension"
            FINDINGS=$((FINDINGS + 1))
        fi
        echo ""

        # Save full certificate details
        echo "$CERT_PEM" | openssl x509 -noout -text > "$EVIDENCE_DIR/cert-full-details.txt" 2>/dev/null
    fi
else
    echo "[SKIP] openssl not installed."
fi
echo ""

# --- Method 2: Nmap ssl-cert Script ---

echo "[*] Method 2: Nmap — ssl-cert script"
echo "----------------------------------------------"

if command -v nmap &>/dev/null; then
    echo "[*] Running nmap ssl-cert..."
    nmap --script ssl-cert -p "$PORT" "$TARGET" 2>&1 | \
        tee "$EVIDENCE_DIR/nmap-ssl-cert.txt" || true

    if grep -qi "expired\|Not valid after.*$(date +%Y)" "$EVIDENCE_DIR/nmap-ssl-cert.txt" 2>/dev/null; then
        echo ""
        echo "[ALERT] Nmap confirms certificate expiry issue"
    fi
else
    echo "[SKIP] nmap not installed. Install with: apt-get install nmap"
fi
echo ""

# --- Method 3: Check for Renewal Automation ---

echo "[*] Method 3: Certificate renewal automation check"
echo "----------------------------------------------"

# Check for certbot
if command -v certbot &>/dev/null; then
    echo "[OK] certbot is installed"
    echo "[*] Checking certbot renewal status..."
    certbot certificates 2>/dev/null | tee "$EVIDENCE_DIR/certbot-certs.txt" || true

    # Check for auto-renewal timer/cron
    if systemctl is-active certbot.timer &>/dev/null 2>&1; then
        echo "[OK] certbot.timer is active (auto-renewal enabled)"
    elif crontab -l 2>/dev/null | grep -q "certbot"; then
        echo "[OK] certbot cron job exists"
    else
        echo "[ALERT] certbot is installed but no auto-renewal is configured"
        FINDINGS=$((FINDINGS + 1))
    fi
else
    echo "[ALERT] certbot is NOT installed — no ACME renewal automation"
    FINDINGS=$((FINDINGS + 1))
fi
echo ""

# Check for certificate monitoring
echo "[*] Checking for certificate monitoring..."
MONITORING_FOUND=false

# Check for common monitoring tools
for tool in "prometheus" "node_exporter" "blackbox_exporter" "nagios" "zabbix"; do
    if command -v "$tool" &>/dev/null || pgrep -x "$tool" &>/dev/null 2>/dev/null; then
        echo "[OK] $tool is running (may include cert monitoring)"
        MONITORING_FOUND=true
    fi
done

if [[ "$MONITORING_FOUND" == "false" ]]; then
    echo "[ALERT] No certificate monitoring tools detected"
    echo "[*] Without monitoring, expired certificates are only discovered by user complaints"
    FINDINGS=$((FINDINGS + 1))
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
    echo "[ALERT] Certificate management issues detected!"
    echo ""
    echo "[*] Key risks:"
    echo "    - Expired certificates cause outages and break integrations"
    echo "    - Self-signed certs train users to ignore browser warnings"
    echo "    - No auto-renewal means manual processes that humans forget"
    echo "    - No monitoring means expired certs go undetected"
    echo ""
    echo "[*] Equifax lesson: An expired cert on a monitoring device went"
    echo "    unnoticed for 76 days while 147.9M records were exfiltrated."
    echo ""
    echo "[*] Run fix.sh to generate a valid cert and set up auto-renewal."
else
    echo "[OK] No certificate management issues detected."
fi

echo ""
echo "[*] Evidence saved to: $EVIDENCE_DIR"
echo "[*] Files:"
ls -la "$EVIDENCE_DIR/"
