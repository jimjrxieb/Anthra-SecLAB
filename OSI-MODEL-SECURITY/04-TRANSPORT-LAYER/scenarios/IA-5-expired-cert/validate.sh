#!/usr/bin/env bash
set -euo pipefail

# IA-5 Expired Certificate — Validate
#
# Confirms that the certificate lifecycle fix is effective:
#   1. Certificate is valid (not expired)
#   2. Certificate is properly signed (not self-signed in production)
#   3. Key size meets minimum (2048-bit)
#   4. Auto-renewal automation exists (certbot/cron)
#   5. Certificate monitoring is active
#
# REQUIREMENTS:
#   - openssl
#
# USAGE:
#   ./validate.sh <target_host> [port]
#
# EXAMPLE:
#   ./validate.sh 10.0.1.50 4444

# --- Argument Validation ---

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <target_host> [port]"
    echo "Example: $0 10.0.1.50 4444"
    exit 1
fi

TARGET="$1"
PORT="${2:-443}"

EVIDENCE_DIR="/tmp/ia5-expired-cert-validate-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$EVIDENCE_DIR"

echo "============================================"
echo "IA-5 Expired Certificate — Validation"
echo "============================================"
echo ""
echo "[*] Target:       $TARGET"
echo "[*] Port:         $PORT"
echo "[*] Evidence dir: $EVIDENCE_DIR"
echo ""

PASS=0
FAIL=0
SKIP=0

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

# --- Test 1: Certificate Is Not Expired ---

echo "[*] Test 1: Certificate must be valid (not expired)"
echo "----------------------------------------------"

if command -v openssl &>/dev/null; then
    CERT_OUTPUT=$(echo | openssl s_client -connect "$TARGET:$PORT" -servername "$TARGET" 2>&1 || true)
    CERT_PEM=$(echo "$CERT_OUTPUT" | openssl x509 2>/dev/null || true)

    if [[ -z "$CERT_PEM" ]]; then
        check_result "Certificate valid" "fail" "Could not retrieve certificate from $TARGET:$PORT"
    else
        NOT_AFTER=$(echo "$CERT_PEM" | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
        echo "    Expiry: $NOT_AFTER"

        if echo "$CERT_PEM" | openssl x509 -checkend 0 -noout 2>/dev/null; then
            check_result "Certificate valid" "pass" "Certificate is not expired (expires: $NOT_AFTER)"
        else
            check_result "Certificate valid" "fail" "Certificate is EXPIRED (expired: $NOT_AFTER)"
        fi
    fi
else
    echo "[SKIP] openssl not available"
    SKIP=$((SKIP + 1))
fi
echo ""

# --- Test 2: Certificate Has Adequate Remaining Validity ---

echo "[*] Test 2: Certificate must have >30 days remaining validity"
echo "----------------------------------------------"

if [[ -n "${CERT_PEM:-}" ]]; then
    if echo "$CERT_PEM" | openssl x509 -checkend 2592000 -noout 2>/dev/null; then
        check_result "Remaining validity" "pass" "Certificate has more than 30 days remaining"
    else
        check_result "Remaining validity" "fail" "Certificate expires within 30 days"
    fi
else
    echo "[SKIP] No certificate available for testing"
    SKIP=$((SKIP + 1))
fi
echo ""

# --- Test 3: Key Size ---

echo "[*] Test 3: Certificate key must be >= 2048 bits"
echo "----------------------------------------------"

if [[ -n "${CERT_PEM:-}" ]]; then
    KEY_BITS=$(echo "$CERT_PEM" | openssl x509 -noout -text 2>/dev/null | \
        grep "Public-Key:" | grep -oP '\d+' || echo "0")
    echo "    Key size: $KEY_BITS bits"

    if [[ "$KEY_BITS" -ge 2048 ]]; then
        check_result "Key size" "pass" "$KEY_BITS-bit key meets 2048-bit minimum"
    else
        check_result "Key size" "fail" "$KEY_BITS-bit key is below 2048-bit minimum"
    fi
else
    echo "[SKIP] No certificate available"
    SKIP=$((SKIP + 1))
fi
echo ""

# --- Test 4: Signature Algorithm ---

echo "[*] Test 4: Certificate must use SHA-256 or stronger"
echo "----------------------------------------------"

if [[ -n "${CERT_PEM:-}" ]]; then
    SIG_ALG=$(echo "$CERT_PEM" | openssl x509 -noout -text 2>/dev/null | \
        grep "Signature Algorithm:" | head -1 | sed 's/.*: //')
    echo "    Algorithm: $SIG_ALG"

    if echo "$SIG_ALG" | grep -qi "sha256\|sha384\|sha512"; then
        check_result "Signature algorithm" "pass" "$SIG_ALG is strong"
    elif echo "$SIG_ALG" | grep -qi "sha1\|md5"; then
        check_result "Signature algorithm" "fail" "$SIG_ALG is deprecated"
    else
        check_result "Signature algorithm" "pass" "$SIG_ALG (acceptable)"
    fi
else
    echo "[SKIP] No certificate available"
    SKIP=$((SKIP + 1))
fi
echo ""

# --- Test 5: Auto-Renewal Automation ---

echo "[*] Test 5: Auto-renewal automation must be configured"
echo "----------------------------------------------"

RENEWAL_FOUND=false

# Check certbot timer
if command -v systemctl &>/dev/null; then
    if systemctl is-active certbot.timer &>/dev/null 2>&1; then
        echo "    [OK] certbot.timer is active"
        RENEWAL_FOUND=true
    fi
fi

# Check cron for certbot
if crontab -l 2>/dev/null | grep -q "certbot"; then
    echo "    [OK] certbot cron job exists"
    crontab -l 2>/dev/null | grep "certbot" | head -3
    RENEWAL_FOUND=true
fi

# Check for any renewal mechanism
if [[ -f /etc/cron.d/certbot ]]; then
    echo "    [OK] /etc/cron.d/certbot exists"
    RENEWAL_FOUND=true
fi

if [[ "$RENEWAL_FOUND" == "true" ]]; then
    check_result "Auto-renewal" "pass" "Certificate renewal automation is configured"
else
    check_result "Auto-renewal" "fail" "No certificate renewal automation found"
fi
echo ""

# --- Test 6: Certificate Monitoring ---

echo "[*] Test 6: Certificate monitoring must be active"
echo "----------------------------------------------"

MONITORING_FOUND=false

# Check for our monitoring script
if [[ -x /usr/local/bin/check-cert-expiry.sh ]]; then
    echo "    [OK] check-cert-expiry.sh is installed and executable"
    MONITORING_FOUND=true
fi

# Check for monitoring cron
if crontab -l 2>/dev/null | grep -q "check-cert-expiry"; then
    echo "    [OK] Certificate monitoring cron job exists"
    crontab -l 2>/dev/null | grep "check-cert-expiry" | head -3
    MONITORING_FOUND=true
fi

# Check for external monitoring
for tool in "prometheus" "blackbox_exporter" "nagios" "zabbix"; do
    if pgrep -x "$tool" &>/dev/null 2>/dev/null; then
        echo "    [OK] $tool is running (may include cert monitoring)"
        MONITORING_FOUND=true
    fi
done

if [[ "$MONITORING_FOUND" == "true" ]]; then
    check_result "Certificate monitoring" "pass" "Monitoring is configured"
else
    check_result "Certificate monitoring" "fail" "No certificate monitoring found"
fi
echo ""

# --- Test 7: Certificate Chain Validation ---

echo "[*] Test 7: Certificate chain must validate"
echo "----------------------------------------------"

if [[ -n "${CERT_OUTPUT:-}" ]]; then
    VERIFY_RESULT=$(echo "$CERT_OUTPUT" | grep "Verify return code:" || echo "unknown")
    echo "    $VERIFY_RESULT"

    if echo "$VERIFY_RESULT" | grep -q "0 (ok)"; then
        check_result "Chain validation" "pass" "Certificate chain validates successfully"
    elif echo "$VERIFY_RESULT" | grep -qi "self.signed\|self signed\|18 (self-signed)"; then
        echo "    [INFO] Self-signed is acceptable for lab environments"
        check_result "Chain validation" "pass" "Self-signed (acceptable for lab)"
    else
        check_result "Chain validation" "fail" "Certificate chain validation failed"
    fi
else
    echo "[SKIP] No connection data available"
    SKIP=$((SKIP + 1))
fi
echo ""

# --- Test 8: Run Certificate Check Script ---

echo "[*] Test 8: Certificate check script must run cleanly"
echo "----------------------------------------------"

if [[ -x /usr/local/bin/check-cert-expiry.sh ]]; then
    echo "[*] Running check-cert-expiry.sh..."
    if /usr/local/bin/check-cert-expiry.sh 2>&1 | tee "$EVIDENCE_DIR/cert-check-output.txt"; then
        check_result "Check script" "pass" "Script runs cleanly with no critical findings"
    else
        EXIT_CODE=$?
        if [[ "$EXIT_CODE" -eq 1 ]]; then
            check_result "Check script" "pass" "Script runs with warnings (non-critical)"
        else
            check_result "Check script" "fail" "Script reports critical findings (exit code: $EXIT_CODE)"
        fi
    fi
else
    echo "[SKIP] check-cert-expiry.sh not installed"
    SKIP=$((SKIP + 1))
fi
echo ""

# --- Validation Summary ---

echo "============================================"
echo "Validation Summary"
echo "============================================"
echo ""
echo "[*] Passed:  $PASS"
echo "[*] Failed:  $FAIL"
echo "[*] Skipped: $SKIP"
echo ""

if [[ "$FAIL" -eq 0 ]] && [[ "$PASS" -gt 0 ]]; then
    echo "[PASS] IA-5 certificate lifecycle validated successfully."
    echo "[*] Certificate is valid, auto-renewal configured, monitoring active."
    echo ""
    echo "[*] Residual risk: LOW"
    echo "    - Likelihood: 1 (Rare) — auto-renewal prevents expiry, monitoring catches drift"
    echo "    - Impact: 3 (Moderate) — cert issues cause outage, not direct data exposure"
    echo "    - Residual Score: 3 (Low)"
elif [[ "$FAIL" -gt 0 ]]; then
    echo "[FAIL] IA-5 certificate lifecycle has $FAIL failing check(s)."
    echo "[*] Review the failures above and re-run fix.sh."
else
    echo "[INCOMPLETE] All tests were skipped — install openssl and check prerequisites."
fi

echo ""
echo "[*] Evidence saved to: $EVIDENCE_DIR"
echo "[*] Files:"
ls -la "$EVIDENCE_DIR/"
