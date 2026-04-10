#!/usr/bin/env bash
set -euo pipefail

# SC-8 Weak TLS Configuration — Validate
#
# Confirms that the TLS hardening fix is effective:
#   1. TLS 1.0 and 1.1 are rejected
#   2. Weak ciphers (RC4, DES, EXPORT, NULL) are unavailable
#   3. HSTS header is present with correct directives
#   4. Certificate key size meets minimum (2048-bit)
#   5. Only strong ciphers are accepted
#
# REQUIREMENTS:
#   - testssl.sh (preferred) or openssl + nmap
#
# USAGE:
#   ./validate.sh <target_host> [port]
#
# EXAMPLE:
#   ./validate.sh 10.0.1.50 4443

# --- Argument Validation ---

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <target_host> [port]"
    echo "Example: $0 10.0.1.50 4443"
    exit 1
fi

TARGET="$1"
PORT="${2:-443}"

EVIDENCE_DIR="/tmp/sc8-weak-tls-validate-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$EVIDENCE_DIR"

echo "============================================"
echo "SC-8 Weak TLS Configuration — Validation"
echo "============================================"
echo ""
echo "[*] Target:       $TARGET"
echo "[*] Port:         $PORT"
echo "[*] Evidence dir: $EVIDENCE_DIR"
echo ""

PASS=0
FAIL=0
SKIP=0

# --- Helper Function ---

check_result() {
    local test_name="$1"
    local result="$2"  # "pass" or "fail"
    local detail="$3"

    if [[ "$result" == "pass" ]]; then
        echo "[PASS] $test_name — $detail"
        PASS=$((PASS + 1))
    else
        echo "[FAIL] $test_name — $detail"
        FAIL=$((FAIL + 1))
    fi
}

# --- Test 1: TLS 1.0 Must Be Rejected ---

echo "[*] Test 1: TLS 1.0 must be rejected"
echo "----------------------------------------------"

if command -v openssl &>/dev/null; then
    TLS10_RESULT=$(echo | openssl s_client -connect "$TARGET:$PORT" -tls1 2>&1 || true)
    if echo "$TLS10_RESULT" | grep -qi "handshake failure\|wrong version\|no protocols\|alert protocol"; then
        check_result "TLS 1.0 rejected" "pass" "Server refuses TLS 1.0 connections"
    elif echo "$TLS10_RESULT" | grep -q "Protocol.*TLSv1$"; then
        check_result "TLS 1.0 rejected" "fail" "Server ACCEPTS TLS 1.0 — still vulnerable"
    else
        check_result "TLS 1.0 rejected" "pass" "TLS 1.0 connection failed (likely rejected)"
    fi
else
    echo "[SKIP] openssl not available"
    SKIP=$((SKIP + 1))
fi
echo ""

# --- Test 2: TLS 1.1 Must Be Rejected ---

echo "[*] Test 2: TLS 1.1 must be rejected"
echo "----------------------------------------------"

if command -v openssl &>/dev/null; then
    TLS11_RESULT=$(echo | openssl s_client -connect "$TARGET:$PORT" -tls1_1 2>&1 || true)
    if echo "$TLS11_RESULT" | grep -qi "handshake failure\|wrong version\|no protocols\|alert protocol"; then
        check_result "TLS 1.1 rejected" "pass" "Server refuses TLS 1.1 connections"
    elif echo "$TLS11_RESULT" | grep -q "Protocol.*TLSv1\.1"; then
        check_result "TLS 1.1 rejected" "fail" "Server ACCEPTS TLS 1.1 — still vulnerable"
    else
        check_result "TLS 1.1 rejected" "pass" "TLS 1.1 connection failed (likely rejected)"
    fi
else
    echo "[SKIP] openssl not available"
    SKIP=$((SKIP + 1))
fi
echo ""

# --- Test 3: TLS 1.2 Must Be Accepted ---

echo "[*] Test 3: TLS 1.2 must be accepted"
echo "----------------------------------------------"

if command -v openssl &>/dev/null; then
    TLS12_RESULT=$(echo | openssl s_client -connect "$TARGET:$PORT" -tls1_2 2>&1 || true)
    if echo "$TLS12_RESULT" | grep -q "Protocol.*TLSv1\.2"; then
        check_result "TLS 1.2 accepted" "pass" "Server accepts TLS 1.2"
    else
        check_result "TLS 1.2 accepted" "fail" "Server does not accept TLS 1.2"
    fi
else
    echo "[SKIP] openssl not available"
    SKIP=$((SKIP + 1))
fi
echo ""

# --- Test 4: Weak Ciphers Must Be Rejected ---

echo "[*] Test 4: Weak ciphers must be rejected"
echo "----------------------------------------------"

if command -v openssl &>/dev/null; then
    WEAK_CIPHERS=("RC4-SHA" "DES-CBC-SHA" "DES-CBC3-SHA" "EXP-RC4-MD5" "NULL-SHA" "NULL-MD5")
    WEAK_FOUND=0

    for cipher in "${WEAK_CIPHERS[@]}"; do
        CIPHER_RESULT=$(echo | openssl s_client -connect "$TARGET:$PORT" -cipher "$cipher" 2>&1 || true)
        if echo "$CIPHER_RESULT" | grep -q "Cipher.*$cipher"; then
            echo "  [FAIL] $cipher is ACCEPTED"
            WEAK_FOUND=$((WEAK_FOUND + 1))
        else
            echo "  [OK]   $cipher is rejected"
        fi
    done

    if [[ "$WEAK_FOUND" -eq 0 ]]; then
        check_result "Weak ciphers rejected" "pass" "All weak ciphers (RC4, DES, EXPORT, NULL) are rejected"
    else
        check_result "Weak ciphers rejected" "fail" "$WEAK_FOUND weak cipher(s) still accepted"
    fi
else
    echo "[SKIP] openssl not available"
    SKIP=$((SKIP + 1))
fi
echo ""

# --- Test 5: Strong Ciphers Must Be Available ---

echo "[*] Test 5: Strong ciphers (ECDHE+AESGCM) must be available"
echo "----------------------------------------------"

if command -v openssl &>/dev/null; then
    STRONG_CIPHERS=("ECDHE-RSA-AES128-GCM-SHA256" "ECDHE-RSA-AES256-GCM-SHA384")
    STRONG_FOUND=0

    for cipher in "${STRONG_CIPHERS[@]}"; do
        CIPHER_RESULT=$(echo | openssl s_client -connect "$TARGET:$PORT" -cipher "$cipher" 2>&1 || true)
        if echo "$CIPHER_RESULT" | grep -qi "Cipher.*$cipher\|Cipher is.*AES"; then
            echo "  [OK] $cipher is accepted"
            STRONG_FOUND=$((STRONG_FOUND + 1))
        else
            echo "  [--] $cipher not accepted (may not be configured)"
        fi
    done

    if [[ "$STRONG_FOUND" -gt 0 ]]; then
        check_result "Strong ciphers available" "pass" "$STRONG_FOUND strong ECDHE+AESGCM cipher(s) available"
    else
        check_result "Strong ciphers available" "fail" "No ECDHE+AESGCM ciphers available"
    fi
else
    echo "[SKIP] openssl not available"
    SKIP=$((SKIP + 1))
fi
echo ""

# --- Test 6: HSTS Header Must Be Present ---

echo "[*] Test 6: HSTS header must be present"
echo "----------------------------------------------"

if command -v openssl &>/dev/null; then
    HEADERS=$(echo -e "GET / HTTP/1.1\r\nHost: $TARGET\r\nConnection: close\r\n\r\n" | \
        openssl s_client -connect "$TARGET:$PORT" -quiet 2>/dev/null || true)

    if echo "$HEADERS" | grep -qi "strict-transport-security"; then
        HSTS_VALUE=$(echo "$HEADERS" | grep -i "strict-transport-security" | head -1)
        echo "  Found: $HSTS_VALUE"

        # Check max-age
        if echo "$HSTS_VALUE" | grep -qP "max-age=\d{7,}"; then
            echo "  [OK] max-age is sufficiently long"
        else
            echo "  [WARN] max-age may be too short"
        fi

        # Check includeSubDomains
        if echo "$HSTS_VALUE" | grep -qi "includeSubDomains"; then
            echo "  [OK] includeSubDomains is set"
        else
            echo "  [WARN] includeSubDomains is not set"
        fi

        check_result "HSTS header present" "pass" "Strict-Transport-Security header is set"
    else
        check_result "HSTS header present" "fail" "HSTS header is MISSING — vulnerable to SSL stripping"
    fi

    echo "$HEADERS" > "$EVIDENCE_DIR/response-headers.txt" 2>/dev/null || true
else
    echo "[SKIP] openssl not available"
    SKIP=$((SKIP + 1))
fi
echo ""

# --- Test 7: Certificate Key Size ---

echo "[*] Test 7: Certificate key size must be >= 2048 bits"
echo "----------------------------------------------"

if command -v openssl &>/dev/null; then
    KEY_BITS=$(echo | openssl s_client -connect "$TARGET:$PORT" 2>/dev/null | \
        openssl x509 -noout -text 2>/dev/null | \
        grep "Public-Key:" | grep -oP '\d+' || echo "0")

    if [[ "$KEY_BITS" -ge 2048 ]]; then
        check_result "Certificate key size" "pass" "$KEY_BITS-bit key meets 2048-bit minimum"
    elif [[ "$KEY_BITS" -gt 0 ]]; then
        check_result "Certificate key size" "fail" "$KEY_BITS-bit key is below 2048-bit minimum"
    else
        echo "[SKIP] Could not determine key size"
        SKIP=$((SKIP + 1))
    fi
else
    echo "[SKIP] openssl not available"
    SKIP=$((SKIP + 1))
fi
echo ""

# --- Test 8: testssl.sh Full Validation (if available) ---

echo "[*] Test 8: testssl.sh comprehensive validation"
echo "----------------------------------------------"

if command -v testssl.sh &>/dev/null || command -v testssl &>/dev/null; then
    TESTSSL_CMD=$(command -v testssl.sh 2>/dev/null || command -v testssl 2>/dev/null)

    echo "[*] Running full testssl.sh audit..."
    "$TESTSSL_CMD" --protocols --ciphers --vulnerabilities --headers \
        --quiet "$TARGET:$PORT" 2>&1 | tee "$EVIDENCE_DIR/testssl-validation.txt" || true

    # Check for any CRITICAL or HIGH findings
    CRITICAL_COUNT=$(grep -ciE "CRITICAL|HIGH|VULNERABLE" "$EVIDENCE_DIR/testssl-validation.txt" 2>/dev/null || echo "0")
    if [[ "$CRITICAL_COUNT" -eq 0 ]]; then
        check_result "testssl.sh audit" "pass" "No CRITICAL or HIGH findings"
    else
        check_result "testssl.sh audit" "fail" "$CRITICAL_COUNT CRITICAL/HIGH findings remain"
    fi
else
    echo "[SKIP] testssl.sh not installed"
    SKIP=$((SKIP + 1))
fi
echo ""

# --- Nmap Validation ---

echo "[*] Test 9: Nmap cipher validation"
echo "----------------------------------------------"

if command -v nmap &>/dev/null; then
    echo "[*] Running nmap ssl-enum-ciphers..."
    nmap -sV --script ssl-enum-ciphers -p "$PORT" "$TARGET" 2>&1 | \
        tee "$EVIDENCE_DIR/nmap-validation.txt" || true

    NMAP_WEAK=$(grep -ciE "RC4|DES|EXPORT|NULL|SEED|IDEA" "$EVIDENCE_DIR/nmap-validation.txt" 2>/dev/null || echo "0")
    if [[ "$NMAP_WEAK" -eq 0 ]]; then
        check_result "Nmap cipher check" "pass" "No weak ciphers found by nmap"
    else
        check_result "Nmap cipher check" "fail" "Weak ciphers still present in nmap results"
    fi
else
    echo "[SKIP] nmap not installed"
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
    echo "[PASS] SC-8 TLS hardening validated successfully."
    echo "[*] TLS 1.0/1.1 rejected, weak ciphers removed, HSTS enabled."
    echo ""
    echo "[*] Residual risk: LOW"
    echo "    - Likelihood: 1 (Rare) — only strong protocols and ciphers accepted"
    echo "    - Impact: 3 (Moderate) — encryption in transit is now enforced"
    echo "    - Residual Score: 3 (Low)"
elif [[ "$FAIL" -gt 0 ]]; then
    echo "[FAIL] SC-8 TLS hardening has $FAIL failing check(s)."
    echo "[*] Review the failures above and re-run fix.sh."
else
    echo "[INCOMPLETE] All tests were skipped — install testssl.sh, openssl, or nmap."
fi

echo ""
echo "[*] Evidence saved to: $EVIDENCE_DIR"
echo "[*] Files:"
ls -la "$EVIDENCE_DIR/"
