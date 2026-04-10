#!/usr/bin/env bash
set -euo pipefail

# SC-8 Weak TLS Configuration — Detect
#
# Detects weak TLS configurations using:
#   1. testssl.sh — comprehensive TLS audit (protocols, ciphers, vulns)
#   2. nmap ssl-enum-ciphers — cipher suite enumeration
#   3. openssl s_client — manual protocol and cipher checks
#
# REQUIREMENTS:
#   - testssl.sh (https://github.com/drwetter/testssl.sh)
#   - nmap with ssl-enum-ciphers script
#   - openssl
#
# USAGE:
#   ./detect.sh <target_host> [port]
#
# EXAMPLE:
#   ./detect.sh 10.0.1.50 4443
#   ./detect.sh weak-tls-lab.anthra.local

# --- Argument Validation ---

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <target_host> [port]"
    echo "Example: $0 10.0.1.50 4443"
    echo ""
    echo "target_host: Hostname or IP to scan"
    echo "port:        TLS port to scan (default: 443)"
    exit 1
fi

TARGET="$1"
PORT="${2:-443}"

EVIDENCE_DIR="/tmp/sc8-weak-tls-detect-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$EVIDENCE_DIR"

echo "============================================"
echo "SC-8 Weak TLS Configuration — Detection"
echo "============================================"
echo ""
echo "[*] Target:       $TARGET"
echo "[*] Port:         $PORT"
echo "[*] Evidence dir: $EVIDENCE_DIR"
echo ""

FINDINGS=0

# --- Method 1: testssl.sh ---

echo "[*] Method 1: testssl.sh — TLS protocol and cipher audit"
echo "----------------------------------------------"

if command -v testssl.sh &>/dev/null || command -v testssl &>/dev/null; then
    TESTSSL_CMD=$(command -v testssl.sh 2>/dev/null || command -v testssl 2>/dev/null)

    echo "[*] Running protocol check..."
    "$TESTSSL_CMD" --protocols --quiet "$TARGET:$PORT" 2>&1 | \
        tee "$EVIDENCE_DIR/testssl-protocols.txt" || true
    echo ""

    echo "[*] Running cipher suite check..."
    "$TESTSSL_CMD" --ciphers --quiet "$TARGET:$PORT" 2>&1 | \
        tee "$EVIDENCE_DIR/testssl-ciphers.txt" || true
    echo ""

    echo "[*] Running vulnerability check (BEAST, POODLE, Sweet32, CRIME)..."
    "$TESTSSL_CMD" --vulnerabilities --quiet "$TARGET:$PORT" 2>&1 | \
        tee "$EVIDENCE_DIR/testssl-vulns.txt" || true
    echo ""

    echo "[*] Running HSTS check..."
    "$TESTSSL_CMD" --headers --quiet "$TARGET:$PORT" 2>&1 | \
        tee "$EVIDENCE_DIR/testssl-headers.txt" || true
    echo ""

    # Parse for findings
    if grep -qi "tls 1\s" "$EVIDENCE_DIR/testssl-protocols.txt" 2>/dev/null && \
       grep -qi "offered" "$EVIDENCE_DIR/testssl-protocols.txt" 2>/dev/null; then
        echo "[ALERT] TLS 1.0 is offered — vulnerable to BEAST and POODLE"
        FINDINGS=$((FINDINGS + 1))
    fi

    if grep -qi "tls 1\.1" "$EVIDENCE_DIR/testssl-protocols.txt" 2>/dev/null && \
       grep -qi "offered" "$EVIDENCE_DIR/testssl-protocols.txt" 2>/dev/null; then
        echo "[ALERT] TLS 1.1 is offered — deprecated since March 2021 (RFC 8996)"
        FINDINGS=$((FINDINGS + 1))
    fi

    if grep -qiE "RC4|DES|EXPORT|NULL" "$EVIDENCE_DIR/testssl-ciphers.txt" 2>/dev/null; then
        echo "[ALERT] Weak ciphers detected (RC4, DES, EXPORT, or NULL)"
        FINDINGS=$((FINDINGS + 1))
    fi

    echo "[+] testssl.sh results saved to $EVIDENCE_DIR/testssl-*.txt"
else
    echo "[SKIP] testssl.sh not installed."
    echo "       Install: git clone https://github.com/drwetter/testssl.sh.git"
    echo "       Or:      apt-get install testssl.sh"
fi
echo ""

# --- Method 2: Nmap ssl-enum-ciphers ---

echo "[*] Method 2: Nmap ssl-enum-ciphers — cipher enumeration"
echo "----------------------------------------------"

if command -v nmap &>/dev/null; then
    echo "[*] Enumerating supported cipher suites..."
    nmap -sV --script ssl-enum-ciphers -p "$PORT" "$TARGET" 2>&1 | \
        tee "$EVIDENCE_DIR/nmap-ssl-enum.txt" || true
    echo ""

    # Parse nmap output for weak ciphers
    if grep -qiE "TLSv1\.0" "$EVIDENCE_DIR/nmap-ssl-enum.txt" 2>/dev/null; then
        echo "[ALERT] Nmap confirms TLS 1.0 is supported"
        FINDINGS=$((FINDINGS + 1))
    fi

    if grep -qiE "RC4|DES|EXPORT|NULL|SEED|IDEA" "$EVIDENCE_DIR/nmap-ssl-enum.txt" 2>/dev/null; then
        echo "[ALERT] Nmap found weak cipher suites"
        grep -iE "RC4|DES|EXPORT|NULL|SEED|IDEA" "$EVIDENCE_DIR/nmap-ssl-enum.txt" | \
            tee "$EVIDENCE_DIR/nmap-weak-ciphers.txt" || true
        FINDINGS=$((FINDINGS + 1))
    fi

    # Check for grade
    if grep -qi "least strength:" "$EVIDENCE_DIR/nmap-ssl-enum.txt" 2>/dev/null; then
        echo ""
        echo "[*] Nmap cipher strength assessment:"
        grep -i "least strength:" "$EVIDENCE_DIR/nmap-ssl-enum.txt" || true
    fi

    echo ""
    echo "[+] Nmap results saved to $EVIDENCE_DIR/nmap-ssl-enum.txt"
else
    echo "[SKIP] nmap not installed. Install with: apt-get install nmap"
fi
echo ""

# --- Method 3: OpenSSL Manual Checks ---

echo "[*] Method 3: OpenSSL — manual protocol and cipher checks"
echo "----------------------------------------------"

if command -v openssl &>/dev/null; then
    # Test TLS 1.0
    echo "[*] Testing TLS 1.0 support..."
    if echo | openssl s_client -connect "$TARGET:$PORT" -tls1 2>/dev/null | \
       grep -q "Protocol.*TLSv1$"; then
        echo "[ALERT] TLS 1.0 is SUPPORTED — deprecated and vulnerable"
        FINDINGS=$((FINDINGS + 1))
    elif echo | openssl s_client -connect "$TARGET:$PORT" -tls1 2>&1 | \
         grep -qi "handshake failure\|wrong version\|no protocols"; then
        echo "[OK] TLS 1.0 is NOT supported"
    else
        echo "[INFO] TLS 1.0 test inconclusive (openssl may not support -tls1 flag)"
    fi

    # Test TLS 1.1
    echo "[*] Testing TLS 1.1 support..."
    if echo | openssl s_client -connect "$TARGET:$PORT" -tls1_1 2>/dev/null | \
       grep -q "Protocol.*TLSv1\.1"; then
        echo "[ALERT] TLS 1.1 is SUPPORTED — deprecated since RFC 8996"
        FINDINGS=$((FINDINGS + 1))
    elif echo | openssl s_client -connect "$TARGET:$PORT" -tls1_1 2>&1 | \
         grep -qi "handshake failure\|wrong version\|no protocols"; then
        echo "[OK] TLS 1.1 is NOT supported"
    else
        echo "[INFO] TLS 1.1 test inconclusive"
    fi

    # Test TLS 1.2
    echo "[*] Testing TLS 1.2 support..."
    if echo | openssl s_client -connect "$TARGET:$PORT" -tls1_2 2>/dev/null | \
       grep -q "Protocol.*TLSv1\.2"; then
        echo "[OK] TLS 1.2 is supported"
    else
        echo "[WARN] TLS 1.2 may not be supported"
    fi

    # Test TLS 1.3
    echo "[*] Testing TLS 1.3 support..."
    if echo | openssl s_client -connect "$TARGET:$PORT" -tls1_3 2>/dev/null | \
       grep -q "Protocol.*TLSv1\.3"; then
        echo "[OK] TLS 1.3 is supported"
    else
        echo "[INFO] TLS 1.3 is not supported (recommended but not required)"
    fi
    echo ""

    # Test specific weak ciphers
    echo "[*] Testing specific weak ciphers..."
    WEAK_CIPHERS=("RC4-SHA" "DES-CBC-SHA" "DES-CBC3-SHA" "EXP-RC4-MD5" "NULL-SHA" "NULL-MD5")
    for cipher in "${WEAK_CIPHERS[@]}"; do
        if echo | openssl s_client -connect "$TARGET:$PORT" -cipher "$cipher" 2>/dev/null | \
           grep -q "Cipher.*$cipher"; then
            echo "[ALERT] Weak cipher ACCEPTED: $cipher"
            FINDINGS=$((FINDINGS + 1))
        else
            echo "[OK] Weak cipher rejected: $cipher"
        fi
    done
    echo ""

    # Check HSTS header
    echo "[*] Checking for HSTS header..."
    HEADERS=$(echo -e "GET / HTTP/1.1\r\nHost: $TARGET\r\nConnection: close\r\n\r\n" | \
        openssl s_client -connect "$TARGET:$PORT" -quiet 2>/dev/null || true)

    if echo "$HEADERS" | grep -qi "strict-transport-security"; then
        echo "[OK] HSTS header is present"
        echo "$HEADERS" | grep -i "strict-transport-security" | \
            tee "$EVIDENCE_DIR/hsts-header.txt"
    else
        echo "[ALERT] HSTS header is MISSING — vulnerable to SSL stripping"
        FINDINGS=$((FINDINGS + 1))
    fi
    echo ""

    # Check certificate details
    echo "[*] Checking certificate details..."
    echo | openssl s_client -connect "$TARGET:$PORT" 2>/dev/null | \
        openssl x509 -noout -text 2>/dev/null | \
        grep -E "Issuer:|Subject:|Not Before|Not After|Public-Key:|Signature Algorithm:" | \
        tee "$EVIDENCE_DIR/cert-details.txt" || true

    # Check key size
    KEY_BITS=$(echo | openssl s_client -connect "$TARGET:$PORT" 2>/dev/null | \
        openssl x509 -noout -text 2>/dev/null | \
        grep "Public-Key:" | grep -oP '\d+' || echo "unknown")

    if [[ "$KEY_BITS" != "unknown" ]] && [[ "$KEY_BITS" -lt 2048 ]]; then
        echo "[ALERT] Certificate key size is $KEY_BITS bits — below 2048-bit minimum"
        FINDINGS=$((FINDINGS + 1))
    elif [[ "$KEY_BITS" != "unknown" ]]; then
        echo "[OK] Certificate key size: $KEY_BITS bits"
    fi
else
    echo "[SKIP] openssl not installed."
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
    echo "[ALERT] Weak TLS configuration detected!"
    echo ""
    echo "[*] Key risks:"
    echo "    - TLS 1.0/1.1 enables BEAST and POODLE downgrade attacks"
    echo "    - Weak ciphers (RC4, DES) can be broken with moderate compute"
    echo "    - Missing HSTS allows SSL stripping (Moxie Marlinspike, 2009)"
    echo "    - Small key sizes are brute-forceable"
    echo ""
    echo "[*] Run fix.sh to enforce TLS 1.2+ with strong cipher suites."
else
    echo "[OK] No weak TLS configurations detected."
fi

echo ""
echo "[*] Evidence saved to: $EVIDENCE_DIR"
echo "[*] Files:"
ls -la "$EVIDENCE_DIR/"
