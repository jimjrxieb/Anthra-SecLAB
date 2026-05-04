#!/usr/bin/env bash
# audit-tls-config.sh — L4 Transport Layer TLS configuration audit
# NIST: SC-8 (transmission confidentiality), SC-13 (cryptographic protection)
# Usage: ./audit-tls-config.sh host:port
#
# CSF 2.0: PR.DS-02 (Data-in-transit confidentiality)
# CIS v8: 3.10 (Encrypt Sensitive Data in Transit)
# NIST: SC-8 (Transmission Confidentiality)
#
set -euo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; NC='\033[0m'
PASS() { echo -e "${GREEN}[PASS]${NC} $*"; }
WARN() { echo -e "${YELLOW}[WARN]${NC} $*"; }
FAIL() { echo -e "${RED}[FAIL]${NC} $*"; }
INFO() { echo -e "       $*"; }

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 host:port"
    echo "  Example: $0 example.com:443"
    exit 1
fi

TARGET="$1"
HOST="${TARGET%%:*}"
PORT="${TARGET##*:}"

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
EVIDENCE_DIR="/tmp/jsa-evidence/tls-audit-${TIMESTAMP}"
mkdir -p "$EVIDENCE_DIR"

echo "======================================================"
echo " L4 TLS Audit — SC-8 / SC-13"
echo " Target: ${TARGET}"
echo " Evidence: ${EVIDENCE_DIR}"
echo " $(date)"
echo "======================================================"
echo ""

# ─── Helper: quick TLS handshake test ──────────────────────────────────────
tls_test() {
    local flag="$1"
    local label="$2"
    local out
    out=$(echo | timeout 5 openssl s_client -connect "${TARGET}" "${flag}" 2>&1 || true)
    echo "$out" > "${EVIDENCE_DIR}/tls-test-${label}.txt"
    if echo "$out" | grep -q "BEGIN CERTIFICATE"; then
        echo "ACCEPTED"
    else
        echo "REJECTED"
    fi
}

# ─── 1. Weak Protocol Tests ────────────────────────────────────────────────
echo "── 1. Weak Protocol Detection ──────────────────────────────────────"

RESULT=$(tls_test "-ssl3" "sslv3" || true)
if [[ "$RESULT" == "ACCEPTED" ]]; then
    FAIL "SSLv3 ACCEPTED — SC-8 violation. Must disable immediately."
else
    PASS "SSLv3 rejected"
fi

RESULT=$(tls_test "-tls1" "tls10" || true)
if [[ "$RESULT" == "ACCEPTED" ]]; then
    FAIL "TLS 1.0 ACCEPTED — SC-8 violation. PCI DSS prohibited since 2018."
else
    PASS "TLS 1.0 rejected"
fi

RESULT=$(tls_test "-tls1_1" "tls11" || true)
if [[ "$RESULT" == "ACCEPTED" ]]; then
    WARN "TLS 1.1 ACCEPTED — deprecated per RFC 8996. Disable and enforce TLS 1.2+."
else
    PASS "TLS 1.1 rejected"
fi

echo ""

# ─── 2. Modern Protocol Support ────────────────────────────────────────────
echo "── 2. Modern Protocol Support ──────────────────────────────────────"

RESULT=$(tls_test "-tls1_2" "tls12" || true)
if [[ "$RESULT" == "ACCEPTED" ]]; then
    PASS "TLS 1.2 supported — minimum baseline met"
else
    FAIL "TLS 1.2 NOT supported — SC-13 violation. No acceptable TLS version available."
fi

RESULT=$(tls_test "-tls1_3" "tls13" || true)
if [[ "$RESULT" == "ACCEPTED" ]]; then
    PASS "TLS 1.3 supported — preferred for forward secrecy"
else
    WARN "TLS 1.3 not supported — strongly recommended (forward secrecy, 0-RTT)"
fi

echo ""

# ─── 3. Certificate Validity ───────────────────────────────────────────────
echo "── 3. Certificate Validity ──────────────────────────────────────────"

CERT_OUT=$(echo | timeout 5 openssl s_client -connect "${TARGET}" 2>/dev/null | openssl x509 -noout -dates -subject -issuer 2>/dev/null || true)
echo "$CERT_OUT" > "${EVIDENCE_DIR}/cert-details.txt"

if [[ -z "$CERT_OUT" ]]; then
    FAIL "Could not retrieve certificate from ${TARGET}"
else
    NOT_AFTER=$(echo "$CERT_OUT" | grep "notAfter" | cut -d= -f2)
    SUBJECT=$(echo "$CERT_OUT" | grep "subject" | sed 's/subject=//')
    ISSUER=$(echo "$CERT_OUT" | grep "issuer" | sed 's/issuer=//')

    INFO "Subject : ${SUBJECT}"
    INFO "Issuer  : ${ISSUER}"
    INFO "Expires : ${NOT_AFTER}"

    if [[ -n "$NOT_AFTER" ]]; then
        EXPIRY_EPOCH=$(date -d "$NOT_AFTER" +%s 2>/dev/null || date -jf "%b %d %T %Y %Z" "$NOT_AFTER" +%s 2>/dev/null || echo 0)
        NOW_EPOCH=$(date +%s)
        DAYS_LEFT=$(( (EXPIRY_EPOCH - NOW_EPOCH) / 86400 ))

        if [[ $DAYS_LEFT -lt 0 ]]; then
            FAIL "Certificate EXPIRED ${DAYS_LEFT#-} days ago — SC-23 violation. Immediate renewal required."
        elif [[ $DAYS_LEFT -lt 30 ]]; then
            WARN "Certificate expires in ${DAYS_LEFT} days — IA-5 alert. Renew now before automated monitoring triggers."
        else
            PASS "Certificate valid for ${DAYS_LEFT} days"
        fi
    fi
fi

echo ""

# ─── 4. Key Size Check ─────────────────────────────────────────────────────
echo "── 4. Key Size ──────────────────────────────────────────────────────"

KEY_INFO=$(echo | timeout 5 openssl s_client -connect "${TARGET}" 2>/dev/null | openssl x509 -noout -text 2>/dev/null | grep -E "Public Key Algorithm|RSA Public-Key|Public-Key:" | head -5 || true)
echo "$KEY_INFO" > "${EVIDENCE_DIR}/key-info.txt"

if echo "$KEY_INFO" | grep -qi "rsaEncryption"; then
    KEY_BITS=$(echo "$KEY_INFO" | grep -oP '\d{3,5}' | head -1 || echo "unknown")
    if [[ "$KEY_BITS" =~ ^[0-9]+$ ]] && [[ "$KEY_BITS" -ge 2048 ]]; then
        PASS "RSA key size: ${KEY_BITS} bits (minimum 2048 met)"
    elif [[ "$KEY_BITS" =~ ^[0-9]+$ ]]; then
        FAIL "RSA key size: ${KEY_BITS} bits — SC-13 violation. Minimum 2048 required."
    else
        WARN "RSA key detected — could not parse bit length. Manual review needed."
    fi
elif echo "$KEY_INFO" | grep -qi "id-ecPublicKey\|EC\|ecdsa"; then
    KEY_BITS=$(echo "$KEY_INFO" | grep -oP '\d{3}' | head -1 || echo "unknown")
    if [[ "$KEY_BITS" =~ ^[0-9]+$ ]] && [[ "$KEY_BITS" -ge 256 ]]; then
        PASS "ECDSA key size: ${KEY_BITS} bits (minimum 256 met)"
    elif [[ "$KEY_BITS" =~ ^[0-9]+$ ]]; then
        FAIL "ECDSA key size: ${KEY_BITS} bits — SC-13 violation. Minimum 256 required."
    else
        WARN "ECDSA key detected — could not parse bit length. Manual review needed."
    fi
else
    WARN "Could not determine key algorithm. Manual verification required."
    INFO "Run: echo | openssl s_client -connect ${TARGET} 2>/dev/null | openssl x509 -noout -text | grep -A2 'Public Key'"
fi

echo ""

# ─── 5. HSTS Header Check ──────────────────────────────────────────────────
echo "── 5. HSTS Header (SC-8 downgrade prevention) ──────────────────────"

HEADERS=$(curl -sI --max-time 10 "https://${HOST}:${PORT}/" 2>/dev/null || true)
echo "$HEADERS" > "${EVIDENCE_DIR}/headers.txt"

if echo "$HEADERS" | grep -qi "Strict-Transport-Security"; then
    HSTS_VALUE=$(echo "$HEADERS" | grep -i "Strict-Transport-Security" | head -1)
    PASS "HSTS present: ${HSTS_VALUE}"
    if echo "$HSTS_VALUE" | grep -qi "includeSubDomains"; then
        PASS "HSTS includeSubDomains set"
    else
        WARN "HSTS missing includeSubDomains — subdomain downgrade possible"
    fi
    if echo "$HSTS_VALUE" | grep -oP 'max-age=\K\d+' | awk '{if ($1 < 31536000) print "SHORT"}' | grep -q "SHORT"; then
        WARN "HSTS max-age below 1 year (31536000 seconds) — consider longer duration"
    fi
else
    FAIL "HSTS header MISSING — SC-8(1) violation. HTTP downgrade attacks possible."
    INFO "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"
fi

echo ""

# ─── 6. Deep-Dive Recommendation ──────────────────────────────────────────
echo "── 6. Deep-Dive Recommendation ─────────────────────────────────────"
echo ""
INFO "For comprehensive cipher analysis, run:"
INFO "  testssl.sh --severity HIGH ${TARGET}"
INFO "  testssl.sh --cipher-per-proto ${TARGET}"
INFO ""
INFO "testssl.sh install: git clone --depth 1 https://github.com/drwetter/testssl.sh.git"
echo ""

# ─── Evidence Summary ──────────────────────────────────────────────────────
echo "======================================================"
echo " Evidence saved to: ${EVIDENCE_DIR}"
ls -1 "$EVIDENCE_DIR"
echo "======================================================"
