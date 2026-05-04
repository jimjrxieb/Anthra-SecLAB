#!/usr/bin/env bash
# audit-crypto-standards.sh — L6 Presentation Layer cryptographic algorithm audit
# NIST: SC-13 (cryptographic protection) — detect weak/broken algorithms
# Usage: ./audit-crypto-standards.sh [--dir <path>] [--tls-host <host:port>]
#        Default scan dir: current working directory
#
# CSF 2.0: DE.CM-09 (Computing monitored for adverse events)
# CIS v8: 3.10 (Encrypt Sensitive Data in Transit)
# NIST: SC-13 (Cryptographic Protection)
#
set -euo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; NC='\033[0m'
PASS() { echo -e "${GREEN}[PASS]${NC} $*"; }
WARN() { echo -e "${YELLOW}[WARN]${NC} $*"; }
FAIL() { echo -e "${RED}[FAIL]${NC} $*"; }
INFO() { echo -e "       $*"; }

SCAN_DIR="${2:-$(pwd)}"
TLS_HOST="${4:-}"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
EVIDENCE_DIR="/tmp/jsa-evidence/crypto-standards-${TIMESTAMP}"
mkdir -p "$EVIDENCE_DIR"

# Parse args
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dir) SCAN_DIR="$2"; shift 2 ;;
        --tls-host) TLS_HOST="$2"; shift 2 ;;
        *) shift ;;
    esac
done

echo "======================================================"
echo " L6 Crypto Standards Audit — SC-13"
echo " Scan directory: ${SCAN_DIR}"
echo " TLS host: ${TLS_HOST:-not specified}"
echo " Evidence: ${EVIDENCE_DIR}"
echo " $(date)"
echo "======================================================"
echo ""

FINDINGS=0
WEAK_PATTERNS=(
    "MD5"
    "SHA-1\|sha1\|SHA1"
    "\bDES\b\|3DES\|Triple.DES\|TripleDES"
    "\bRC4\b\|ARC4\|Arcfour"
    "\bRC2\b"
    "hashlib\.md5\|hashlib\.sha1"
    "crypto\.createHash.*['\"]md5['\"]"
    "crypto\.createHash.*['\"]sha1['\"]"
    "MessageDigest\.getInstance.*MD5"
    "MessageDigest\.getInstance.*SHA-1\b"
)

WEAK_LABELS=(
    "MD5 hash algorithm"
    "SHA-1 hash algorithm"
    "DES/3DES cipher (broken)"
    "RC4 stream cipher (broken)"
    "RC2 cipher (deprecated)"
    "Python hashlib.md5 usage"
    "Node.js crypto MD5"
    "Node.js crypto SHA-1"
    "Java MD5 MessageDigest"
    "Java SHA-1 MessageDigest"
)

# File extensions to scan
SCAN_EXTENSIONS=("*.py" "*.js" "*.ts" "*.go" "*.java" "*.rb" "*.php"
                 "*.conf" "*.cfg" "*.yaml" "*.yml" "*.json" "*.toml"
                 "*.env" "*.properties" "*.xml" "*.ini" "*.sh")

# ─── Source Code / Config Scan ────────────────────────────────────────────
echo "═══════════════════════════════════════════════════════"
echo " Weak Algorithm Scan: ${SCAN_DIR}"
echo "═══════════════════════════════════════════════════════"

TOTAL_HITS=0
SCAN_RESULTS_FILE="${EVIDENCE_DIR}/weak-algo-scan.txt"
: > "$SCAN_RESULTS_FILE"

for i in "${!WEAK_PATTERNS[@]}"; do
    PATTERN="${WEAK_PATTERNS[$i]}"
    LABEL="${WEAK_LABELS[$i]}"

    # Build find + grep command for each extension
    HITS=""
    for ext in "${SCAN_EXTENSIONS[@]}"; do
        FOUND=$(find "$SCAN_DIR" -name "$ext" -not -path "*/.git/*" -not -path "*/node_modules/*" \
            -not -path "*/__pycache__/*" -not -path "*/vendor/*" \
            -exec grep -l -E "$PATTERN" {} \; 2>/dev/null || true)
        HITS="${HITS}${FOUND}"$'\n'
    done

    # Deduplicate
    UNIQUE_HITS=$(echo "$HITS" | sort -u | grep -v '^$' || true)
    HIT_COUNT=$(echo "$UNIQUE_HITS" | grep -c '.' 2>/dev/null || echo "0")

    if [[ "$HIT_COUNT" -gt 0 ]]; then
        FAIL "Found ${HIT_COUNT} file(s) with ${LABEL}"
        echo "=== ${LABEL} ===" >> "$SCAN_RESULTS_FILE"
        while IFS= read -r file; do
            [[ -z "$file" ]] && continue
            LINE_MATCHES=$(grep -n -E "$PATTERN" "$file" 2>/dev/null | head -5 || true)
            INFO "  $file"
            while IFS= read -r line; do
                INFO "    $line"
                echo "  $file: $line" >> "$SCAN_RESULTS_FILE"
            done <<< "$LINE_MATCHES"
        done <<< "$UNIQUE_HITS"
        TOTAL_HITS=$((TOTAL_HITS + HIT_COUNT))
        FINDINGS=$((FINDINGS + 1))
    fi
done

if [[ "$TOTAL_HITS" -eq 0 ]]; then
    PASS "No weak algorithm patterns found in ${SCAN_DIR}"
    echo "PASS: No weak algorithms detected" >> "$SCAN_RESULTS_FILE"
fi
echo ""

# ─── TLS Cipher Suite Check ───────────────────────────────────────────────
echo "═══════════════════════════════════════════════════════"
echo " TLS Cipher Suite Check"
echo "═══════════════════════════════════════════════════════"

if ! command -v openssl &>/dev/null; then
    WARN "openssl not found — skipping TLS cipher checks"
else
    # Check all services in the cluster if kubectl available
    if command -v kubectl &>/dev/null && kubectl cluster-info &>/dev/null 2>&1; then
        echo "── K8s Services with TLS ─────────────────────────────────────"

        # Get services with HTTPS ports
        HTTPS_SVCS=$(kubectl get services -A \
            -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.spec.clusterIP}{"\t"}{range .spec.ports[*]}{.port}{","}{end}{"\n"}{end}' \
            2>/dev/null || echo "")

        if [[ -n "$HTTPS_SVCS" ]]; then
            TLS_CHECK_FILE="${EVIDENCE_DIR}/tls-cipher-check.txt"
            : > "$TLS_CHECK_FILE"

            echo "$HTTPS_SVCS" | while IFS=$'\t' read -r ns svc_name cluster_ip ports; do
                [[ -z "$cluster_ip" || "$cluster_ip" == "None" ]] && continue
                # Only check common HTTPS ports
                if echo "$ports" | grep -qE '(443|8443|6443),'; then
                    INFO "Checking TLS on ${ns}/${svc_name} (${cluster_ip})"
                    # timeout 3s openssl s_client
                    TLS_RESULT=$(echo "" | timeout 3 openssl s_client \
                        -connect "${cluster_ip}:443" \
                        -cipher "RC4:DES:3DES:MD5:NULL" \
                        2>/dev/null | head -5 || echo "connection failed or no weak ciphers accepted")
                    echo "${ns}/${svc_name}: ${TLS_RESULT}" >> "$TLS_CHECK_FILE"
                fi
            done
            INFO "TLS check results: ${EVIDENCE_DIR}/tls-cipher-check.txt"
        fi
    fi

    # Check user-specified host
    if [[ -n "$TLS_HOST" ]]; then
        echo "── TLS Check: ${TLS_HOST} ────────────────────────────────────"
        HOST="${TLS_HOST%:*}"
        PORT="${TLS_HOST#*:}"
        PORT="${PORT:-443}"

        TLS_RESULT_FILE="${EVIDENCE_DIR}/tls-check-${HOST}-${PORT}.txt"

        # Get full TLS info
        TLS_INFO=$(echo "" | timeout 5 openssl s_client \
            -connect "${HOST}:${PORT}" \
            -brief 2>/dev/null || echo "connection failed")
        echo "$TLS_INFO" > "$TLS_RESULT_FILE"

        # Check protocol version
        PROTO=$(echo "$TLS_INFO" | grep "Protocol" | awk '{print $NF}')
        if echo "$PROTO" | grep -qE "TLSv1$|TLSv1\.0|SSLv3|SSLv2"; then
            FAIL "Weak TLS protocol: ${PROTO} on ${TLS_HOST}"
            INFO "WHY: TLS 1.0/1.1 and SSL are broken — require TLS 1.2+ (SC-13)"
            FINDINGS=$((FINDINGS + 1))
        elif [[ -n "$PROTO" ]]; then
            PASS "TLS protocol: ${PROTO} on ${TLS_HOST}"
        else
            WARN "Could not determine TLS protocol for ${TLS_HOST}"
        fi

        # Check cipher
        CIPHER=$(echo "$TLS_INFO" | grep "Cipher" | awk '{print $NF}')
        if echo "$CIPHER" | grep -qiE "RC4|DES|NULL|EXPORT|MD5|anon"; then
            FAIL "Weak cipher in use: ${CIPHER} on ${TLS_HOST}"
            FINDINGS=$((FINDINGS + 1))
        elif [[ -n "$CIPHER" ]]; then
            PASS "Cipher: ${CIPHER} on ${TLS_HOST}"
        fi

        # Test specifically for weak cipher acceptance
        echo ""
        INFO "Testing weak cipher acceptance on ${TLS_HOST}..."
        for weak_cipher in "RC4-SHA" "DES-CBC3-SHA" "EXP-RC4-MD5" "NULL-MD5"; do
            WEAK_RESULT=$(echo "" | timeout 3 openssl s_client \
                -connect "${HOST}:${PORT}" \
                -cipher "$weak_cipher" 2>&1 | grep -i "cipher\|handshake\|error" | head -2 || echo "rejected")
            if echo "$WEAK_RESULT" | grep -qi "Cipher is"; then
                FAIL "Server accepted weak cipher: ${weak_cipher}"
                FINDINGS=$((FINDINGS + 1))
            else
                PASS "Rejected weak cipher: ${weak_cipher}"
            fi
        done
    fi
fi
echo ""

# ─── Password Hashing Check ───────────────────────────────────────────────
echo "═══════════════════════════════════════════════════════"
echo " Password Hashing Algorithm Check"
echo "═══════════════════════════════════════════════════════"

HASH_PATTERNS=(
    "password_hash.*md5\|password.*=.*md5"
    "bcrypt\|argon2\|scrypt\|pbkdf2"
    "ROUNDS\s*=\s*[0-9]\{1,3\}[^0-9]"  # bcrypt rounds too low
)

PW_HASH_FILE="${EVIDENCE_DIR}/password-hashing.txt"
: > "$PW_HASH_FILE"

# Check for bcrypt/argon2/scrypt (good) vs md5/sha1 for passwords (bad)
for ext in "${SCAN_EXTENSIONS[@]}"; do
    # Bad: MD5/SHA1 used for passwords
    BAD_PW=$(find "$SCAN_DIR" -name "$ext" -not -path "*/.git/*" -not -path "*/node_modules/*" \
        -exec grep -l -i -E "password.*md5|md5.*password|hash_password.*sha1|sha1.*password" {} \; \
        2>/dev/null || true)

    if [[ -n "$BAD_PW" ]]; then
        while IFS= read -r file; do
            [[ -z "$file" ]] && continue
            FAIL "Possible MD5/SHA1 password hash in: $file"
            grep -n -i -E "password.*md5|md5.*password|hash_password.*sha1" "$file" 2>/dev/null \
                | head -3 | while IFS= read -r line; do
                    INFO "  $line"
                    echo "$file: $line" >> "$PW_HASH_FILE"
                done
            FINDINGS=$((FINDINGS + 1))
        done <<< "$BAD_PW"
    fi
done

# Good: check bcrypt/argon2 usage
GOOD_HASH=$(find "$SCAN_DIR" -name "*.py" -o -name "*.js" -o -name "*.ts" -o -name "*.go" \
    -not -path "*/.git/*" -not -path "*/node_modules/*" \
    | xargs grep -l -E "bcrypt|argon2|scrypt|pbkdf2" 2>/dev/null || true)

if [[ -n "$GOOD_HASH" ]]; then
    while IFS= read -r file; do
        [[ -z "$file" ]] && continue
        PASS "Modern password hashing found in: $file"
        echo "GOOD: $file" >> "$PW_HASH_FILE"
    done <<< "$GOOD_HASH"
fi
echo ""

# ─── Summary ──────────────────────────────────────────────────────────────
echo "======================================================"
echo " Crypto Standards Audit Summary"
echo " Total findings: ${FINDINGS}"
echo " Evidence: ${EVIDENCE_DIR}"
echo " $(date)"
echo "======================================================"

cat > "${EVIDENCE_DIR}/summary.txt" <<EOF
L6 Crypto Standards Audit Summary
Date: $(date)
Scan Directory: ${SCAN_DIR}
Total Findings: ${FINDINGS}
NIST Control: SC-13 (Cryptographic Protection)

Weak algorithms checked:
$(for label in "${WEAK_LABELS[@]}"; do echo "  - ${label}"; done)

Files:
- weak-algo-scan.txt: Files with weak algorithm patterns and line numbers
- tls-cipher-check.txt: K8s service TLS cipher results
- tls-check-*.txt: Individual host TLS check results
- password-hashing.txt: Password hashing algorithm findings
EOF

if [[ $FINDINGS -gt 0 ]]; then
    echo ""
    WARN "Remediation: see 02-fixers/fix-weak-hashing.md"
    WARN "Migration guide: replace MD5/SHA-1 with bcrypt (passwords) or SHA-256+ (data integrity)"
fi
