#!/usr/bin/env bash
# run-all-audits.sh — L6 Presentation Layer audit orchestrator
# NIST: SC-28, SC-13, SC-12, SI-10
# Usage: ./run-all-audits.sh [--dir <scan-dir>] [--tls-host <host:port>]
#        Runs all 4 auditors sequentially, saves consolidated evidence.
set -euo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'; NC='\033[0m'
INFO() { echo -e "       $*"; }
PASS() { echo -e "${GREEN}[PASS]${NC} $*"; }
WARN() { echo -e "${YELLOW}[WARN]${NC} $*"; }
FAIL() { echo -e "${RED}[FAIL]${NC} $*"; }
SECTION() { echo -e "\n${BLUE}╔══════════════════════════════════════════════════════╗${NC}"; \
             echo -e "${BLUE}║ $*${NC}"; \
             echo -e "${BLUE}╚══════════════════════════════════════════════════════╝${NC}"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AUDITORS_DIR="${SCRIPT_DIR}/../01-auditors"
SCAN_DIR="$(pwd)"
TLS_HOST=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dir) SCAN_DIR="$2"; shift 2 ;;
        --tls-host) TLS_HOST="$2"; shift 2 ;;
        *) shift ;;
    esac
done

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
MASTER_EVIDENCE="/tmp/jsa-evidence/L6-presentation-${TIMESTAMP}"
mkdir -p "$MASTER_EVIDENCE"

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║  L6 Presentation Layer — Full Audit                  ║"
echo "║  NIST: SC-28 / SC-13 / SC-12 / SI-10                ║"
echo "╚══════════════════════════════════════════════════════╝"
echo " Scan directory: ${SCAN_DIR}"
echo " TLS host: ${TLS_HOST:-not specified}"
echo " Master evidence: ${MASTER_EVIDENCE}"
echo " $(date)"
echo ""

TOTAL_FINDINGS=0
AUDIT_RESULTS=()

# Helper: run an auditor and capture its exit status
run_auditor() {
    local name="$1"
    local script="$2"
    shift 2
    local args=("$@")

    SECTION "${name}"
    echo ""

    if [[ ! -f "$script" ]]; then
        WARN "Auditor not found: ${script}"
        AUDIT_RESULTS+=("${name}: SKIP (script not found)")
        return
    fi

    if [[ ! -x "$script" ]]; then
        chmod +x "$script"
    fi

    # Run auditor, capture output and exit code
    AUDIT_OUT=$(mktemp)
    set +e
    bash "$script" "${args[@]}" 2>&1 | tee "$AUDIT_OUT"
    EXIT_CODE=$?
    set -e

    # Parse findings from output
    FINDINGS=$(grep -c '^\[FAIL\]' "$AUDIT_OUT" 2>/dev/null || echo "0")
    WARNINGS=$(grep -c '^\[WARN\]' "$AUDIT_OUT" 2>/dev/null || echo "0")

    # Copy evidence to master dir
    EVIDENCE_FROM=$(grep "Evidence:" "$AUDIT_OUT" 2>/dev/null | tail -1 | awk '{print $NF}' || echo "")
    if [[ -n "$EVIDENCE_FROM" && -d "$EVIDENCE_FROM" ]]; then
        AUDIT_LABEL=$(echo "$name" | tr ' ' '-' | tr '[:upper:]' '[:lower:]')
        cp -r "$EVIDENCE_FROM" "${MASTER_EVIDENCE}/${AUDIT_LABEL}" 2>/dev/null || true
    fi

    rm -f "$AUDIT_OUT"

    TOTAL_FINDINGS=$((TOTAL_FINDINGS + FINDINGS))

    if [[ "$FINDINGS" -gt 0 ]]; then
        AUDIT_RESULTS+=("${name}: FAIL (${FINDINGS} findings, ${WARNINGS} warnings)")
    elif [[ "$WARNINGS" -gt 0 ]]; then
        AUDIT_RESULTS+=("${name}: WARN (0 findings, ${WARNINGS} warnings)")
    else
        AUDIT_RESULTS+=("${name}: PASS")
    fi
}

# ── Run all 4 auditors ────────────────────────────────────────────────────

run_auditor \
    "1/4 Encryption at Rest (SC-28)" \
    "${AUDITORS_DIR}/audit-encryption-at-rest.sh"

run_auditor \
    "2/4 Key Rotation (SC-12)" \
    "${AUDITORS_DIR}/audit-key-rotation.sh"

if [[ -n "$TLS_HOST" ]]; then
    run_auditor \
        "3/4 Crypto Standards (SC-13)" \
        "${AUDITORS_DIR}/audit-crypto-standards.sh" \
        "--dir" "$SCAN_DIR" \
        "--tls-host" "$TLS_HOST"
else
    run_auditor \
        "3/4 Crypto Standards (SC-13)" \
        "${AUDITORS_DIR}/audit-crypto-standards.sh" \
        "--dir" "$SCAN_DIR"
fi

run_auditor \
    "4/4 Secrets Exposure (SC-28/SI-10)" \
    "${AUDITORS_DIR}/audit-secrets-exposure.sh" \
    "--dir" "$SCAN_DIR"

# ── Consolidated Summary ───────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║  L6 Audit Summary                                    ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

for result in "${AUDIT_RESULTS[@]}"; do
    if echo "$result" | grep -q "FAIL"; then
        echo -e " ${RED}[FAIL]${NC} ${result}"
    elif echo "$result" | grep -q "WARN"; then
        echo -e " ${YELLOW}[WARN]${NC} ${result}"
    elif echo "$result" | grep -q "SKIP"; then
        echo -e "  [SKIP] ${result}"
    else
        echo -e " ${GREEN}[PASS]${NC} ${result}"
    fi
done

echo ""
echo " Total findings: ${TOTAL_FINDINGS}"
echo " Master evidence: ${MASTER_EVIDENCE}"
echo " $(date)"
echo ""

# Write master summary
cat > "${MASTER_EVIDENCE}/master-summary.txt" <<EOF
L6 Presentation Layer — Full Audit Summary
Date: $(date)
Scan Directory: ${SCAN_DIR}
TLS Host: ${TLS_HOST:-not specified}
Total Findings: ${TOTAL_FINDINGS}

NIST Controls Assessed:
  SC-28: Protection of Information at Rest
  SC-13: Cryptographic Protection
  SC-12: Cryptographic Key Establishment and Management
  SI-10: Information Input Validation

Audit Results:
$(for r in "${AUDIT_RESULTS[@]}"; do echo "  $r"; done)

Evidence directories:
$(ls "${MASTER_EVIDENCE}/" 2>/dev/null | grep -v master-summary | while read -r d; do
    echo "  ${MASTER_EVIDENCE}/${d}/"
done)

Recommended remediation (in priority order):
1. Secrets exposure: rotate any found secrets immediately
2. Encryption at rest: enable etcd encryption (fix-etcd-encryption.sh)
3. Weak crypto: migrate MD5/SHA-1 (fix-weak-hashing.md)
4. Key rotation: rotate stale keys (fix-key-rotation.sh)
5. Disk encryption: enable BitLocker/LUKS (fix-bitlocker-enforcement.md)
EOF

if [[ "$TOTAL_FINDINGS" -gt 0 ]]; then
    echo ""
    WARN "Remediation scripts: 02-fixers/"
    WARN "See playbooks/02-fix-SC28-encryption.md and 02a-fix-SC13-crypto.md"
fi

exit $([[ "$TOTAL_FINDINGS" -gt 0 ]] && echo 1 || echo 0)
