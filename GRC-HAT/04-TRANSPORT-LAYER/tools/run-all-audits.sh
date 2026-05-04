#!/usr/bin/env bash
# run-all-audits.sh — Orchestrator: run all L4 Transport Layer auditors
# NIST: SC-8, SC-13, SC-23, IA-5
# Usage: ./run-all-audits.sh [host:port] [namespace]
#
# CSF 2.0: ID.RA-01 (Vulnerabilities identified)
# CIS v8: 7.1 (Establish Vulnerability Management Process)
# NIST: CA-2 (Security Assessment)
#
set -euo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
PASS()  { echo -e "${GREEN}[PASS]${NC} $*"; }
WARN()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
FAIL()  { echo -e "${RED}[FAIL]${NC} $*"; }
INFO()  { echo -e "${CYAN}[INFO]${NC} $*"; }
TITLE() { echo -e "\n${BOLD}$*${NC}"; }

TARGET="${1:-}"
NAMESPACE="${2:-default}"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
EVIDENCE_ROOT="/tmp/jsa-evidence/l4-full-audit-${TIMESTAMP}"
mkdir -p "$EVIDENCE_ROOT"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AUDITORS_DIR="${SCRIPT_DIR}/01-auditors"

echo ""
echo -e "${BOLD}======================================================"
echo " L4 TRANSPORT LAYER — Full Security Audit"
echo " NIST: SC-8, SC-13, SC-23, IA-5"
echo " Evidence Root: ${EVIDENCE_ROOT}"
echo " $(date)"
echo -e "======================================================${NC}"
echo ""

TOTAL_PASS=0
TOTAL_WARN=0
TOTAL_FAIL=0

# ─── Audit 1: TLS Configuration ──────────────────────────────────────────
TITLE "=== AUDIT 1/3: TLS Protocol & Cipher Configuration ==="

if [[ -z "$TARGET" ]]; then
    WARN "No target specified — skipping TLS config audit"
    INFO "Pass host:port as first argument: $0 example.com:443"
    (( TOTAL_WARN++ )) || true
else
    if bash "${AUDITORS_DIR}/audit-tls-config.sh" "$TARGET" 2>&1 | tee "${EVIDENCE_ROOT}/01-tls-config.log"; then
        PASS "TLS configuration audit completed"
        (( TOTAL_PASS++ )) || true
    else
        FAIL "TLS configuration audit failed"
        (( TOTAL_FAIL++ )) || true
    fi
fi

echo ""

# ─── Audit 2: Certificate Lifecycle ──────────────────────────────────────
TITLE "=== AUDIT 2/3: Certificate Lifecycle & Management ==="

if bash "${AUDITORS_DIR}/audit-cert-lifecycle.sh" 2>&1 | tee "${EVIDENCE_ROOT}/02-cert-lifecycle.log"; then
    PASS "Certificate lifecycle audit completed"
    (( TOTAL_PASS++ )) || true
else
    FAIL "Certificate lifecycle audit failed"
    (( TOTAL_FAIL++ )) || true
fi

echo ""

# ─── Audit 3: mTLS Status ─────────────────────────────────────────────────
TITLE "=== AUDIT 3/3: Mutual TLS Status ==="

if bash "${AUDITORS_DIR}/audit-mtls-status.sh" "$NAMESPACE" 2>&1 | tee "${EVIDENCE_ROOT}/03-mtls-status.log"; then
    PASS "mTLS status audit completed"
    (( TOTAL_PASS++ )) || true
else
    FAIL "mTLS status audit failed"
    (( TOTAL_FAIL++ )) || true
fi

echo ""

# ─── Summary ──────────────────────────────────────────────────────────────
echo -e "${BOLD}======================================================"
echo " AUDIT SUMMARY"
echo -e "======================================================${NC}"
echo ""

# Parse results from logs
TLS_FAILS=$(grep -c "\[FAIL\]" "${EVIDENCE_ROOT}/01-tls-config.log" 2>/dev/null || echo "0")
TLS_WARNS=$(grep -c "\[WARN\]" "${EVIDENCE_ROOT}/01-tls-config.log" 2>/dev/null || echo "0")
CERT_FAILS=$(grep -c "\[FAIL\]" "${EVIDENCE_ROOT}/02-cert-lifecycle.log" 2>/dev/null || echo "0")
CERT_WARNS=$(grep -c "\[WARN\]" "${EVIDENCE_ROOT}/02-cert-lifecycle.log" 2>/dev/null || echo "0")
MTLS_FAILS=$(grep -c "\[FAIL\]\|\[GAP\]" "${EVIDENCE_ROOT}/03-mtls-status.log" 2>/dev/null || echo "0")
MTLS_WARNS=$(grep -c "\[WARN\]" "${EVIDENCE_ROOT}/03-mtls-status.log" 2>/dev/null || echo "0")

echo "  Audit 1 — TLS Config:      ${TLS_FAILS} failures, ${TLS_WARNS} warnings"
echo "  Audit 2 — Cert Lifecycle:  ${CERT_FAILS} failures, ${CERT_WARNS} warnings"
echo "  Audit 3 — mTLS Status:     ${MTLS_FAILS} failures, ${MTLS_WARNS} warnings"
echo ""

TOTAL_CRITICAL=$(( TLS_FAILS + CERT_FAILS + MTLS_FAILS ))
TOTAL_WARNINGS=$(( TLS_WARNS + CERT_WARNS + MTLS_WARNS ))

if [[ $TOTAL_CRITICAL -gt 0 ]]; then
    FAIL "Total critical findings: ${TOTAL_CRITICAL} — immediate remediation required"
    echo ""
    echo "  Priority fixes:"
    [[ $TLS_FAILS -gt 0 ]]  && echo "    → run: 02-fixers/fix-weak-ciphers.sh --platform nginx|apache|iis|azure"
    [[ $CERT_FAILS -gt 0 ]] && echo "    → run: 02-fixers/fix-expired-cert.sh --method certmanager|manual|letsencrypt"
    [[ $MTLS_FAILS -gt 0 ]] && echo "    → review: playbooks/02-fix-SC8-tls.md for mTLS deployment"
elif [[ $TOTAL_WARNINGS -gt 0 ]]; then
    WARN "Total warnings: ${TOTAL_WARNINGS} — review and remediate within 30 days"
else
    PASS "No critical findings — L4 Transport Layer posture clean"
fi

echo ""
echo "  NIST Control Coverage:"
echo "    SC-8  (Transmission Confidentiality)  → TLS audit"
echo "    SC-13 (Cryptographic Protection)      → Cipher audit"
echo "    SC-23 (Session Authenticity)          → mTLS audit"
echo "    IA-5  (Authenticator Management)      → Cert lifecycle"
echo ""

# ─── testssl.sh recommendation ────────────────────────────────────────────
if [[ -n "$TARGET" ]]; then
    echo "  Deep-dive recommendation:"
    INFO "  testssl.sh --severity HIGH ${TARGET}"
    INFO "  testssl.sh --cipher-per-proto ${TARGET}"
fi

echo ""
echo -e "${BOLD}Evidence archive: ${EVIDENCE_ROOT}${NC}"
echo ""
ls -1 "$EVIDENCE_ROOT"
echo ""
echo -e "${BOLD}======================================================"
echo " L4 Transport Layer Audit Complete"
echo -e "======================================================${NC}"
