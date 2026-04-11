#!/usr/bin/env bash
# run-all-audits.sh — L5 Session Layer audit orchestrator
# NIST: AC-2, AC-6, AC-12, IA-2, IA-8, SC-23
# Usage: ./run-all-audits.sh [namespace] [--entra-only | --keycloak-only | --k8s-only]
set -euo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'; NC='\033[0m'
PASS() { echo -e "${GREEN}[PASS]${NC} $*"; }
WARN() { echo -e "${YELLOW}[WARN]${NC} $*"; }
FAIL() { echo -e "${RED}[FAIL]${NC} $*"; }
INFO() { echo -e "       $*"; }
SECTION() { echo -e "${BLUE}$*${NC}"; }

NAMESPACE="${1:-default}"
FILTER="${2:-}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../01-auditors" && pwd)"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
SUMMARY_DIR="/tmp/jsa-evidence/l5-session-summary-${TIMESTAMP}"
mkdir -p "$SUMMARY_DIR"

echo "======================================================"
echo " L5 Session Layer — All Audits"
echo " Namespace: ${NAMESPACE}"
echo " Filter: ${FILTER:-none}"
echo " Started: $(date)"
echo " Summary: ${SUMMARY_DIR}"
echo "======================================================"
echo ""

TOTAL_SCRIPTS=0
PASSED_SCRIPTS=0
FAILED_SCRIPTS=0
WARNINGS=()

run_audit() {
    local script="$1"
    local args="${2:-}"
    local name
    name=$(basename "$script" .sh)

    TOTAL_SCRIPTS=$((TOTAL_SCRIPTS + 1))
    SECTION "┌──────────────────────────────────────────────────────"
    SECTION "│ Running: ${name}"
    SECTION "└──────────────────────────────────────────────────────"

    local log_file="${SUMMARY_DIR}/${name}.log"

    if bash "${script}" ${args} 2>&1 | tee "$log_file"; then
        PASSED_SCRIPTS=$((PASSED_SCRIPTS + 1))
        echo ""
        PASS "Completed: ${name}"
    else
        FAILED_SCRIPTS=$((FAILED_SCRIPTS + 1))
        WARNINGS+=("${name} exited non-zero — check ${log_file}")
        echo ""
        WARN "Non-zero exit: ${name} — logged to ${log_file}"
    fi
    echo ""
}

# ─── K8s Audits ───────────────────────────────────────────────────────────
if [[ -z "$FILTER" || "$FILTER" != "--entra-only" && "$FILTER" != "--keycloak-only" ]]; then
    SECTION "═══ K8s RBAC + Service Account Audits ═══════════════════"
    run_audit "${SCRIPT_DIR}/audit-rbac-privileges.sh" "${NAMESPACE}"
    run_audit "${SCRIPT_DIR}/audit-service-accounts.sh" "${NAMESPACE}"
fi

# ─── Identity Platform Audits ─────────────────────────────────────────────
if [[ "$FILTER" != "--k8s-only" ]]; then
    SECTION "═══ Identity Platform Audits ════════════════════════════"
    SESSION_FILTER="${FILTER:-}"
    MFA_FILTER="${FILTER:-}"
    run_audit "${SCRIPT_DIR}/audit-session-policy.sh" "${SESSION_FILTER}"
    run_audit "${SCRIPT_DIR}/audit-mfa-status.sh" "${MFA_FILTER}"
fi

# ─── Summary ──────────────────────────────────────────────────────────────
echo "======================================================"
echo " L5 Session Layer Audit Summary"
echo " ──────────────────────────────"
echo " Scripts run:    ${TOTAL_SCRIPTS}"
PASS_DISPLAY="${PASSED_SCRIPTS}/${TOTAL_SCRIPTS} completed without errors"
echo -e " ${GREEN}Passed:${NC}        ${PASS_DISPLAY}"
if [[ $FAILED_SCRIPTS -gt 0 ]]; then
    echo -e " ${RED}Non-zero exits:${NC} ${FAILED_SCRIPTS}"
    for w in "${WARNINGS[@]}"; do
        echo -e "   ${YELLOW}→${NC} $w"
    done
fi
echo ""
echo " Evidence logs: ${SUMMARY_DIR}/"
echo " Finished: $(date)"
echo "======================================================"
echo ""
INFO "Individual evidence directories created under /tmp/jsa-evidence/"
INFO "Archive evidence: tar -czf l5-evidence-${TIMESTAMP}.tar.gz /tmp/jsa-evidence/"
INFO ""
INFO "Next step: 03-validate.md — verify findings are remediated"
INFO "Triage alerts: 04-triage-alerts.md — daily operations"
