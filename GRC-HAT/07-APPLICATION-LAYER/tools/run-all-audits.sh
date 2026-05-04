#!/usr/bin/env bash
# run-all-audits.sh — L7 Application Layer audit orchestrator
# NIST: AU-6 (audit review), RA-5 (vulnerability scanning), SI-4 (monitoring)
# Usage: ./run-all-audits.sh [--quick | --siem-only | --vuln-only | --edr-only]
#
# CSF 2.0: ID.RA-01 (Vulnerabilities identified)
# CIS v8: 7.1 (Establish Vulnerability Management Process)
# NIST: CA-2 (Security Assessment)
#
set -euo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'
PASS() { echo -e "${GREEN}[PASS]${NC} $*"; }
WARN() { echo -e "${YELLOW}[WARN]${NC} $*"; }
FAIL() { echo -e "${RED}[FAIL]${NC} $*"; }
INFO() { echo -e "       $*"; }
SECTION() { echo -e "\n${BLUE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; echo -e "${BLUE}${BOLD} $* ${NC}"; echo -e "${BLUE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; }

MODE="${1:-all}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AUDITORS_DIR="${SCRIPT_DIR}/../01-auditors"

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
EVIDENCE_DIR="/tmp/jsa-evidence/l7-full-audit-${TIMESTAMP}"
REPORT_FILE="${EVIDENCE_DIR}/L7-AUDIT-REPORT-${TIMESTAMP}.txt"
mkdir -p "$EVIDENCE_DIR"

TOTAL_FINDINGS=0
AUDITS_PASSED=0
AUDITS_FAILED=0

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║     L7 Application Layer — Full Security Audit      ║"
echo "║     NIST: SA-11, RA-5, AC-6, SI-4, AU-2, AU-6       ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""
echo "  Mode:      ${MODE}"
echo "  Evidence:  ${EVIDENCE_DIR}"
echo "  Report:    ${REPORT_FILE}"
echo "  Started:   $(date)"
echo ""

# ─── Audit Runner ─────────────────────────────────────────────────────────────

run_audit() {
    local AUDIT_NAME="$1"
    local AUDIT_SCRIPT="$2"
    local AUDIT_ARGS="${3:-}"

    SECTION "$AUDIT_NAME"

    if [[ ! -x "$AUDIT_SCRIPT" ]]; then
        WARN "Audit script not executable: $AUDIT_SCRIPT"
        INFO "Fix: chmod +x $AUDIT_SCRIPT"
        AUDITS_FAILED=$((AUDITS_FAILED + 1))
        return
    fi

    START_TIME=$(date +%s)

    # Run audit, capture exit code
    if bash "$AUDIT_SCRIPT" $AUDIT_ARGS 2>&1 | tee "${EVIDENCE_DIR}/$(basename $AUDIT_SCRIPT .sh)-output.txt"; then
        END_TIME=$(date +%s)
        DURATION=$(( END_TIME - START_TIME ))
        PASS "$AUDIT_NAME — PASSED (${DURATION}s)"
        AUDITS_PASSED=$((AUDITS_PASSED + 1))
        echo "AUDIT=$AUDIT_NAME STATUS=PASS DURATION=${DURATION}s" >> "${REPORT_FILE}"
    else
        END_TIME=$(date +%s)
        DURATION=$(( END_TIME - START_TIME ))
        FAIL "$AUDIT_NAME — FINDINGS DETECTED (${DURATION}s)"
        AUDITS_FAILED=$((AUDITS_FAILED + 1))
        TOTAL_FINDINGS=$((TOTAL_FINDINGS + 1))
        echo "AUDIT=$AUDIT_NAME STATUS=FAIL DURATION=${DURATION}s" >> "${REPORT_FILE}"
    fi

    echo ""
}

# ─── Run Selected Audits ──────────────────────────────────────────────────────

case "$MODE" in
    "--siem-only")
        run_audit "SIEM Ingest Health (Sentinel + Splunk)" \
            "${AUDITORS_DIR}/audit-siem-ingest.sh"
        run_audit "Alert Rules Coverage (Sentinel + Splunk)" \
            "${AUDITORS_DIR}/audit-alert-rules.sh"
        run_audit "Log Retention Compliance" \
            "${AUDITORS_DIR}/audit-log-retention.sh"
        ;;

    "--vuln-only")
        run_audit "Vulnerability Scan Coverage (ZAP/Trivy/Semgrep/kube-bench)" \
            "${AUDITORS_DIR}/audit-vuln-scan-coverage.sh"
        ;;

    "--edr-only")
        run_audit "EDR Agent Health (Defender + Wazuh)" \
            "${AUDITORS_DIR}/audit-edr-agents.sh"
        ;;

    "--quick")
        # Quick: just SIEM and EDR — skip vuln scan coverage (slower)
        run_audit "SIEM Ingest Health" \
            "${AUDITORS_DIR}/audit-siem-ingest.sh"
        run_audit "EDR Agent Health" \
            "${AUDITORS_DIR}/audit-edr-agents.sh"
        ;;

    "all"|*)
        # Full audit — all 5 auditors in sequence
        run_audit "1/5 — SIEM Ingest Health (Sentinel + Splunk)" \
            "${AUDITORS_DIR}/audit-siem-ingest.sh"

        run_audit "2/5 — EDR Agent Health (Defender + Wazuh)" \
            "${AUDITORS_DIR}/audit-edr-agents.sh"

        run_audit "3/5 — Vulnerability Scan Coverage" \
            "${AUDITORS_DIR}/audit-vuln-scan-coverage.sh"

        run_audit "4/5 — Alert Rules Coverage (Dual SIEM)" \
            "${AUDITORS_DIR}/audit-alert-rules.sh"

        run_audit "5/5 — Log Retention Compliance" \
            "${AUDITORS_DIR}/audit-log-retention.sh"
        ;;
esac

# ─── Final Report ─────────────────────────────────────────────────────────────

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║             L7 AUDIT COMPLETE — SUMMARY             ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

if [[ $AUDITS_FAILED -eq 0 ]]; then
    echo -e "  ${GREEN}${BOLD}Status: ALL AUDITS PASSED${NC}"
else
    echo -e "  ${RED}${BOLD}Status: ${AUDITS_FAILED} AUDIT(S) WITH FINDINGS${NC}"
fi

echo ""
echo "  Audits passed:    $AUDITS_PASSED"
echo "  Audits with findings: $AUDITS_FAILED"
echo "  Evidence dir:     $EVIDENCE_DIR"
echo "  Report file:      $REPORT_FILE"
echo "  Completed:        $(date)"
echo ""

# Remediation guidance if findings exist
if [[ $AUDITS_FAILED -gt 0 ]]; then
    echo "─────────────────────────────────────────────────────"
    echo "  Remediation guide:"
    echo ""
    echo "  SIEM findings:    02-fixers/fix-sentinel-analytics-rule.md"
    echo "                    02-fixers/fix-splunk-alert-rules.sh"
    echo "                    02-fixers/fix-missing-log-source.sh"
    echo ""
    echo "  EDR findings:     02-fixers/fix-defender-active-response.md"
    echo "                    02-fixers/fix-wazuh-fim-paths.sh"
    echo ""
    echo "  Vuln scan gaps:   playbooks/02a-fix-RA5-vuln-scan.md"
    echo ""
    echo "  Next step:        Run playbooks/03-validate.md after fixes"
    echo "─────────────────────────────────────────────────────"
fi

# Write summary to report file
{
    echo ""
    echo "═══════════════════════════════════════════"
    echo " AUDIT SUMMARY"
    echo "═══════════════════════════════════════════"
    echo "timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "layer: L7-APPLICATION"
    echo "mode: $MODE"
    echo "audits_passed: $AUDITS_PASSED"
    echo "audits_failed: $AUDITS_FAILED"
    echo "evidence_dir: $EVIDENCE_DIR"
} >> "$REPORT_FILE"

[[ $AUDITS_FAILED -gt 0 ]] && exit 1 || exit 0
