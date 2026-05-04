#!/usr/bin/env bash
# run-all-audits.sh — Layer 3 Network Audit Orchestrator
# Runs all four L3 auditors and produces a combined report
# NIST Controls: SC-7, AC-4, SI-3, SI-4
#
# CSF 2.0: ID.RA-01 (Vulnerabilities identified)
# CIS v8: 7.1 (Establish Vulnerability Management Process)
# NIST: CA-2 (Security Assessment)
#
set -euo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; NC='\033[0m'; BOLD='\033[1m'

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
REPORT_DIR="/tmp/jsa-evidence/l3-full-audit-${TIMESTAMP}"
mkdir -p "$REPORT_DIR"
REPORT="$REPORT_DIR/l3-audit-report.txt"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AUDITOR_DIR="${SCRIPT_DIR}/../01-auditors"

log() { echo -e "$1" | tee -a "$REPORT"; }

log "${BOLD}============================================================${NC}"
log "${BOLD}Layer 3 Network — Full Audit Run${NC}"
log "Timestamp: $(date)"
log "Host: $(hostname)"
log "Report: $REPORT_DIR"
log "${BOLD}============================================================${NC}"

total_pass=0; total_warn=0; total_fail=0

run_auditor() {
  local SCRIPT="$1"
  local NAME="$2"
  local NIST_CONTROLS="$3"

  log "\n${BOLD}────────────────────────────────────────────────────────────${NC}"
  log "${BOLD}Running: ${NAME}${NC}"
  log "NIST: ${NIST_CONTROLS}"
  log "${BOLD}────────────────────────────────────────────────────────────${NC}"

  if [[ ! -f "$SCRIPT" ]]; then
    log "${RED}[ERROR]${NC} Script not found: $SCRIPT"
    ((total_fail++))
    return
  fi

  if [[ ! -x "$SCRIPT" ]]; then
    chmod +x "$SCRIPT"
  fi

  # Run auditor, capture exit code
  if bash "$SCRIPT" 2>&1 | tee "$REPORT_DIR/${NAME}-output.txt"; then
    RESULT=0
  else
    RESULT=$?
  fi

  # Parse PASS/WARN/FAIL counts from auditor output
  OUTPUT="$REPORT_DIR/${NAME}-output.txt"
  PASS=$(grep -c '\[PASS\]' "$OUTPUT" 2>/dev/null || echo "0")
  WARN=$(grep -c '\[WARN\]' "$OUTPUT" 2>/dev/null || echo "0")
  FAIL=$(grep -c '\[FAIL\]' "$OUTPUT" 2>/dev/null || echo "0")

  total_pass=$((total_pass + PASS))
  total_warn=$((total_warn + WARN))
  total_fail=$((total_fail + FAIL))

  if [[ $RESULT -eq 0 ]]; then
    log "${GREEN}[COMPLETE]${NC} ${NAME}: PASS=${PASS} WARN=${WARN} FAIL=${FAIL}"
  else
    log "${RED}[FINDINGS]${NC} ${NAME}: PASS=${PASS} WARN=${WARN} FAIL=${FAIL}"
  fi

  # Append auditor output to combined report
  log "\n--- ${NAME} Output ---" >> "$REPORT"
  cat "$REPORT_DIR/${NAME}-output.txt" >> "$REPORT" 2>/dev/null || true
}

# ─── Run all auditors ─────────────────────────────────────────────────────────
run_auditor "${AUDITOR_DIR}/audit-firewall-rules.sh" \
  "audit-firewall-rules" \
  "SC-7 (Boundary Protection), AC-4 (Information Flow)"

run_auditor "${AUDITOR_DIR}/audit-suricata-config.sh" \
  "audit-suricata-config" \
  "SI-3 (Malicious Code Protection), SI-4 (System Monitoring)"

run_auditor "${AUDITOR_DIR}/audit-zeek-config.sh" \
  "audit-zeek-config" \
  "AU-2 (Event Logging), SI-4 (System Monitoring)"

run_auditor "${AUDITOR_DIR}/audit-network-segmentation.sh" \
  "audit-network-segmentation" \
  "AC-4 (Information Flow), SC-7 (Boundary Protection)"

# ─── Summary ─────────────────────────────────────────────────────────────────
log "\n${BOLD}============================================================${NC}"
log "${BOLD}Layer 3 Full Audit — Combined Summary${NC}"
log "Timestamp: $(date)"
log ""
log "  ${GREEN}Total PASS${NC}: ${total_pass}"
log "  ${YELLOW}Total WARN${NC}: ${total_warn}"
log "  ${RED}Total FAIL${NC}: ${total_fail}"
log ""

if [[ $total_fail -gt 0 ]]; then
  log "${RED}RESULT: FAIL — ${total_fail} control failure(s) require remediation${NC}"
  log "Next: Review FAIL items, run relevant fixers in 02-fixers/"
elif [[ $total_warn -gt 0 ]]; then
  log "${YELLOW}RESULT: WARN — No critical failures, ${total_warn} item(s) need attention${NC}"
else
  log "${GREEN}RESULT: PASS — All L3 controls verified${NC}"
fi

log ""
log "Evidence packages in: /tmp/jsa-evidence/"
log "Combined report:      $REPORT"
log "${BOLD}============================================================${NC}"

[[ $total_fail -gt 0 ]] && exit 1 || exit 0
