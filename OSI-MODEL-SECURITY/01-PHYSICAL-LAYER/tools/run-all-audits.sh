#!/usr/bin/env bash
set -euo pipefail

# PURPOSE:       Orchestrator — runs all Layer 1 Physical auditors sequentially
# NIST CONTROLS: PE-3, PE-6, PE-11, PE-13, PE-14, PE-15
# WHERE TO RUN:  Analyst workstation during on-site physical security assessment
# USAGE:         ./tools/run-all-audits.sh

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
PASS=0; WARN=0; FAIL=0

pass()  { echo -e "${GREEN}[PASS]${NC} $1"; ((PASS++)); }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; ((WARN++)); }
fail()  { echo -e "${RED}[FAIL]${NC} $1"; ((FAIL++)); }
info()  { echo -e "${CYAN}[INFO]${NC} $1"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAYER_DIR="$(dirname "$SCRIPT_DIR")"

echo ""
echo -e "${CYAN}================================================${NC}"
echo -e "${CYAN}  Layer 1 Physical — Full Audit Suite${NC}"
echo -e "${CYAN}  $(date)${NC}"
echo -e "${CYAN}================================================${NC}"
echo ""

run_audit() {
  local script="$1"
  local name="$2"
  local exit_code=0

  echo ""
  echo -e "${CYAN}--- Running: ${name} ---${NC}"
  echo ""

  if bash "$script"; then
    pass "$name completed — no failures"
  else
    exit_code=$?
    fail "$name completed — findings detected"
  fi
  return $exit_code
}

AUDIT_FAILURES=0

info "Step 1/2: PE-3 Physical Access Control"
if ! run_audit "$LAYER_DIR/01-auditors/audit-physical-access.sh" "PE-3 Physical Access Audit"; then
  ((AUDIT_FAILURES++)) || true
fi

echo ""
info "Step 2/2: PE-14 Environmental Controls"
if ! run_audit "$LAYER_DIR/01-auditors/audit-environmental-controls.sh" "PE-14 Environmental Controls Audit"; then
  ((AUDIT_FAILURES++)) || true
fi

echo ""
echo -e "${CYAN}================================================${NC}"
echo -e "  LAYER 1 AUDIT SUITE — FINAL SUMMARY"
echo -e "${CYAN}================================================${NC}"
echo ""

if [[ $AUDIT_FAILURES -eq 0 ]]; then
  echo -e "${GREEN}All audits passed — no findings requiring remediation${NC}"
  echo ""
  echo "Next step: Document assessment results in 03-templates/pe-assessment-checklist.md"
  exit 0
else
  echo -e "${RED}${AUDIT_FAILURES} audit(s) returned findings${NC}"
  echo ""
  echo "Remediation resources:"
  echo "  PE-3 gaps:  $LAYER_DIR/02-fixers/fix-access-policy.md"
  echo "  PE-14 gaps: $LAYER_DIR/02-fixers/fix-environmental-monitoring.md"
  echo ""
  echo "After remediation: run playbooks/03-validate.md to confirm resolution"
  exit 1
fi
