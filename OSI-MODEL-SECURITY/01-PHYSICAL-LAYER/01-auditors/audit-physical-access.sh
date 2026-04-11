#!/usr/bin/env bash
set -euo pipefail

# PURPOSE:       Interactive PE-3 physical access control audit checklist
# NIST CONTROLS: PE-3 Physical Access Control
# WHERE TO RUN:  Analyst workstation during on-site physical security assessment
# USAGE:         ./audit-physical-access.sh

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
PASS=0; WARN=0; FAIL=0

pass()  { echo -e "${GREEN}[PASS]${NC} $1"; ((PASS++)); }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; ((WARN++)); }
fail()  { echo -e "${RED}[FAIL]${NC} $1"; ((FAIL++)); }
info()  { echo -e "${CYAN}[INFO]${NC} $1"; }

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
EVIDENCE_DIR="/tmp/jsa-evidence/physical-access-${TIMESTAMP}"
mkdir -p "$EVIDENCE_DIR"
RESULTS_FILE="$EVIDENCE_DIR/results.txt"

{
  echo "PE-3 Physical Access Control Audit"
  echo "Date: $(date)"
  echo "Auditor: ${USER}"
  echo "================================================"
} | tee "$RESULTS_FILE"

echo ""
info "Starting PE-3 Physical Access Control Assessment"
info "Evidence will be saved to: $EVIDENCE_DIR"
echo ""

ask() {
  local question="$1"
  local result
  read -rp "$(echo -e "${CYAN}[CHECK]${NC} ${question} [y/n]: ")" result
  echo "$question => $result" >> "$RESULTS_FILE"
  [[ "$result" == "y" || "$result" == "Y" ]]
}

echo "--- Badge Access ---"
if ask "Are all facility entry points controlled by electronic badge access?"; then
  pass "Badge access controls are in place at all entry points"
else
  fail "FINDING: Not all entry points have electronic badge access (PE-3)"
fi

if ask "Are terminated employee badges deactivated within 24 hours of separation?"; then
  pass "Terminated badge deactivation SLA is met"
else
  fail "FINDING: Terminated badge deactivation SLA not enforced — credential residue risk (PE-3)"
fi

echo ""
echo "--- Visitor Logs ---"
if ask "Is a visitor log maintained at all controlled entry points?"; then
  pass "Visitor logs are maintained"
else
  fail "FINDING: No visitor log maintained — non-repudiation gap (PE-3)"
fi

if ask "Do visitor log entries include: name, organization, time in/out, host employee?"; then
  pass "Visitor log entries contain required fields"
else
  warn "WARN: Visitor log entries are incomplete — may not satisfy audit requirements"
fi

echo ""
echo "--- Escort Policy ---"
if ask "Is an escort policy in place for all visitors and contractors?"; then
  pass "Escort policy is defined"
else
  fail "FINDING: No escort policy — unauthorized physical access risk (PE-3)"
fi

if ask "Is the escort policy actively enforced (not just documented)?"; then
  pass "Escort policy is actively enforced"
else
  warn "WARN: Escort policy exists but enforcement is inconsistent"
fi

echo ""
echo "--- Server Room Access ---"
if ask "Is server room / data center access restricted to authorized personnel only?"; then
  pass "Server room access is appropriately restricted"
else
  fail "FINDING: Server room access is not adequately restricted (PE-3)"
fi

if ask "Is the server room access list reviewed and recertified at least annually?"; then
  pass "Access list review cadence is met"
else
  fail "FINDING: Access list reviews not performed — privilege accumulation risk (PE-3)"
fi

echo ""
echo "--- CCTV ---"
if ask "Are CCTV cameras installed at all controlled entry points?"; then
  pass "CCTV coverage exists at entry points"
else
  fail "FINDING: No CCTV at entry points — monitoring gap (PE-6)"
fi

if ask "Is CCTV footage retained for at least 90 days?"; then
  pass "CCTV retention policy meets minimum threshold"
else
  warn "WARN: CCTV footage retention may be insufficient for incident investigation"
fi

echo ""
echo "--- Access List Reviews ---"
if ask "Are physical access lists formally reviewed on a documented schedule?"; then
  pass "Formal access list review process is in place"
else
  fail "FINDING: No formal access list review process (PE-3)"
fi

{
  echo ""
  echo "================================================"
  echo "SUMMARY"
  echo "PASS: $PASS  WARN: $WARN  FAIL: $FAIL"
  echo "================================================"
} | tee -a "$RESULTS_FILE"

echo ""
info "Results saved to: $RESULTS_FILE"
echo ""

if [[ $FAIL -gt 0 ]]; then
  echo -e "${RED}Assessment complete — $FAIL finding(s) require remediation. See 02-fixers/fix-access-policy.md${NC}"
  exit 1
else
  echo -e "${GREEN}Assessment complete — All checks passed (WARN: $WARN)${NC}"
  exit 0
fi
