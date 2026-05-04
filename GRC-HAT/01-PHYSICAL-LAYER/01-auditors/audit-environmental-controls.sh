#!/usr/bin/env bash
set -euo pipefail

# PURPOSE:       Interactive PE-14 environmental controls audit checklist
# NIST CONTROLS: PE-14 Temperature and Humidity Controls, PE-13 Fire Protection, PE-11 Emergency Power
# WHERE TO RUN:  Analyst workstation during on-site physical security assessment
# USAGE:         ./audit-environmental-controls.sh
#
# CSF 2.0: PR.PS-01 (Configuration management applied)
# CIS v8: 4.1 (Establish Secure Configuration Process)
# NIST: PE-14 (Environmental Controls)
#

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
PASS=0; WARN=0; FAIL=0

pass()  { echo -e "${GREEN}[PASS]${NC} $1"; ((PASS++)); }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; ((WARN++)); }
fail()  { echo -e "${RED}[FAIL]${NC} $1"; ((FAIL++)); }
info()  { echo -e "${CYAN}[INFO]${NC} $1"; }

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
EVIDENCE_DIR="/tmp/jsa-evidence/environmental-controls-${TIMESTAMP}"
mkdir -p "$EVIDENCE_DIR"
RESULTS_FILE="$EVIDENCE_DIR/results.txt"

{
  echo "PE-14 Environmental Controls Audit"
  echo "Date: $(date)"
  echo "Auditor: ${USER}"
  echo "================================================"
} | tee "$RESULTS_FILE"

echo ""
info "Starting PE-14 Environmental Controls Assessment"
info "Evidence will be saved to: $EVIDENCE_DIR"
echo ""

ask() {
  local question="$1"
  local result
  read -rp "$(echo -e "${CYAN}[CHECK]${NC} ${question} [y/n]: ")" result
  echo "$question => $result" >> "$RESULTS_FILE"
  [[ "$result" == "y" || "$result" == "Y" ]]
}

echo "--- Temperature and Humidity (PE-14) ---"
info "Acceptable range: 64-75°F (18-24°C) temperature, 40-60% relative humidity"

if ask "Is temperature currently within range (64-75°F / 18-24°C)?"; then
  pass "Temperature is within acceptable range"
else
  fail "FINDING: Temperature out of range — equipment damage and reliability risk (PE-14)"
fi

if ask "Is humidity currently within range (40-60% RH)?"; then
  pass "Humidity is within acceptable range"
else
  fail "FINDING: Humidity out of range — condensation or static discharge risk (PE-14)"
fi

if ask "Are automated temperature and humidity alerts configured?"; then
  pass "Automated environmental alerts are configured"
else
  fail "FINDING: No automated environmental alerts — delayed detection of HVAC failure (PE-14)"
fi

if ask "Is HVAC serviced on a documented maintenance schedule?"; then
  pass "HVAC maintenance schedule is documented and followed"
else
  warn "WARN: HVAC maintenance schedule not confirmed — preventive maintenance gap"
fi

echo ""
echo "--- Fire Suppression (PE-13) ---"
if ask "Is a clean-agent fire suppression system installed (FM-200 or Novec 1230)?"; then
  pass "Clean-agent fire suppression system is installed"
else
  fail "FINDING: No clean-agent suppression — water sprinklers would destroy equipment (PE-13)"
fi

if ask "Has the fire suppression system been tested within the last 12 months?"; then
  pass "Fire suppression system testing is current"
else
  warn "WARN: Fire suppression last test date not confirmed — may be out of compliance"
fi

if ask "Are smoke detectors installed and tested within the last 6 months?"; then
  pass "Smoke detectors are present and recently tested"
else
  fail "FINDING: Smoke detectors not confirmed current — early fire detection gap (PE-13)"
fi

echo ""
echo "--- Emergency Power (PE-11) ---"
if ask "Is an Uninterruptible Power Supply (UPS) installed for all critical systems?"; then
  pass "UPS is installed for critical systems"
else
  fail "FINDING: No UPS — unplanned power loss will cause data loss and outage (PE-11)"
fi

if ask "Has the UPS load been tested under realistic conditions within the last 12 months?"; then
  pass "UPS load testing is current"
else
  warn "WARN: UPS load test not confirmed — actual runtime under load is unknown"
fi

if ask "Is a generator available for extended power outages (>30 minutes)?"; then
  pass "Generator backup is available"
else
  warn "WARN: No generator — UPS runtime is the only protection for extended outages"
fi

echo ""
echo "--- Water Detection (PE-15) ---"
if ask "Are water/leak detection sensors installed under raised floors or near HVAC drainage?"; then
  pass "Water leak detection sensors are in place"
else
  fail "FINDING: No water leak detection — flood damage may go undetected (PE-15)"
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
  echo -e "${RED}Assessment complete — $FAIL finding(s) require remediation. See 02-fixers/fix-environmental-monitoring.md${NC}"
  exit 1
else
  echo -e "${GREEN}Assessment complete — All checks passed (WARN: $WARN)${NC}"
  exit 0
fi
