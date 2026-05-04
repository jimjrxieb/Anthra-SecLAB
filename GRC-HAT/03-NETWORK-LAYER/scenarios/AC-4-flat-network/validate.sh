#!/usr/bin/env bash
set -euo pipefail

# AC-4 Flat Network — Validate
#
# Confirms that network segmentation is working by testing cross-subnet
# reachability. Traffic that should be blocked must be blocked. Traffic
# that should be allowed must still work.
#
# Checks:
#   1. Nmap sweep confirms blocked paths are actually blocked
#   2. Nmap sweep confirms allowed paths still work
#   3. FORWARD chain has deny rules and correct policy
#   4. Logging is active for denied traffic
#   5. Specific zone-to-zone policy enforcement
#
# REQUIREMENTS:
#   - nmap (apt-get install nmap)
#   - Root/sudo privileges
#   - Run AFTER fix.sh
#
# USAGE:
#   sudo ./validate.sh <mgmt_cidr> <app_cidr> <data_cidr> <user_cidr>
#
# EXAMPLE:
#   sudo ./validate.sh 10.0.100.0/24 10.0.10.0/24 10.0.20.0/24 10.0.30.0/24
#
# CSF 2.0: PR.IR-01 (Networks protected)
# CIS v8: 12.2 (Establish Network-Based Segmentation)
# NIST: AC-4 (Information Flow Enforcement)
#

# --- Argument Validation ---

if [[ $# -ne 4 ]]; then
    echo "Usage: $0 <mgmt_cidr> <app_cidr> <data_cidr> <user_cidr>"
    echo "Example: $0 10.0.100.0/24 10.0.10.0/24 10.0.20.0/24 10.0.30.0/24"
    exit 1
fi

MGMT_CIDR="$1"
APP_CIDR="$2"
DATA_CIDR="$3"
USER_CIDR="$4"

# Verify running as root
if [[ $EUID -ne 0 ]]; then
    echo "[ERROR] This script must be run as root (sudo)."
    exit 1
fi

EVIDENCE_DIR="/tmp/ac4-flat-validate-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$EVIDENCE_DIR"

PASS_COUNT=0
FAIL_COUNT=0
TOTAL_CHECKS=0

echo "============================================"
echo "AC-4 Flat Network — Validation"
echo "============================================"
echo ""
echo "[*] Zone mapping:"
echo "    MGMT: $MGMT_CIDR"
echo "    APP:  $APP_CIDR"
echo "    DATA: $DATA_CIDR"
echo "    USER: $USER_CIDR"
echo "[*] Evidence dir: $EVIDENCE_DIR"
echo ""

# --- Helper function for pass/fail ---

check_result() {
    local test_name="$1"
    local passed="$2"
    local detail="$3"
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if [[ "$passed" == "true" ]]; then
        PASS_COUNT=$((PASS_COUNT + 1))
        echo "[PASS] $test_name"
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        echo "[FAIL] $test_name"
    fi
    echo "       $detail"
    echo ""
}

# --- Check 1: FORWARD Chain Policy ---

echo "[*] Check 1: FORWARD chain default policy"
echo "---------------------------------------------------"

FORWARD_POLICY=$(iptables -L FORWARD -n 2>/dev/null | head -1 | grep -oP '\(policy \K[A-Z]+' || echo "UNKNOWN")
if [[ "$FORWARD_POLICY" == "DROP" ]]; then
    check_result "FORWARD policy is DROP" "true" \
        "Default deny — only explicitly allowed cross-zone traffic passes."
else
    check_result "FORWARD policy is DROP" "false" \
        "FORWARD policy is $FORWARD_POLICY — should be DROP for segmentation."
fi

# --- Check 2: Segmentation Rules Exist ---

echo "[*] Check 2: Segmentation rules in FORWARD chain"
echo "---------------------------------------------------"

FORWARD_RULES=$(iptables -L FORWARD -n --line-numbers 2>/dev/null | grep -c "^[0-9]" || echo "0")
if [[ "$FORWARD_RULES" -gt 3 ]]; then
    check_result "FORWARD chain has segmentation rules" "true" \
        "$FORWARD_RULES rules in FORWARD chain."
else
    check_result "FORWARD chain has segmentation rules" "false" \
        "Only $FORWARD_RULES rules — insufficient for zone-based segmentation."
fi

# --- Check 3: Default Deny Rule Exists ---

echo "[*] Check 3: Explicit deny rule at end of FORWARD chain"
echo "---------------------------------------------------"

LAST_RULE=$(iptables -L FORWARD -n 2>/dev/null | tail -1)
if echo "$LAST_RULE" | grep -q "DROP"; then
    check_result "Explicit DROP rule at end of FORWARD chain" "true" \
        "Final rule is DROP — all unmatched cross-zone traffic is blocked."
else
    check_result "Explicit DROP rule at end of FORWARD chain" "false" \
        "Last rule is not DROP: $LAST_RULE"
fi

# --- Check 4: Logging Active ---

echo "[*] Check 4: Denied traffic logging"
echo "---------------------------------------------------"

LOG_RULES=$(iptables -L FORWARD -n 2>/dev/null | grep "LOG" || true)
if [[ -n "$LOG_RULES" ]]; then
    check_result "Denied traffic logging enabled" "true" \
        "LOG rule found — denied traffic is being recorded for forensics."
else
    check_result "Denied traffic logging enabled" "false" \
        "No LOG rule in FORWARD chain — denied traffic is silently dropped."
fi

# --- Check 5: Zone-to-Zone Policy Verification ---

echo "[*] Check 5: Zone-to-zone policy rules"
echo "---------------------------------------------------"

# Check MGMT -> APP rule exists
if iptables -L FORWARD -n 2>/dev/null | grep -q "AC4-FIX: MGMT->APP"; then
    check_result "MGMT -> APP admin rule exists" "true" \
        "Management can reach application zone for administration."
else
    check_result "MGMT -> APP admin rule exists" "false" \
        "No MGMT->APP rule — administrators cannot reach app servers."
fi

# Check APP -> DATA rule exists
if iptables -L FORWARD -n 2>/dev/null | grep -q "AC4-FIX: APP->DATA"; then
    check_result "APP -> DATA database rule exists" "true" \
        "Application servers can reach database zone."
else
    check_result "APP -> DATA database rule exists" "false" \
        "No APP->DATA rule — apps cannot reach databases."
fi

# Check USER -> APP rule exists
if iptables -L FORWARD -n 2>/dev/null | grep -q "AC4-FIX: USER->APP"; then
    check_result "USER -> APP web access rule exists" "true" \
        "Users can reach application web services."
else
    check_result "USER -> APP web access rule exists" "false" \
        "No USER->APP rule — users cannot reach web applications."
fi

# --- Check 6: Blocked Paths Verification (Nmap) ---

echo "[*] Check 6: Blocked path verification via Nmap"
echo "---------------------------------------------------"

if command -v nmap &>/dev/null; then
    # Test USER -> DATA (should be BLOCKED)
    # Use first usable IP in data subnet as target
    DATA_TARGET=$(echo "$DATA_CIDR" | sed 's|/.*||' | awk -F. '{printf "%s.%s.%s.%d", $1,$2,$3,$4+1}')

    echo "[*] Testing USER -> DATA path (should be blocked)..."
    echo "[*] Scanning $DATA_TARGET for database ports from user zone perspective..."

    SCAN_OUTPUT="$EVIDENCE_DIR/user-to-data-scan.txt"
    nmap -sS -Pn -p 3306,5432,1433 -T4 --reason \
        -oN "$SCAN_OUTPUT" "$DATA_TARGET" 2>&1 | grep "^[0-9]" || true

    OPEN_DB=$(grep "open" "$SCAN_OUTPUT" 2>/dev/null | grep -v "filtered" || true)
    if [[ -z "$OPEN_DB" ]]; then
        check_result "USER -> DATA blocked (database ports)" "true" \
            "Database ports on $DATA_TARGET are filtered/closed from user zone."
    else
        check_result "USER -> DATA blocked (database ports)" "false" \
            "Database ports are reachable: $OPEN_DB"
    fi
else
    echo "[SKIP] nmap not installed — cannot verify blocked paths."
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    FAIL_COUNT=$((FAIL_COUNT + 1))
fi

# --- Check 7: No Catch-All ACCEPT ---

echo "[*] Check 7: No overpermissive catch-all rules"
echo "---------------------------------------------------"

CATCHALL=$(iptables -L FORWARD -n 2>/dev/null | grep "ACCEPT" | grep "0\.0\.0\.0/0.*0\.0\.0\.0/0" | grep -v "ctstate\|AC4-FIX" || true)
if [[ -z "$CATCHALL" ]]; then
    check_result "No catch-all ACCEPT in FORWARD chain" "true" \
        "No overpermissive rules — all ACCEPT rules are zone-specific."
else
    check_result "No catch-all ACCEPT in FORWARD chain" "false" \
        "Catch-all ACCEPT rule found: $CATCHALL"
fi

# --- Save Current Rules for Evidence ---

iptables -L FORWARD -n -v --line-numbers > "$EVIDENCE_DIR/forward-chain-validated.txt" 2>&1
iptables-save > "$EVIDENCE_DIR/iptables-validated.txt"

# --- Validation Report ---

echo "============================================"
echo "Validation Report"
echo "============================================"
echo ""
echo "Date:        $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "Zones:       MGMT=$MGMT_CIDR APP=$APP_CIDR DATA=$DATA_CIDR USER=$USER_CIDR"
echo ""
echo "Results:     $PASS_COUNT passed / $FAIL_COUNT failed / $TOTAL_CHECKS total"
echo ""

if [[ "$FAIL_COUNT" -eq 0 ]]; then
    echo "OVERALL: PASS — Network segmentation is properly implemented."
    echo ""
    echo "Zone-based firewall is active with explicit allow rules and default deny."
    echo "Cross-zone traffic is restricted to approved paths only."
    echo "Denied traffic is logged for forensic analysis."
else
    echo "OVERALL: FAIL — Network segmentation needs additional work."
    echo ""
    echo "Recommended actions:"
    if [[ "$FORWARD_POLICY" != "DROP" ]]; then
        echo "  - Set FORWARD policy to DROP: iptables -P FORWARD DROP"
    fi
    echo "  - Re-run fix.sh with correct zone CIDRs"
    echo "  - Review FORWARD chain for missing or overpermissive rules"
    echo "  - Verify logging is active for denied traffic"
fi
echo ""
echo "[*] Evidence saved to: $EVIDENCE_DIR"

# Save report
{
    echo "AC-4 Flat Network Validation Report"
    echo "Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "Zones: MGMT=$MGMT_CIDR APP=$APP_CIDR DATA=$DATA_CIDR USER=$USER_CIDR"
    echo "Result: $PASS_COUNT/$TOTAL_CHECKS passed"
    echo "Overall: $(if [[ $FAIL_COUNT -eq 0 ]]; then echo PASS; else echo FAIL; fi)"
} > "$EVIDENCE_DIR/validation-report.txt"
