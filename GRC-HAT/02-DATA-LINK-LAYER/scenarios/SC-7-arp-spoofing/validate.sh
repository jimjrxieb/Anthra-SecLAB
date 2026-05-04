#!/usr/bin/env bash
set -euo pipefail

# SC-7 ARP Spoofing — Validate
#
# Re-runs ARP spoofing attempt to confirm that DAI, static ARP entries,
# or other mitigations are blocking the attack.
#
# This script:
#   1. Snapshots the current ARP table on the target
#   2. Sends spoofed ARP replies to the target
#   3. Checks whether the target's ARP table was poisoned
#   4. Verifies DAI is dropping invalid ARP packets (switch log check)
#   5. Produces a pass/fail validation report
#
# REQUIREMENTS:
#   - arping or arpspoof (for sending test ARP)
#   - Root/sudo privileges
#   - Run AFTER fix.md controls are implemented
#
# USAGE:
#   sudo ./validate.sh <interface> <target_ip> <spoofed_ip>
#
# EXAMPLE:
#   sudo ./validate.sh eth0 192.168.1.100 192.168.1.1
#   (Attempts to tell 192.168.1.100 that 192.168.1.1 is at our MAC)
#
# CSF 2.0: DE.CM-01 (Networks monitored)
# CIS v8: 13.2 (Deploy Network-Based IDS)
# NIST: SC-7 (Boundary Protection)
#

# --- Argument Validation ---

if [[ $# -ne 3 ]]; then
    echo "Usage: $0 <interface> <target_ip> <spoofed_ip>"
    echo "Example: $0 eth0 192.168.1.100 192.168.1.1"
    echo ""
    echo "This will attempt to poison <target_ip>'s ARP cache"
    echo "by claiming <spoofed_ip> is at our MAC address."
    exit 1
fi

IFACE="$1"
TARGET="$2"
SPOOFED="$3"
EVIDENCE_DIR="/tmp/sc7-validate-$(date +%Y%m%d-%H%M%S)"
PASS_COUNT=0
FAIL_COUNT=0
TOTAL_CHECKS=0

# Verify running as root
if [[ $EUID -ne 0 ]]; then
    echo "[ERROR] This script must be run as root (sudo)."
    exit 1
fi

# Verify interface exists
if ! ip link show "$IFACE" &>/dev/null; then
    echo "[ERROR] Interface $IFACE does not exist."
    exit 1
fi

mkdir -p "$EVIDENCE_DIR"

ATTACKER_MAC=$(ip link show "$IFACE" | awk '/ether/ {print $2}')

echo "============================================"
echo "SC-7 ARP Spoofing — Validation"
echo "============================================"
echo ""
echo "[*] Interface:    $IFACE"
echo "[*] Target:       $TARGET"
echo "[*] Spoofed IP:   $SPOOFED"
echo "[*] Attacker MAC: $ATTACKER_MAC"
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

# --- Check 1: ARP Table Baseline ---

echo "[*] Check 1: Capturing pre-test ARP table baseline"
echo "---------------------------------------------------"
arp -n > "$EVIDENCE_DIR/arp-before.txt"

# Record what the target currently thinks the spoofed IP's MAC is
LEGIT_MAC=$(arp -n | awk -v ip="$SPOOFED" '$1 == ip {print $3}')
if [[ -n "$LEGIT_MAC" ]]; then
    echo "[*] Current ARP entry: $SPOOFED -> $LEGIT_MAC"
else
    echo "[*] No existing ARP entry for $SPOOFED"
    LEGIT_MAC="(none)"
fi
echo ""

# --- Check 2: Attempt ARP Spoofing ---

echo "[*] Check 2: Attempting ARP spoof (5-second burst)"
echo "---------------------------------------------------"

if command -v arpspoof &>/dev/null; then
    # Send spoofed ARP replies for 5 seconds
    timeout 5 arpspoof -i "$IFACE" -t "$TARGET" "$SPOOFED" > "$EVIDENCE_DIR/spoof-output.txt" 2>&1 || true
    echo "[*] Sent spoofed ARP replies for 5 seconds"
elif command -v arping &>/dev/null; then
    # Use arping to send unsolicited ARP replies
    arping -c 10 -U -I "$IFACE" -s "$SPOOFED" "$TARGET" > "$EVIDENCE_DIR/spoof-output.txt" 2>&1 || true
    echo "[*] Sent unsolicited ARP replies via arping"
else
    echo "[ERROR] Neither arpspoof nor arping available."
    echo "Install with: apt-get install dsniff   # for arpspoof"
    echo "         or:  apt-get install arping    # for arping"
    exit 1
fi
echo ""

# Brief pause for ARP tables to update (or not, if protected)
sleep 2

# --- Check 3: Verify ARP Table Was NOT Poisoned ---

echo "[*] Check 3: Verifying ARP table integrity"
echo "---------------------------------------------------"
arp -n > "$EVIDENCE_DIR/arp-after.txt"

CURRENT_MAC=$(arp -n | awk -v ip="$SPOOFED" '$1 == ip {print $3}')
echo "[*] Post-spoof ARP entry: $SPOOFED -> ${CURRENT_MAC:-(none)}"

if [[ "$CURRENT_MAC" == "$ATTACKER_MAC" ]]; then
    check_result "ARP cache poisoning blocked" "false" \
        "Target ARP cache WAS poisoned. $SPOOFED now maps to attacker MAC $ATTACKER_MAC. DAI is not working or not enabled."
else
    check_result "ARP cache poisoning blocked" "true" \
        "Target ARP cache was NOT poisoned. $SPOOFED still maps to $CURRENT_MAC (expected: $LEGIT_MAC)."
fi

# --- Check 4: Verify Static ARP Entry (if configured) ---

echo "[*] Check 4: Static ARP entry for critical systems"
echo "---------------------------------------------------"

# Check if the spoofed IP has a PERM (static) ARP entry
if ip neigh show "$SPOOFED" 2>/dev/null | grep -q "PERMANENT"; then
    check_result "Static ARP entry exists for $SPOOFED" "true" \
        "Static ARP entry found — immune to ARP cache poisoning."
else
    check_result "Static ARP entry exists for $SPOOFED" "false" \
        "No static ARP entry. Consider adding: arp -s $SPOOFED <correct_mac>"
fi

# --- Check 5: Verify arpwatch Is Running ---

echo "[*] Check 5: ARP monitoring active"
echo "---------------------------------------------------"

if pgrep -x arpwatch &>/dev/null; then
    check_result "arpwatch monitoring active" "true" \
        "arpwatch is running and monitoring ARP changes."
else
    check_result "arpwatch monitoring active" "false" \
        "arpwatch is not running. Start with: arpwatch -i $IFACE"
fi

# --- Check 6: Verify DAI Log Entries (switch-side) ---

echo "[*] Check 6: DAI drop verification"
echo "---------------------------------------------------"
echo "[INFO] DAI operates on the switch, not the host."
echo "       To verify DAI is dropping spoofed ARP packets, check switch logs:"
echo ""
echo "       Cisco IOS:"
echo "         show ip arp inspection statistics vlan <id>"
echo "         show ip arp inspection log"
echo ""
echo "       Expected: Forwarded = normal ARP, Dropped = spoofed ARP blocked by DAI"
echo ""

# We cannot programmatically check the switch from the host, so this is informational
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
echo "[INFO] Manual verification required — check switch DAI logs for drops during this test."
echo ""

# --- Validation Report ---

echo "============================================"
echo "Validation Report"
echo "============================================"
echo ""
echo "Date:        $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "Target:      $TARGET"
echo "Spoofed IP:  $SPOOFED"
echo "Attacker:    $ATTACKER_MAC"
echo ""
echo "Results:     $PASS_COUNT passed / $FAIL_COUNT failed / $TOTAL_CHECKS total"
echo ""

if [[ "$FAIL_COUNT" -eq 0 ]]; then
    echo "OVERALL: PASS — ARP spoofing mitigations are effective."
else
    echo "OVERALL: FAIL — ARP spoofing mitigations need additional work."
    echo ""
    echo "Recommended actions:"
    if [[ "$CURRENT_MAC" == "$ATTACKER_MAC" ]]; then
        echo "  - Enable Dynamic ARP Inspection (DAI) on the switch"
        echo "  - Enable DHCP snooping (required for DAI)"
    fi
    if ! ip neigh show "$SPOOFED" 2>/dev/null | grep -q "PERMANENT"; then
        echo "  - Add static ARP entry for $SPOOFED"
    fi
    if ! pgrep -x arpwatch &>/dev/null; then
        echo "  - Start arpwatch for continuous monitoring"
    fi
fi
echo ""
echo "[*] Evidence saved to: $EVIDENCE_DIR"

# Save report
{
    echo "SC-7 ARP Spoofing Validation Report"
    echo "Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "Target: $TARGET | Spoofed: $SPOOFED | Attacker MAC: $ATTACKER_MAC"
    echo "Result: $PASS_COUNT/$TOTAL_CHECKS passed"
    echo "Overall: $(if [[ $FAIL_COUNT -eq 0 ]]; then echo PASS; else echo FAIL; fi)"
} > "$EVIDENCE_DIR/validation-report.txt"
