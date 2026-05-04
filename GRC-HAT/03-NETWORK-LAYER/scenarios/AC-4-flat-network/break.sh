#!/usr/bin/env bash
set -euo pipefail

# AC-4 Flat Network — Break
#
# Removes firewall segmentation rules to create a flat network where all
# subnets can communicate freely. Simulates a common misconfiguration where
# network segmentation is absent or has been accidentally removed.
#
# This script:
#   1. Records current firewall/routing rules (evidence)
#   2. Flushes FORWARD chain rules that enforce subnet segmentation
#   3. Sets FORWARD policy to ACCEPT (allow all cross-subnet traffic)
#   4. Disables any zone-based firewall rules
#
# REQUIREMENTS:
#   - Root/sudo privileges
#   - iptables (Linux firewall/router)
#   - Host must be acting as a gateway/router between subnets
#
# USAGE:
#   sudo ./break.sh
#
# EXAMPLE:
#   sudo ./break.sh
#   (Removes all subnet segmentation — all subnets can reach all subnets)
#
# WARNING: This script is for authorized security testing only.
#          Unauthorized use is illegal under the CFAA and equivalent laws.
#
# CSF 2.0: PR.IR-01 (Networks protected)
# CIS v8: 17.8 (Conduct Post-Incident Reviews)
# NIST: AC-4 (Information Flow Enforcement)
#

# Verify running as root
if [[ $EUID -ne 0 ]]; then
    echo "[ERROR] This script must be run as root (sudo)."
    exit 1
fi

# Verify iptables is available
if ! command -v iptables &>/dev/null; then
    echo "[ERROR] iptables not found. This script requires a Linux host acting as a router/firewall."
    exit 1
fi

EVIDENCE_DIR="/tmp/ac4-flat-network-evidence-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$EVIDENCE_DIR"

echo "============================================"
echo "AC-4 Flat Network — Break Scenario"
echo "============================================"
echo ""

# --- Record Pre-Break State ---

echo "[*] Recording pre-break network state..."
echo ""

# Save current iptables rules (full backup for rollback)
iptables-save > "$EVIDENCE_DIR/iptables-full-backup.txt"
echo "[+] Full iptables backup saved to $EVIDENCE_DIR/iptables-full-backup.txt"

# Save FORWARD chain rules specifically
echo "[*] Current FORWARD chain rules (segmentation rules):"
iptables -L FORWARD -n -v --line-numbers | tee "$EVIDENCE_DIR/forward-chain-before.txt"
echo ""

# Save routing table
echo "[*] Current routing table:"
ip route show | tee "$EVIDENCE_DIR/routes-before.txt"
echo ""

# Show current network interfaces and subnets
echo "[*] Network interfaces and subnets:"
ip -4 addr show | grep -E "inet |^[0-9]" | tee "$EVIDENCE_DIR/interfaces.txt"
echo ""

# Check current IP forwarding state
ORIG_FORWARD=$(cat /proc/sys/net/ipv4/ip_forward)
echo "[*] IP forwarding state: $ORIG_FORWARD"
echo ""

# --- Cleanup Handler ---

cleanup() {
    echo ""
    echo "[*] Break scenario complete."
    echo "[*] To restore segmentation, run: iptables-restore < $EVIDENCE_DIR/iptables-full-backup.txt"
    echo "[*] Evidence saved to: $EVIDENCE_DIR"
}

trap cleanup EXIT

# --- Execute Break ---

# Step 1: Enable IP forwarding (required for cross-subnet routing)
echo "[*] Step 1: Ensuring IP forwarding is enabled..."
echo 1 > /proc/sys/net/ipv4/ip_forward
echo "[+] IP forwarding enabled (was: $ORIG_FORWARD)"
echo ""

# Step 2: Flush all FORWARD chain rules (removes segmentation)
echo "[*] Step 2: Flushing FORWARD chain (removing all segmentation rules)..."
RULE_COUNT=$(iptables -L FORWARD -n --line-numbers 2>/dev/null | grep -c "^[0-9]" || echo "0")
iptables -F FORWARD
echo "[+] Flushed $RULE_COUNT rules from FORWARD chain"
echo ""

# Step 3: Set FORWARD policy to ACCEPT (allow all cross-subnet traffic)
echo "[*] Step 3: Setting FORWARD policy to ACCEPT..."
iptables -P FORWARD ACCEPT
echo "[+] FORWARD policy set to ACCEPT — all cross-subnet traffic is now allowed"
echo ""

# Step 4: Remove any zone-based rules in custom chains
echo "[*] Step 4: Checking for custom zone chains..."
CUSTOM_CHAINS=$(iptables -L -n 2>/dev/null | grep "^Chain" | grep -v "INPUT\|OUTPUT\|FORWARD" | awk '{print $2}' || true)
if [[ -n "$CUSTOM_CHAINS" ]]; then
    echo "[*] Found custom chains (may contain zone rules):"
    for chain in $CUSTOM_CHAINS; do
        CHAIN_RULES=$(iptables -L "$chain" -n --line-numbers 2>/dev/null | grep -c "^[0-9]" || echo "0")
        if [[ "$CHAIN_RULES" -gt 0 ]]; then
            echo "    $chain: $CHAIN_RULES rules"
            iptables -F "$chain" 2>/dev/null || true
            echo "    [+] Flushed $chain"
        fi
    done
else
    echo "[*] No custom zone chains found."
fi
echo ""

# Step 5: Add explicit ACCEPT rules for common inter-subnet traffic
echo "[*] Step 5: Adding explicit ACCEPT rules for cross-subnet traffic..."
iptables -A FORWARD -j ACCEPT -m comment --comment "AC4-BREAK: Allow all forwarded traffic"
echo "[+] Added catch-all FORWARD ACCEPT rule"
echo ""

# --- Post-Break State ---

echo "[*] Post-break FORWARD chain:"
iptables -L FORWARD -n -v --line-numbers | tee "$EVIDENCE_DIR/forward-chain-after.txt"
echo ""

echo "============================================"
echo "Break Summary"
echo "============================================"
echo ""
echo "[!] Network segmentation has been removed."
echo "[!] All subnets can now communicate freely through this host."
echo "[!] FORWARD policy: ACCEPT"
echo "[!] FORWARD chain: flushed (no segmentation rules)"
echo ""
echo "[*] This simulates a flat network — the #1 enabler of lateral movement."
echo "[*] An attacker on any subnet can now reach every other subnet."
echo "[*] Run detect.sh to confirm cross-subnet reachability, then fix.sh to segment."
