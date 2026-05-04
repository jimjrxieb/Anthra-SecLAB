#!/usr/bin/env bash
set -euo pipefail

# SC-7 Firewall Misconfiguration — Break
#
# Opens 0.0.0.0/0 inbound on management ports (SSH 22, RDP 3389) by
# adding overly permissive firewall rules. Simulates a common misconfiguration
# where management interfaces are exposed to the entire internet.
#
# Supports both iptables (Linux) and Windows Firewall (netsh) commands.
# The script detects the platform and uses the appropriate tool.
#
# REQUIREMENTS:
#   - Root/sudo privileges (Linux) or Administrator (Windows)
#   - iptables (Linux) or netsh (Windows)
#
# USAGE:
#   sudo ./break.sh [interface]
#
# EXAMPLE:
#   sudo ./break.sh eth0
#   (Opens SSH and RDP from 0.0.0.0/0 on eth0)
#
# WARNING: This script is for authorized security testing only.
#          Unauthorized use is illegal under the CFAA and equivalent laws.
#
# CSF 2.0: PR.PS-01 (Configuration management applied)
# CIS v8: 17.8 (Conduct Post-Incident Reviews)
# NIST: SC-7 (Boundary Protection)
#

# --- Argument Validation ---

IFACE="${1:-}"

# Verify running as root
if [[ $EUID -ne 0 ]]; then
    echo "[ERROR] This script must be run as root (sudo)."
    exit 1
fi

# --- Platform Detection ---

PLATFORM="unknown"
if command -v iptables &>/dev/null; then
    PLATFORM="linux"
elif command -v netsh.exe &>/dev/null || command -v netsh &>/dev/null; then
    PLATFORM="windows"
else
    echo "[ERROR] Neither iptables nor netsh found."
    echo "This script requires a Linux host with iptables or a Windows host with netsh."
    exit 1
fi

echo "============================================"
echo "SC-7 Firewall Misconfiguration — Break"
echo "============================================"
echo ""
echo "[*] Platform: $PLATFORM"
echo "[*] Action:   Open management ports (SSH 22, RDP 3389) from 0.0.0.0/0"
echo ""

# --- Record Pre-Break State ---

EVIDENCE_DIR="/tmp/sc7-firewall-evidence-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$EVIDENCE_DIR"

echo "[*] Recording pre-break firewall state..."
if [[ "$PLATFORM" == "linux" ]]; then
    iptables -L -n -v --line-numbers > "$EVIDENCE_DIR/iptables-before.txt" 2>&1
    echo "[*] Saved iptables rules to $EVIDENCE_DIR/iptables-before.txt"

    if [[ -n "$IFACE" ]]; then
        if ! ip link show "$IFACE" &>/dev/null; then
            echo "[ERROR] Interface $IFACE does not exist."
            echo "Available interfaces:"
            ip -br link show
            exit 1
        fi
        echo "[*] Interface: $IFACE"
    else
        echo "[*] Interface: all (no interface specified)"
    fi
else
    netsh advfirewall firewall show rule name=all > "$EVIDENCE_DIR/firewall-before.txt" 2>&1
    echo "[*] Saved Windows Firewall rules to $EVIDENCE_DIR/firewall-before.txt"
fi
echo ""

# --- Cleanup Handler ---

cleanup() {
    echo ""
    echo "[*] Break scenario complete."
    echo "[*] Evidence saved to: $EVIDENCE_DIR"
    echo ""
    echo "[!] IMPORTANT: Management ports are now open to 0.0.0.0/0"
    echo "[!] Run fix.sh to restrict access to admin CIDR."
}

trap cleanup EXIT

# --- Execute Break ---

if [[ "$PLATFORM" == "linux" ]]; then
    echo "[*] Adding iptables rules to allow SSH (22) from 0.0.0.0/0..."

    if [[ -n "$IFACE" ]]; then
        # Open SSH from anywhere on specified interface
        iptables -A INPUT -i "$IFACE" -p tcp --dport 22 -s 0.0.0.0/0 -j ACCEPT \
            -m comment --comment "SC7-BREAK: SSH open to world"
        # Open RDP from anywhere on specified interface
        iptables -A INPUT -i "$IFACE" -p tcp --dport 3389 -s 0.0.0.0/0 -j ACCEPT \
            -m comment --comment "SC7-BREAK: RDP open to world"
    else
        # Open SSH from anywhere on all interfaces
        iptables -A INPUT -p tcp --dport 22 -s 0.0.0.0/0 -j ACCEPT \
            -m comment --comment "SC7-BREAK: SSH open to world"
        # Open RDP from anywhere on all interfaces
        iptables -A INPUT -p tcp --dport 3389 -s 0.0.0.0/0 -j ACCEPT \
            -m comment --comment "SC7-BREAK: RDP open to world"
    fi

    echo "[+] SSH (port 22) — OPEN to 0.0.0.0/0"
    echo "[+] RDP (port 3389) — OPEN to 0.0.0.0/0"
    echo ""

    # Disable any rate limiting on these ports
    echo "[*] Disabling connection rate limiting on management ports..."
    iptables -D INPUT -p tcp --dport 22 -m connlimit --connlimit-above 5 -j DROP 2>/dev/null || true
    iptables -D INPUT -p tcp --dport 3389 -m connlimit --connlimit-above 5 -j DROP 2>/dev/null || true
    echo "[+] Rate limiting removed (if it existed)"
    echo ""

    # Disable logging for these ports (hide the evidence)
    echo "[*] Removing any logging rules for management ports..."
    iptables -D INPUT -p tcp --dport 22 -j LOG --log-prefix "SSH-ACCESS: " 2>/dev/null || true
    iptables -D INPUT -p tcp --dport 3389 -j LOG --log-prefix "RDP-ACCESS: " 2>/dev/null || true
    echo "[+] Logging rules removed (if they existed)"
    echo ""

    # Record post-break state
    echo "[*] Post-break iptables rules:"
    iptables -L INPUT -n -v --line-numbers | tee "$EVIDENCE_DIR/iptables-after.txt"

else
    # Windows Firewall — netsh commands
    echo "[*] Adding Windows Firewall rules to allow SSH (22) from any..."

    netsh advfirewall firewall add rule name="SC7-BREAK: SSH Open to World" \
        dir=in action=allow protocol=tcp localport=22 \
        remoteip=any enable=yes

    netsh advfirewall firewall add rule name="SC7-BREAK: RDP Open to World" \
        dir=in action=allow protocol=tcp localport=3389 \
        remoteip=any enable=yes

    echo "[+] SSH (port 22) — OPEN to any"
    echo "[+] RDP (port 3389) — OPEN to any"
    echo ""

    # Disable Windows Firewall logging (hide the evidence)
    echo "[*] Disabling firewall logging..."
    netsh advfirewall set allprofiles logging droppedconnections disable 2>/dev/null || true
    netsh advfirewall set allprofiles logging allowedconnections disable 2>/dev/null || true
    echo "[+] Firewall logging disabled"
    echo ""

    # Record post-break state
    echo "[*] Post-break firewall rules:"
    netsh advfirewall firewall show rule name=all dir=in | \
        grep -A 5 "SC7-BREAK" | tee "$EVIDENCE_DIR/firewall-after.txt"
fi

echo ""
echo "============================================"
echo "Break Summary"
echo "============================================"
echo ""
echo "[!] Management ports SSH (22) and RDP (3389) are now open to 0.0.0.0/0"
echo "[!] No source IP restriction — any IP on the internet can attempt connection"
echo "[!] Logging has been disabled — connections will not be recorded"
echo "[!] Rate limiting has been removed — brute force is unthrottled"
echo ""
echo "[*] This is the #1 ransomware entry vector (Sophos 2024)."
echo "[*] Run detect.sh to confirm the exposure, then fix.sh to remediate."
