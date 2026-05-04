#!/usr/bin/env bash
set -euo pipefail

# Layer 2 — Data Link Tool Setup
#
# Installs the detection and attack tools needed for SC-7 ARP spoofing
# and AC-3 VLAN hopping scenarios. Run once before starting L2 break/fix.
#
# REQUIRES: sudo privileges
# USAGE:    sudo ./setup-l2-tools.sh
# TEARDOWN: sudo ./teardown-l2-tools.sh
#
# CSF 2.0: ID.RA-01 (Vulnerabilities identified)
# CIS v8: 7.1 (Establish Vulnerability Management Process)
# NIST: SA-10 (Developer Configuration Management)
#

# --- Root Check ---

if [[ $EUID -ne 0 ]]; then
    echo "[ERROR] This script must be run as root (sudo)."
    exit 1
fi

echo "============================================"
echo "Layer 2 — Data Link Tool Setup"
echo "============================================"
echo ""

# --- Define Packages ---

PACKAGES=(
    dsniff          # arpspoof — ARP cache poisoning (break scenario)
    arpwatch        # ARP change detection and alerting (detect scenario)
    tshark          # Wireshark CLI — packet capture and ARP analysis (detect scenario)
    arping          # ARP ping — validation and testing (validate scenario)
    net-tools       # arp command — ARP table inspection (all scenarios)
    tcpdump         # Low-level packet capture — backup to tshark
)

echo "[*] Packages to install:"
for pkg in "${PACKAGES[@]}"; do
    echo "    - $pkg"
done
echo ""

# --- Pre-Install State ---

echo "[*] Checking which packages are already installed..."
ALREADY_INSTALLED=()
TO_INSTALL=()

for pkg in "${PACKAGES[@]}"; do
    if dpkg -s "$pkg" &>/dev/null; then
        ALREADY_INSTALLED+=("$pkg")
    else
        TO_INSTALL+=("$pkg")
    fi
done

if [[ ${#ALREADY_INSTALLED[@]} -gt 0 ]]; then
    echo "[*] Already installed: ${ALREADY_INSTALLED[*]}"
fi

if [[ ${#TO_INSTALL[@]} -eq 0 ]]; then
    echo "[+] All packages already installed. Nothing to do."
    echo ""
    echo "[*] Verifying tool availability..."
    for tool in arpspoof arpwatch tshark arping arp tcpdump; do
        if command -v "$tool" &>/dev/null; then
            echo "    [OK] $tool — $(command -v "$tool")"
        else
            echo "    [!!] $tool — not found in PATH"
        fi
    done
    exit 0
fi

echo "[*] To install: ${TO_INSTALL[*]}"
echo ""

# --- Install ---

echo "[*] Updating package index..."
apt-get update -qq

echo "[*] Installing packages..."
# DEBIAN_FRONTEND prevents tshark from prompting about wireshark capture group
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${TO_INSTALL[@]}"

echo ""
echo "[+] Installation complete."
echo ""

# --- Post-Install Verification ---

echo "[*] Verifying tool availability..."
PASS=0
FAIL=0

for tool in arpspoof arpwatch tshark arping arp tcpdump; do
    if command -v "$tool" &>/dev/null; then
        echo "    [OK] $tool — $(command -v "$tool")"
        PASS=$((PASS + 1))
    else
        echo "    [!!] $tool — not found in PATH"
        FAIL=$((FAIL + 1))
    fi
done

echo ""
echo "[*] Results: $PASS tools available, $FAIL missing"

# --- Network Interface Info ---

echo ""
echo "[*] Available network interfaces for L2 scenarios:"
ip -br link show | while read -r name state _; do
    echo "    $name ($state)"
done

echo ""
echo "[*] Docker bridge network (k3d nodes):"
docker network inspect k3d-seclab 2>/dev/null | python3 -c "
import sys, json
data = json.load(sys.stdin)
subnet = data[0]['IPAM']['Config'][0]['Subnet']
print(f'    Subnet: {subnet}')
print('    Containers:')
for name, info in data[0]['Containers'].items():
    print(f\"      {info['Name']:30s} {info['IPv4Address']}\")
" 2>/dev/null || echo "    [SKIP] k3d-seclab network not found or docker not accessible"

echo ""
echo "============================================"
echo "Setup complete. Ready for L2 scenarios."
echo ""
echo "Next steps:"
echo "  1. cd scenarios/SC-7-arp-spoofing/"
echo "  2. sudo ./break.sh <interface> <target1_ip> <target2_ip>"
echo "  3. sudo ./detect.sh <interface> 60"
echo "============================================"
