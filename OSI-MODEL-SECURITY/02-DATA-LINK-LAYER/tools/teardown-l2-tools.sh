#!/usr/bin/env bash
set -euo pipefail

# Layer 2 — Data Link Tool Teardown
#
# Removes the detection and attack tools installed by setup-l2-tools.sh.
# Cleans up arpwatch state, evidence temp files, and restores host to
# pre-scenario state.
#
# REQUIRES: sudo privileges
# USAGE:    sudo ./teardown-l2-tools.sh [--keep-evidence]
#
# OPTIONS:
#   --keep-evidence   Skip cleanup of /tmp/sc7-* evidence directories

# --- Root Check ---

if [[ $EUID -ne 0 ]]; then
    echo "[ERROR] This script must be run as root (sudo)."
    exit 1
fi

KEEP_EVIDENCE=false
if [[ "${1:-}" == "--keep-evidence" ]]; then
    KEEP_EVIDENCE=true
fi

echo "============================================"
echo "Layer 2 — Data Link Tool Teardown"
echo "============================================"
echo ""

# --- Stop Running Processes ---

echo "[*] Stopping any running L2 tool processes..."

for proc in arpwatch arpspoof ettercap tshark tcpdump; do
    if pgrep -x "$proc" &>/dev/null; then
        echo "    [*] Stopping $proc..."
        killall "$proc" 2>/dev/null || true
        echo "    [+] $proc stopped"
    fi
done
echo ""

# --- Restore IP Forwarding ---

CURRENT_FORWARD=$(cat /proc/sys/net/ipv4/ip_forward)
if [[ "$CURRENT_FORWARD" == "1" ]]; then
    echo "[*] Disabling IP forwarding (was enabled — likely from break scenario)..."
    echo 0 > /proc/sys/net/ipv4/ip_forward
    echo "[+] IP forwarding disabled"
else
    echo "[*] IP forwarding already disabled (clean state)"
fi
echo ""

# --- Flush ARP Cache ---

echo "[*] Flushing ARP cache to remove any poisoned entries..."
ip neigh flush all 2>/dev/null || true
echo "[+] ARP cache flushed"
echo ""

# --- Remove Packages ---

PACKAGES=(
    dsniff
    arpwatch
    tshark
    arping
    tcpdump
)

# net-tools is commonly used by other things — don't remove it
echo "[*] Packages to remove: ${PACKAGES[*]}"
echo "[*] Keeping net-tools (commonly used by other tools)"
echo ""

INSTALLED=()
for pkg in "${PACKAGES[@]}"; do
    if dpkg -s "$pkg" &>/dev/null; then
        INSTALLED+=("$pkg")
    fi
done

if [[ ${#INSTALLED[@]} -eq 0 ]]; then
    echo "[*] No L2 packages installed. Nothing to remove."
else
    echo "[*] Removing: ${INSTALLED[*]}"
    apt-get remove -y -qq "${INSTALLED[@]}"
    echo "[*] Cleaning up unused dependencies..."
    apt-get autoremove -y -qq
    echo "[+] Packages removed"
fi
echo ""

# --- Clean Up arpwatch State ---

echo "[*] Cleaning up arpwatch state files..."
for f in /var/lib/arpwatch/arp.dat /var/lib/arpwatch/*.dat; do
    if [[ -f "$f" ]]; then
        rm -f "$f"
        echo "    [+] Removed $f"
    fi
done
echo ""

# --- Clean Up Evidence Temp Files ---

if [[ "$KEEP_EVIDENCE" == true ]]; then
    echo "[*] Keeping evidence directories (--keep-evidence flag set)"
    echo "[*] Evidence locations:"
    ls -d /tmp/sc7-* 2>/dev/null | while read -r dir; do
        echo "    $dir"
    done || echo "    (none found)"
else
    echo "[*] Cleaning up evidence temp directories..."
    EVIDENCE_DIRS=$(ls -d /tmp/sc7-* 2>/dev/null || true)
    if [[ -n "$EVIDENCE_DIRS" ]]; then
        echo "$EVIDENCE_DIRS" | while read -r dir; do
            rm -rf "$dir"
            echo "    [+] Removed $dir"
        done
    else
        echo "    (no evidence directories found)"
    fi
fi
echo ""

# --- Verify Clean State ---

echo "[*] Verifying teardown..."
CLEAN=true

for tool in arpspoof arpwatch tshark arping tcpdump; do
    if command -v "$tool" &>/dev/null; then
        echo "    [!!] $tool still in PATH — $(command -v "$tool")"
        CLEAN=false
    fi
done

for proc in arpwatch arpspoof ettercap tshark tcpdump; do
    if pgrep -x "$proc" &>/dev/null; then
        echo "    [!!] $proc still running"
        CLEAN=false
    fi
done

FORWARD=$(cat /proc/sys/net/ipv4/ip_forward)
if [[ "$FORWARD" == "1" ]]; then
    echo "    [!!] IP forwarding still enabled"
    CLEAN=false
fi

echo ""
if [[ "$CLEAN" == true ]]; then
    echo "[+] Teardown complete. Host restored to pre-scenario state."
else
    echo "[!] Teardown completed with warnings. Check items marked [!!] above."
fi

echo ""
echo "============================================"
echo "Layer 2 tools removed. Lab environment clean."
echo "============================================"
