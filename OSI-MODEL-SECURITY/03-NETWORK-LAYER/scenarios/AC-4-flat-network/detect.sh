#!/usr/bin/env bash
set -euo pipefail

# AC-4 Flat Network — Detect
#
# Detects lack of network segmentation by performing cross-subnet reachability
# tests using Nmap. Confirms that traffic flows freely between subnets that
# should be isolated.
#
# Detection methods:
#   1. Nmap ping sweep across multiple subnets from a single host
#   2. Nmap port scan showing services reachable across subnet boundaries
#   3. Firewall rule audit for missing FORWARD chain segmentation
#   4. Traceroute analysis showing direct routing between zones
#
# REQUIREMENTS:
#   - nmap (apt-get install nmap)
#   - Root/sudo privileges
#
# USAGE:
#   sudo ./detect.sh <subnet1> <subnet2> [subnet3] [subnet4]
#
# EXAMPLE:
#   sudo ./detect.sh 10.0.1.0/24 10.0.2.0/24 10.0.3.0/24
#   (Tests cross-subnet reachability between three subnets)

# --- Argument Validation ---

if [[ $# -lt 2 ]]; then
    echo "Usage: $0 <subnet1> <subnet2> [subnet3] [subnet4]"
    echo "Example: $0 10.0.1.0/24 10.0.2.0/24 10.0.3.0/24"
    echo ""
    echo "Provide at least two subnets to test cross-subnet reachability."
    exit 1
fi

SUBNETS=("$@")

# Verify running as root
if [[ $EUID -ne 0 ]]; then
    echo "[ERROR] This script must be run as root (sudo)."
    exit 1
fi

EVIDENCE_DIR="/tmp/ac4-flat-detect-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$EVIDENCE_DIR"

FINDINGS=0

echo "============================================"
echo "AC-4 Flat Network — Detection"
echo "============================================"
echo ""
echo "[*] Subnets to test: ${SUBNETS[*]}"
echo "[*] Evidence dir:    $EVIDENCE_DIR"
echo ""

# --- Method 1: Nmap Ping Sweep Across Subnets ---

echo "[*] Method 1: Cross-subnet ping sweep"
echo "----------------------------------------------"

if command -v nmap &>/dev/null; then
    TOTAL_REACHABLE=0

    for subnet in "${SUBNETS[@]}"; do
        echo "[*] Scanning $subnet..."
        SWEEP_FILE="$EVIDENCE_DIR/sweep-$(echo "$subnet" | tr '/' '-').txt"

        # Ping sweep — fast host discovery
        nmap -sn -T4 "$subnet" -oN "$SWEEP_FILE" 2>&1 | tail -3

        # Count reachable hosts
        HOSTS_UP=$(grep -c "Host is up" "$SWEEP_FILE" 2>/dev/null || echo "0")
        TOTAL_REACHABLE=$((TOTAL_REACHABLE + HOSTS_UP))
        echo "[*] $subnet: $HOSTS_UP hosts reachable"
        echo ""
    done

    if [[ "$TOTAL_REACHABLE" -gt 0 ]]; then
        echo "[ALERT] $TOTAL_REACHABLE hosts reachable across all subnets from this host."
        echo "[*] In a properly segmented network, hosts in other zones should not respond."
        FINDINGS=$((FINDINGS + 1))
    else
        echo "[OK] No hosts reachable across subnets — segmentation may be in place."
    fi
    echo ""
else
    echo "[SKIP] nmap not installed. Install with: apt-get install nmap"
    echo ""
fi

# --- Method 2: Cross-Subnet Service Scan ---

echo "[*] Method 2: Cross-subnet service reachability"
echo "----------------------------------------------"

if command -v nmap &>/dev/null; then
    # Scan common internal services across all subnets
    # These services should NOT be reachable across zone boundaries
    COMMON_PORTS="22,80,443,445,3306,5432,1433,3389,8080,8443"

    for subnet in "${SUBNETS[@]}"; do
        echo "[*] Scanning $subnet for internal services (ports: $COMMON_PORTS)..."
        SERVICE_FILE="$EVIDENCE_DIR/services-$(echo "$subnet" | tr '/' '-').txt"

        nmap -sS -Pn -p "$COMMON_PORTS" -T4 --open \
            -oN "$SERVICE_FILE" "$subnet" 2>&1 | grep -E "^Nmap|open" || true
        echo ""

        # Count open services
        OPEN_SERVICES=$(grep -c "open" "$SERVICE_FILE" 2>/dev/null || echo "0")
        if [[ "$OPEN_SERVICES" -gt 0 ]]; then
            echo "[ALERT] $OPEN_SERVICES open services found on $subnet from this host."
            FINDINGS=$((FINDINGS + 1))
        fi
    done
    echo ""
else
    echo "[SKIP] nmap not installed."
    echo ""
fi

# --- Method 3: Firewall Rule Audit ---

echo "[*] Method 3: Firewall FORWARD chain audit"
echo "----------------------------------------------"

if command -v iptables &>/dev/null; then
    # Check FORWARD chain policy
    FORWARD_POLICY=$(iptables -L FORWARD -n 2>/dev/null | head -1 | grep -oP '\(policy \K[A-Z]+' || echo "UNKNOWN")
    echo "[*] FORWARD chain policy: $FORWARD_POLICY"

    if [[ "$FORWARD_POLICY" == "ACCEPT" ]]; then
        echo "[ALERT] FORWARD policy is ACCEPT — all cross-subnet traffic is allowed by default!"
        FINDINGS=$((FINDINGS + 1))
    fi
    echo ""

    # Check for segmentation rules in FORWARD chain
    FORWARD_RULES=$(iptables -L FORWARD -n --line-numbers 2>/dev/null | grep -c "^[0-9]" || echo "0")
    echo "[*] FORWARD chain rule count: $FORWARD_RULES"

    if [[ "$FORWARD_RULES" -eq 0 ]]; then
        echo "[ALERT] FORWARD chain is empty — no segmentation rules exist!"
        FINDINGS=$((FINDINGS + 1))
    elif [[ "$FORWARD_RULES" -eq 1 ]]; then
        # Check if the single rule is a catch-all ACCEPT
        SINGLE_RULE=$(iptables -L FORWARD -n 2>/dev/null | grep "ACCEPT" | grep "0\.0\.0\.0/0.*0\.0\.0\.0/0" || true)
        if [[ -n "$SINGLE_RULE" ]]; then
            echo "[ALERT] FORWARD chain has only a catch-all ACCEPT — no segmentation!"
            FINDINGS=$((FINDINGS + 1))
        fi
    fi
    echo ""

    # Display current FORWARD chain for evidence
    echo "[*] Current FORWARD chain rules:"
    iptables -L FORWARD -n -v --line-numbers 2>/dev/null | tee "$EVIDENCE_DIR/forward-chain.txt"
    echo ""

    # Check for inter-subnet DROP/REJECT rules
    DENY_RULES=$(iptables -L FORWARD -n 2>/dev/null | grep -E "DROP|REJECT" || true)
    if [[ -z "$DENY_RULES" ]]; then
        echo "[ALERT] No DROP or REJECT rules in FORWARD chain — nothing blocks cross-subnet traffic."
        FINDINGS=$((FINDINGS + 1))
    else
        echo "[OK] Found deny rules in FORWARD chain:"
        echo "$DENY_RULES"
    fi
    echo ""
else
    echo "[SKIP] iptables not available."
    echo ""
fi

# --- Method 4: Traceroute Analysis ---

echo "[*] Method 4: Traceroute to subnets (routing path analysis)"
echo "----------------------------------------------"

if command -v traceroute &>/dev/null; then
    for subnet in "${SUBNETS[@]}"; do
        # Use first usable IP in subnet as target
        TARGET_IP=$(echo "$subnet" | sed 's|/.*||' | awk -F. '{printf "%s.%s.%s.%d", $1,$2,$3,$4+1}')
        echo "[*] Traceroute to $TARGET_IP ($subnet):"
        traceroute -n -m 5 -w 2 "$TARGET_IP" 2>/dev/null | tee "$EVIDENCE_DIR/traceroute-$TARGET_IP.txt" || true
        echo ""
    done
elif command -v tracepath &>/dev/null; then
    for subnet in "${SUBNETS[@]}"; do
        TARGET_IP=$(echo "$subnet" | sed 's|/.*||' | awk -F. '{printf "%s.%s.%s.%d", $1,$2,$3,$4+1}')
        echo "[*] Tracepath to $TARGET_IP ($subnet):"
        tracepath -n "$TARGET_IP" 2>/dev/null | head -10 | tee "$EVIDENCE_DIR/tracepath-$TARGET_IP.txt" || true
        echo ""
    done
else
    echo "[SKIP] Neither traceroute nor tracepath installed."
fi
echo ""

# --- Evidence Summary ---

echo "============================================"
echo "Detection Summary"
echo "============================================"
echo ""
echo "[*] Total findings: $FINDINGS"
echo ""

if [[ "$FINDINGS" -gt 0 ]]; then
    echo "[ALERT] Flat network detected — inadequate segmentation!"
    echo ""
    echo "[*] Impact: An attacker on any subnet can reach services on every other subnet."
    echo "[*] This enables lateral movement — the primary cost amplifier in data breaches."
    echo "[*] IBM 2024: breaches with lateral movement cost 28% more than contained breaches."
    echo ""
    echo "[*] Run fix.sh to implement subnet segmentation with firewall rules."
else
    echo "[OK] No cross-subnet reachability issues detected."
fi

echo ""
echo "[*] Evidence saved to: $EVIDENCE_DIR"
echo "[*] Files:"
ls -la "$EVIDENCE_DIR/"
