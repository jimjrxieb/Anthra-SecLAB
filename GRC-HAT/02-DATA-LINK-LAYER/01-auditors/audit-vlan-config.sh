#!/usr/bin/env bash
set -euo pipefail

# PURPOSE:      Verify VLAN segmentation controls: interfaces exist, 802.1q module loaded,
#               bridge VLAN filtering active, native VLAN is not VLAN 1 (VLAN hopping risk).
# NIST CONTROLS: SC-7 (boundary protection), AC-4 (information flow enforcement), AC-3 (access enforcement)
# WHERE TO RUN: Linux host or VM; run as root or sudo for full results
# USAGE:        sudo ./audit-vlan-config.sh
#
# CSF 2.0: PR.IR-01 (Networks protected from unauthorized access)
# CIS v8: 12.2 (Establish Network-Based Segmentation)
# NIST: SC-7 (Boundary Protection)
#

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
PASS=0; WARN=0; FAIL=0

pass()  { echo -e "${GREEN}[PASS]${NC} $1"; ((PASS++)); }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; ((WARN++)); }
fail()  { echo -e "${RED}[FAIL]${NC} $1"; ((FAIL++)); }
info()  { echo -e "${CYAN}[INFO]${NC} $1"; }

EVIDENCE_DIR="/tmp/jsa-evidence/vlan-config-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$EVIDENCE_DIR"

echo "============================================================"
echo " Layer 2 VLAN Configuration Audit"
echo " NIST: SC-7 | AC-4 | AC-3"
echo " Evidence: $EVIDENCE_DIR"
echo "============================================================"
echo ""

# --- Check 1: 802.1q kernel module ---
info "Checking 802.1q VLAN kernel module..."
if lsmod 2>/dev/null | grep -q "^8021q"; then
    pass "802.1q kernel module is loaded"
    lsmod | grep 8021q > "$EVIDENCE_DIR/8021q-module.txt" 2>/dev/null || true
else
    fail "802.1q kernel module NOT loaded — VLAN tagging not supported at kernel level"
    info "  Load: sudo modprobe 8021q"
    info "  Persist: echo '8021q' | sudo tee -a /etc/modules"
fi

# --- Check 2: VLAN interfaces ---
info "Checking for VLAN-tagged interfaces (ip -d link)..."
VLAN_IFACES=$(ip -d link show 2>/dev/null | grep -A2 "vlan" | grep "id" || true)

if [[ -n "$VLAN_IFACES" ]]; then
    pass "VLAN interfaces detected"
    echo "$VLAN_IFACES"
    ip -d link show 2>/dev/null > "$EVIDENCE_DIR/ip-link-detail.txt"

    # Extract VLAN IDs and check for VLAN 1 native
    VLAN_IDS=$(echo "$VLAN_IFACES" | grep -oE 'id [0-9]+' | awk '{print $2}' || true)
    echo "$VLAN_IDS" > "$EVIDENCE_DIR/vlan-ids.txt"

    if echo "$VLAN_IDS" | grep -q "^1$"; then
        fail "VLAN 1 is in use as a configured VLAN ID — verify it is not the native VLAN on trunks (VLAN hopping risk)"
    else
        pass "VLAN 1 not detected as an active tagged VLAN ID"
    fi
else
    warn "No VLAN-tagged interfaces found — may be a flat network or VLAN config is on physical switch"
    info "  If VLANs should be present, check: ip -d link show | grep vlan"
    ip -d link show 2>/dev/null > "$EVIDENCE_DIR/ip-link-detail.txt" || true
fi

# --- Check 3: Bridge VLAN filtering ---
info "Checking Linux bridge VLAN filtering..."
BRIDGES=$(ip link show type bridge 2>/dev/null | grep -oP '(?<=^\d+: )[^:]+' || \
          brctl show 2>/dev/null | grep -v 'bridge name' | awk '{print $1}' | grep -v '^$' || true)

if [[ -n "$BRIDGES" ]]; then
    info "Bridges found: $BRIDGES"
    VLAN_FILTER_ENABLED=false

    while IFS= read -r bridge; do
        [[ -z "$bridge" ]] && continue
        VLAN_FILTER=$(cat "/sys/class/net/$bridge/bridge/vlan_filtering" 2>/dev/null || echo "unknown")
        if [[ "$VLAN_FILTER" == "1" ]]; then
            pass "Bridge '$bridge': VLAN filtering ENABLED"
            VLAN_FILTER_ENABLED=true
            # Show bridge VLAN table
            bridge vlan show dev "$bridge" 2>/dev/null >> "$EVIDENCE_DIR/bridge-vlan-table.txt" || true
        elif [[ "$VLAN_FILTER" == "0" ]]; then
            fail "Bridge '$bridge': VLAN filtering DISABLED — all traffic can cross VLAN boundaries"
            info "  Fix: ip link set $bridge type bridge vlan_filtering 1"
        else
            warn "Bridge '$bridge': Cannot determine VLAN filtering status"
        fi
    done <<< "$BRIDGES"

    # Check bridge VLAN table for native VLAN 1 issues
    if [[ "$VLAN_FILTER_ENABLED" == "true" ]]; then
        BRIDGE_VLAN_TABLE=$(bridge vlan show 2>/dev/null || true)
        echo "$BRIDGE_VLAN_TABLE" > "$EVIDENCE_DIR/bridge-vlan-show.txt"

        # Native VLAN check: PVID untagged on VLAN 1
        if echo "$BRIDGE_VLAN_TABLE" | grep -E "^\s+1\s.*PVID.*Egress Untagged" &>/dev/null || \
           echo "$BRIDGE_VLAN_TABLE" | grep -E "1\s+PVID untagged" &>/dev/null; then
            fail "Native VLAN is VLAN 1 on a bridge port — VLAN hopping risk (SC-7 violation)"
            info "  Recommended: Change native VLAN to an unused VLAN (e.g., 999)"
        else
            pass "Native VLAN 1 not detected as PVID untagged on bridge ports"
        fi
    fi
else
    warn "No Linux bridges found — VLAN segmentation may be enforced at physical/virtual switch level"
    info "  If using a managed switch, verify VLAN configuration on the switch directly"
fi

# --- Check 4: DTP (Dynamic Trunking Protocol) equivalent ---
info "Checking for dynamic VLAN trunk negotiation exposure..."
# On Linux, check for GVRP/MVRP which are Linux equivalents of DTP
if command -v bridge &>/dev/null; then
    MVRP_STATUS=$(cat /sys/class/net/*/bridge/mcast_vlan_aware 2>/dev/null | head -1 || echo "unknown")
    info "MVRP/GVRP dynamic VLAN registration: checking..."
fi

# Check for lldpd as an indicator of trunk negotiation awareness
if command -v lldpctl &>/dev/null || systemctl is-active --quiet lldpd 2>/dev/null; then
    info "LLDP daemon running — verify LLDP data exposure is intentional (AC-4)"
    warn "LLDP broadcasts network topology — ensure it is disabled on untrusted ports"
else
    pass "LLDP daemon not active — trunk negotiation broadcast exposure reduced"
fi

# --- Check 5: Network namespace isolation ---
info "Checking network namespace isolation..."
NS_COUNT=$(ip netns list 2>/dev/null | wc -l || echo "0")
if [[ "$NS_COUNT" -gt 0 ]]; then
    pass "Network namespaces in use ($NS_COUNT) — container/VM network isolation active"
    ip netns list 2>/dev/null > "$EVIDENCE_DIR/network-namespaces.txt" || true
else
    info "No additional network namespaces — single flat network namespace"
fi

# --- Check 6: Interface listing summary ---
info "Saving full interface listing to evidence..."
ip -d link show 2>/dev/null > "$EVIDENCE_DIR/ip-d-link-full.txt" || true
ip addr show 2>/dev/null > "$EVIDENCE_DIR/ip-addr-show.txt" || true

# Count VLAN interfaces by type
VLAN_COUNT=$(ip -d link show 2>/dev/null | grep -c "vlan protocol" || echo "0")
info "Total VLAN-tagged interfaces: $VLAN_COUNT"

# --- Evidence summary ---
echo ""
echo "============================================================"
echo " AUDIT SUMMARY"
echo "============================================================"
echo -e " ${GREEN}PASS: $PASS${NC}  ${YELLOW}WARN: $WARN${NC}  ${RED}FAIL: $FAIL${NC}"
echo ""
echo " Evidence saved: $EVIDENCE_DIR"

cat > "$EVIDENCE_DIR/audit-summary.txt" <<EOF
Layer 2 VLAN Configuration Audit
Date: $(date)
Hostname: $(hostname)
PASS: $PASS  WARN: $WARN  FAIL: $FAIL
NIST Controls: SC-7, AC-4, AC-3
EOF

if [[ $FAIL -gt 0 ]]; then
    echo ""
    fail "FAIL findings require remediation — see playbooks/02a-fix-AC3-vlan-segmentation.md"
    exit 1
fi
