#!/usr/bin/env bash
set -euo pipefail

# PURPOSE:      Check 802.1X port-based Network Access Control (NAC) status.
#               Linux: wpa_supplicant running, EAP state per interface.
#               Windows: dot3svc service running, netsh lan show interfaces.
#               Verifies that NAC is enforced at the data link layer.
# NIST CONTROLS: IA-2 (identification/authentication), AC-3 (access enforcement), SC-7 (boundary)
# WHERE TO RUN: Linux or Windows host; run as root/Administrator for full results
# USAGE:        sudo ./audit-802.1x-status.sh [interface]
#               Default interface: eth0
#
# CSF 2.0: PR.AA-03 (Users and services authenticated)
# CIS v8: 1.4 (Use DHCP Logging to Update Asset Inventory)
# NIST: IA-3 (Device Identification and Authentication)
#

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
PASS=0; WARN=0; FAIL=0

pass()  { echo -e "${GREEN}[PASS]${NC} $1"; ((PASS++)); }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; ((WARN++)); }
fail()  { echo -e "${RED}[FAIL]${NC} $1"; ((FAIL++)); }
info()  { echo -e "${CYAN}[INFO]${NC} $1"; }

INTERFACE="${1:-eth0}"
EVIDENCE_DIR="/tmp/jsa-evidence/802.1x-status-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$EVIDENCE_DIR"

echo "============================================================"
echo " Layer 2 802.1X NAC Status Audit"
echo " NIST: IA-2 | AC-3 | SC-7"
echo " Interface: $INTERFACE"
echo " Evidence: $EVIDENCE_DIR"
echo "============================================================"
echo ""

# --- Platform detection ---
PLATFORM="linux"
if [[ -f /proc/version ]] && grep -qi "microsoft\|wsl" /proc/version 2>/dev/null; then
    PLATFORM="wsl"
fi

# Check if we're running in a context where Windows tools are available
if command -v netsh.exe &>/dev/null || command -v sc.exe &>/dev/null; then
    PLATFORM="windows"
fi

info "Detected platform: $PLATFORM"
echo "Platform: $PLATFORM" > "$EVIDENCE_DIR/platform.txt"

# ============================================================
# LINUX / WSL PATH
# ============================================================
if [[ "$PLATFORM" == "linux" || "$PLATFORM" == "wsl" ]]; then

    # --- Check 1: wpa_supplicant process ---
    info "Checking wpa_supplicant (802.1X supplicant)..."
    if pgrep -x wpa_supplicant &>/dev/null; then
        pass "wpa_supplicant is running"
        ps aux | grep wpa_supplicant | grep -v grep > "$EVIDENCE_DIR/wpa_supplicant-process.txt" || true

        # Show wpa_supplicant interfaces
        WPA_CTRL_DIRS=("/run/wpa_supplicant" "/var/run/wpa_supplicant")
        for ctrl_dir in "${WPA_CTRL_DIRS[@]}"; do
            if [[ -d "$ctrl_dir" ]]; then
                info "  wpa_supplicant control sockets: $ctrl_dir"
                ls "$ctrl_dir" > "$EVIDENCE_DIR/wpa-ctrl-sockets.txt" 2>/dev/null || true
                break
            fi
        done
    else
        fail "wpa_supplicant NOT running — 802.1X authentication not active (IA-2 gap)"
        info "  Install: apt install wpasupplicant  OR  yum install wpa_supplicant"
        info "  Configure: /etc/wpa_supplicant/wpa_supplicant-$INTERFACE.conf"
    fi

    # --- Check 2: wpa_supplicant EAP state ---
    info "Checking EAP authentication state..."
    if command -v wpa_cli &>/dev/null; then
        EAP_STATE=$(wpa_cli -i "$INTERFACE" status 2>/dev/null || echo "interface_unavailable")
        echo "$EAP_STATE" > "$EVIDENCE_DIR/wpa-cli-status.txt"

        if echo "$EAP_STATE" | grep -q "EAP state=AUTHENTICATED"; then
            pass "802.1X EAP state: AUTHENTICATED on $INTERFACE"
        elif echo "$EAP_STATE" | grep -q "EAP state="; then
            EAP_CURRENT=$(echo "$EAP_STATE" | grep "EAP state=" | cut -d= -f2)
            fail "EAP state is '$EAP_CURRENT' — not authenticated on $INTERFACE"
        elif echo "$EAP_STATE" | grep -q "interface_unavailable\|Failed\|No such"; then
            warn "wpa_cli could not query $INTERFACE — interface may not be managed by wpa_supplicant"
        else
            info "EAP status output saved to evidence"
        fi
    else
        warn "wpa_cli not found — cannot query EAP state directly"
    fi

    # --- Check 3: wpa_supplicant configuration ---
    info "Checking wpa_supplicant configuration files..."
    WPA_CONF_PATHS=(
        "/etc/wpa_supplicant/wpa_supplicant-${INTERFACE}.conf"
        "/etc/wpa_supplicant/wpa_supplicant.conf"
        "/etc/wpa_supplicant.conf"
    )
    WPA_CONF_FOUND=false

    for conf in "${WPA_CONF_PATHS[@]}"; do
        if [[ -f "$conf" ]]; then
            WPA_CONF_FOUND=true
            pass "wpa_supplicant configuration found: $conf"
            # Check for EAP method configured
            if grep -q "eap=" "$conf" 2>/dev/null; then
                EAP_METHOD=$(grep "eap=" "$conf" | head -1 | tr -d ' ')
                pass "EAP method configured: $EAP_METHOD"
            else
                warn "No EAP method found in $conf — 802.1X may not be configured for wired NAC"
            fi
            # Sanitize copy for evidence (remove passwords/certs)
            grep -v -E "password|private_key_passwd|pin=" "$conf" > "$EVIDENCE_DIR/wpa-conf-sanitized.txt" 2>/dev/null || true
            break
        fi
    done

    if [[ "$WPA_CONF_FOUND" == "false" ]]; then
        warn "No wpa_supplicant configuration file found"
        info "  Expected at: /etc/wpa_supplicant/wpa_supplicant-${INTERFACE}.conf"
    fi

    # --- Check 4: hostapd (authenticator role) ---
    info "Checking hostapd (802.1X authenticator for AP/switch role)..."
    if pgrep -x hostapd &>/dev/null; then
        pass "hostapd running — this host acts as an 802.1X authenticator"
        ps aux | grep hostapd | grep -v grep > "$EVIDENCE_DIR/hostapd-process.txt" || true
    else
        info "hostapd not running — this host is in supplicant (client) role"
    fi

    # --- Check 5: NetworkManager 802.1X ---
    info "Checking NetworkManager for 802.1X profiles..."
    if command -v nmcli &>/dev/null; then
        NM_CONNECTIONS=$(nmcli -t -f NAME,TYPE connection show 2>/dev/null || true)
        echo "$NM_CONNECTIONS" > "$EVIDENCE_DIR/nm-connections.txt"
        # Check for 802.1X in connection details
        NM_8021X=$(nmcli -t connection show 2>/dev/null | grep -i "8021x\|eap" || true)
        if [[ -n "$NM_8021X" ]]; then
            pass "NetworkManager has 802.1X/EAP configured connections"
        else
            warn "No 802.1X connections found in NetworkManager"
        fi
    else
        info "nmcli not available — NetworkManager not in use"
    fi

    # --- Check 6: Radius client availability ---
    info "Checking for RADIUS client tools (freeradius-client, radtest)..."
    if command -v radtest &>/dev/null; then
        pass "radtest available — RADIUS authentication testing capability present"
    else
        info "radtest not installed — optional for RADIUS NAC testing"
    fi

fi

# ============================================================
# WINDOWS PATH (native or WSL with Windows tools)
# ============================================================
if [[ "$PLATFORM" == "windows" ]]; then

    # --- Check 1: dot3svc (Wired AutoConfig service) ---
    info "Checking dot3svc (Wired AutoConfig / 802.1X) service..."
    DOT3SVC_STATUS=$(sc.exe query dot3svc 2>/dev/null || echo "query_failed")
    echo "$DOT3SVC_STATUS" > "$EVIDENCE_DIR/dot3svc-status.txt"

    if echo "$DOT3SVC_STATUS" | grep -q "RUNNING"; then
        pass "dot3svc (Wired AutoConfig) is RUNNING — 802.1X capable"
    elif echo "$DOT3SVC_STATUS" | grep -q "STOPPED"; then
        fail "dot3svc is STOPPED — 802.1X wired NAC not active (IA-2 gap)"
        info "  Fix: sc.exe start dot3svc  OR  Set-Service dot3svc -StartupType Automatic"
    else
        warn "Could not determine dot3svc status"
    fi

    # --- Check 2: netsh lan show interfaces ---
    info "Checking wired LAN 802.1X interface status..."
    NETSH_STATUS=$(netsh.exe lan show interfaces 2>/dev/null || echo "netsh_unavailable")
    echo "$NETSH_STATUS" > "$EVIDENCE_DIR/netsh-lan-interfaces.txt"

    if echo "$NETSH_STATUS" | grep -qi "authentication.*enabled\|802.1x.*enabled"; then
        pass "802.1X authentication enabled on wired interface(s)"
    elif echo "$NETSH_STATUS" | grep -qi "enabled"; then
        warn "Interface enabled but 802.1X authentication state unclear — review evidence"
    else
        fail "802.1X not detected as enabled on wired interfaces"
    fi

    # --- Check 3: EAP profile existence ---
    info "Checking for 802.1X EAP profiles..."
    NETSH_PROFILES=$(netsh.exe lan show profiles 2>/dev/null || echo "no_profiles")
    echo "$NETSH_PROFILES" > "$EVIDENCE_DIR/netsh-lan-profiles.txt"

    if echo "$NETSH_PROFILES" | grep -q "Profile"; then
        pass "LAN profiles configured — 802.1X EAP settings may be present"
    else
        warn "No LAN profiles found — 802.1X EAP may not be configured"
    fi

fi

# ============================================================
# SUMMARY
# ============================================================
echo ""
echo "============================================================"
echo " AUDIT SUMMARY"
echo "============================================================"
echo -e " ${GREEN}PASS: $PASS${NC}  ${YELLOW}WARN: $WARN${NC}  ${RED}FAIL: $FAIL${NC}"
echo ""
echo " Evidence saved: $EVIDENCE_DIR"
echo ""
info "Enterprise equivalent: Cisco ISE (\$50K+ for full NAC deployment)"
info "Open source path: FreeRADIUS + wpa_supplicant + hostapd"

cat > "$EVIDENCE_DIR/audit-summary.txt" <<EOF
Layer 2 802.1X NAC Status Audit
Date: $(date)
Hostname: $(hostname)
Platform: $PLATFORM
Interface: $INTERFACE
PASS: $PASS  WARN: $WARN  FAIL: $FAIL
NIST Controls: IA-2, AC-3, SC-7
EOF

if [[ $FAIL -gt 0 ]]; then
    echo ""
    fail "FAIL findings present — 802.1X NAC enforcement gaps require remediation"
    exit 1
fi
