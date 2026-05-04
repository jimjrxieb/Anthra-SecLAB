#!/usr/bin/env bash
set -euo pipefail

# PURPOSE:      Install and configure arpwatch for ARP monitoring.
#               Steps: detect package manager, install arpwatch, set interface,
#               enable and start the service, verify it is running.
#               Includes rsyslog forwarding configuration for SIEM integration.
# NIST CONTROLS: SI-4 (monitoring), AC-6 (least privilege for service account), SC-7 (boundary)
# WHERE TO RUN: Linux host with root/sudo; internet access required for package install
# USAGE:        sudo ./fix-arp-monitoring.sh [interface] [siem_host:port]
#               Example: sudo ./fix-arp-monitoring.sh eth0 siem.corp.local:514
#
# CSF 2.0: DE.CM-01 (Networks monitored)
# CIS v8: 13.2 (Deploy Network-Based IDS)
# NIST: SI-4 (Information System Monitoring)
#

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
PASS=0; WARN=0; FAIL=0

pass()  { echo -e "${GREEN}[PASS]${NC} $1"; ((PASS++)); }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; ((WARN++)); }
fail()  { echo -e "${RED}[FAIL]${NC} $1"; ((FAIL++)); }
info()  { echo -e "${CYAN}[INFO]${NC} $1"; }
header(){ echo ""; echo -e "${CYAN}=== $1 ===${NC}"; }

INTERFACE="${1:-eth0}"
SIEM_TARGET="${2:-}"  # Optional: host:port for syslog forwarding

echo "============================================================"
echo " Layer 2 ARP Monitoring Fix — Install arpwatch"
echo " NIST: SI-4 | AC-6 | SC-7"
echo " Interface: $INTERFACE"
echo "============================================================"
echo ""

# --- Verify root ---
if [[ $EUID -ne 0 ]]; then
    fail "This script must be run as root. Use: sudo $0"
    exit 1
fi

# ============================================================
# STEP 1: Install arpwatch
# ============================================================
header "Step 1: Install arpwatch"

if command -v arpwatch &>/dev/null; then
    pass "arpwatch is already installed at $(which arpwatch)"
else
    info "Detecting package manager..."

    if command -v apt-get &>/dev/null; then
        info "Using apt-get (Debian/Ubuntu)..."
        apt-get update -qq
        apt-get install -y arpwatch
        pass "arpwatch installed via apt-get"

    elif command -v yum &>/dev/null; then
        info "Using yum (RHEL/CentOS 7)..."
        yum install -y arpwatch
        pass "arpwatch installed via yum"

    elif command -v dnf &>/dev/null; then
        info "Using dnf (RHEL/CentOS 8+/Fedora)..."
        dnf install -y arpwatch
        pass "arpwatch installed via dnf"

    else
        fail "No supported package manager found (apt-get, yum, dnf)"
        fail "Install arpwatch manually then re-run this script"
        exit 1
    fi
fi

# ============================================================
# STEP 2: Configure arpwatch interface and options
# ============================================================
header "Step 2: Configure arpwatch"

# Locate default config file
ARPWATCH_SYSCONFIG=""
for f in /etc/default/arpwatch /etc/sysconfig/arpwatch; do
    if [[ -f "$f" ]]; then
        ARPWATCH_SYSCONFIG="$f"
        break
    fi
done

# Determine data directory
ARPWATCH_DATA_DIR="/var/lib/arpwatch"
[[ -d /var/arpwatch ]] && ARPWATCH_DATA_DIR="/var/arpwatch"
mkdir -p "$ARPWATCH_DATA_DIR"
chown arpwatch:arpwatch "$ARPWATCH_DATA_DIR" 2>/dev/null || \
    chown nobody:nogroup "$ARPWATCH_DATA_DIR" 2>/dev/null || \
    info "Could not set arpwatch ownership — manual verification needed"

if [[ -n "$ARPWATCH_SYSCONFIG" ]]; then
    info "Backing up existing config: ${ARPWATCH_SYSCONFIG}.bak"
    cp "$ARPWATCH_SYSCONFIG" "${ARPWATCH_SYSCONFIG}.bak"

    # Set interface in config
    # Different distros use different variable names
    if grep -q "^IFACE" "$ARPWATCH_SYSCONFIG" 2>/dev/null; then
        sed -i "s|^IFACE=.*|IFACE=\"$INTERFACE\"|" "$ARPWATCH_SYSCONFIG"
    elif grep -q "^ARGS" "$ARPWATCH_SYSCONFIG" 2>/dev/null; then
        sed -i "s|^ARGS=.*|ARGS=\"-i $INTERFACE -u arpwatch\"|" "$ARPWATCH_SYSCONFIG"
    else
        echo "ARGS=\"-i $INTERFACE -u arpwatch\"" >> "$ARPWATCH_SYSCONFIG"
    fi
    pass "arpwatch configured for interface: $INTERFACE (via $ARPWATCH_SYSCONFIG)"
else
    # Create systemd override for interface
    SYSTEMD_OVERRIDE_DIR="/etc/systemd/system/arpwatch.service.d"
    mkdir -p "$SYSTEMD_OVERRIDE_DIR"
    cat > "$SYSTEMD_OVERRIDE_DIR/interface.conf" <<OVERRIDE
[Service]
ExecStart=
ExecStart=/usr/sbin/arpwatch -i $INTERFACE -u arpwatch -f ${ARPWATCH_DATA_DIR}/arp.dat
OVERRIDE
    pass "arpwatch interface configured via systemd override: $SYSTEMD_OVERRIDE_DIR/interface.conf"
    systemctl daemon-reload
fi

# ============================================================
# STEP 3: Enable and start arpwatch service
# ============================================================
header "Step 3: Enable and start arpwatch"

if command -v systemctl &>/dev/null; then
    systemctl enable arpwatch
    pass "arpwatch enabled at boot"

    systemctl restart arpwatch
    sleep 2

    if systemctl is-active --quiet arpwatch; then
        pass "arpwatch service is ACTIVE"
        systemctl status arpwatch --no-pager
    else
        fail "arpwatch failed to start — check: journalctl -u arpwatch -n 50"
    fi
else
    service arpwatch start || fail "Could not start arpwatch"
    pass "arpwatch started via service command"
fi

# ============================================================
# STEP 4: Verify arpwatch is capturing
# ============================================================
header "Step 4: Verify arpwatch is capturing"

sleep 3  # Give arpwatch time to write initial data

if [[ -f "${ARPWATCH_DATA_DIR}/arp.dat" ]]; then
    ENTRY_COUNT=$(wc -l < "${ARPWATCH_DATA_DIR}/arp.dat" 2>/dev/null || echo "0")
    pass "arpwatch database exists: ${ARPWATCH_DATA_DIR}/arp.dat ($ENTRY_COUNT entries)"
else
    warn "arpwatch database not yet created — may need traffic on $INTERFACE to initialize"
    info "  Generate traffic: ping -c 5 \$(ip route | grep default | awk '{print \$3}')"
fi

# Verify arpwatch is listening on correct interface
if pgrep -a arpwatch 2>/dev/null | grep -q "$INTERFACE"; then
    pass "arpwatch process confirmed on interface $INTERFACE"
else
    warn "Could not confirm arpwatch is bound to $INTERFACE — check process list"
    pgrep -a arpwatch 2>/dev/null || true
fi

# ============================================================
# STEP 5: Configure rsyslog for SIEM forwarding
# ============================================================
header "Step 5: Configure rsyslog for arpwatch SIEM forwarding"

# ---- HOW TO CREATE A CUSTOM ARP ALERT ----
# arpwatch logs to syslog with the program name 'arpwatch'.
# Log events include:
#   "new station"     — new MAC/IP pair seen (possible rogue device)
#   "changed ethernet address"  — ARP flip-flop (possible spoofing)
#   "flip flop"       — MAC changed and changed back (ARP poisoning indicator)
#   "new activity"    — known MAC/IP seen again after absence
#
# The rsyslog filter below captures arpwatch messages and:
#   1. Writes them to a local log for local SOC review
#   2. Forwards them to SIEM via UDP/TCP syslog (if SIEM_TARGET is set)
# ------------------------------------------

RSYSLOG_ARPWATCH_CONF="/etc/rsyslog.d/10-arpwatch.conf"

if [[ -f "$RSYSLOG_ARPWATCH_CONF" ]]; then
    info "rsyslog arpwatch config already exists: $RSYSLOG_ARPWATCH_CONF"
    info "Backing up to ${RSYSLOG_ARPWATCH_CONF}.bak"
    cp "$RSYSLOG_ARPWATCH_CONF" "${RSYSLOG_ARPWATCH_CONF}.bak"
fi

if [[ -n "$SIEM_TARGET" ]]; then
    SIEM_HOST="${SIEM_TARGET%%:*}"
    SIEM_PORT="${SIEM_TARGET##*:}"
    FORWARD_DIRECTIVE="*.* @@${SIEM_HOST}:${SIEM_PORT}"  # @@ = TCP, @ = UDP
    info "Configuring forwarding to SIEM: $SIEM_HOST:$SIEM_PORT (TCP)"
else
    FORWARD_DIRECTIVE="# SIEM forwarding not configured — set SIEM_TARGET argument to enable"
    warn "No SIEM target specified — local logging only"
    info "  Re-run: sudo ./fix-arp-monitoring.sh $INTERFACE <siem_host>:<port>"
fi

cat > "$RSYSLOG_ARPWATCH_CONF" <<RSYSLOG_EOF
# arpwatch syslog filter — SI-4 monitoring, SC-7 boundary protection
# Generated by fix-arp-monitoring.sh $(date)
#
# arpwatch event types logged:
#   new station          — new MAC/IP seen (rogue device indicator)
#   changed ethernet address — ARP flip-flop (spoofing indicator)
#   flip flop            — MAC oscillation (ARP poisoning)
#   new activity         — reactivated MAC/IP pair
#
# NIST SI-4: System monitoring requires logging of ARP anomalies.
# NIST SC-7: Boundary protection includes L2 ARP integrity monitoring.

# --- Local log file for all arpwatch events ---
:programname, isequal, "arpwatch" {
    /var/log/arpwatch.log
    stop
}

# --- Forward to SIEM (uncomment and set target to enable) ---
# :programname, isequal, "arpwatch" @@siem.corp.local:514
$FORWARD_DIRECTIVE
RSYSLOG_EOF

pass "rsyslog arpwatch config written: $RSYSLOG_ARPWATCH_CONF"

# Create log file with correct permissions
touch /var/log/arpwatch.log
chmod 640 /var/log/arpwatch.log

# Reload rsyslog
if command -v systemctl &>/dev/null; then
    systemctl reload rsyslog 2>/dev/null || systemctl restart rsyslog 2>/dev/null
    pass "rsyslog reloaded"
elif command -v service &>/dev/null; then
    service rsyslog reload 2>/dev/null || service rsyslog restart 2>/dev/null
    pass "rsyslog reloaded"
fi

# ============================================================
# SUMMARY
# ============================================================
echo ""
echo "============================================================"
echo " FIX SUMMARY"
echo "============================================================"
echo -e " ${GREEN}PASS: $PASS${NC}  ${YELLOW}WARN: $WARN${NC}  ${RED}FAIL: $FAIL${NC}"
echo ""
echo " arpwatch is monitoring: $INTERFACE"
echo " Database: ${ARPWATCH_DATA_DIR}/arp.dat"
echo " Local log: /var/log/arpwatch.log"
if [[ -n "$SIEM_TARGET" ]]; then
    echo " SIEM forward: $SIEM_TARGET (TCP syslog)"
fi
echo ""
info "Validate with: sudo ./01-auditors/audit-arp-integrity.sh $INTERFACE"
info "Run all audits: sudo ./tools/run-all-audits.sh"
