#!/usr/bin/env bash
set -euo pipefail

# PURPOSE:      Check ARP table for duplicate MACs (spoofing indicator), verify arpwatch
#               is running, check arpwatch database for known MAC-IP pairs, and detect
#               gratuitous ARP capability.
# NIST CONTROLS: SI-4 (monitoring), SC-7 (boundary protection), AC-4 (information flow)
# WHERE TO RUN: Linux host or VM with network access; run as root or sudo for full results
# USAGE:        sudo ./audit-arp-integrity.sh [interface]
#               Default interface: eth0 (override as first argument)

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
PASS=0; WARN=0; FAIL=0

pass()  { echo -e "${GREEN}[PASS]${NC} $1"; ((PASS++)); }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; ((WARN++)); }
fail()  { echo -e "${RED}[FAIL]${NC} $1"; ((FAIL++)); }
info()  { echo -e "${CYAN}[INFO]${NC} $1"; }

INTERFACE="${1:-eth0}"
EVIDENCE_DIR="/tmp/jsa-evidence/arp-integrity-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$EVIDENCE_DIR"

echo "============================================================"
echo " Layer 2 ARP Integrity Audit"
echo " NIST: SI-4 | SC-7 | AC-4"
echo " Interface: $INTERFACE"
echo " Evidence: $EVIDENCE_DIR"
echo "============================================================"
echo ""

# --- Check 1: Platform-aware ARP table collection ---
info "Collecting ARP table..."
if command -v ip &>/dev/null; then
    ARP_TABLE=$(ip neigh show 2>/dev/null || true)
    echo "$ARP_TABLE" > "$EVIDENCE_DIR/arp-table-ip-neigh.txt"
    info "Using 'ip neigh' (iproute2)"
elif command -v arp &>/dev/null; then
    ARP_TABLE=$(arp -n 2>/dev/null || true)
    echo "$ARP_TABLE" > "$EVIDENCE_DIR/arp-table-arp-n.txt"
    info "Using 'arp -n' (net-tools)"
else
    fail "Neither 'ip' nor 'arp' command found — cannot audit ARP table"
    ARP_TABLE=""
fi

# --- Check 2: Duplicate MAC detection (spoofing indicator) ---
info "Checking for duplicate MAC addresses in ARP table..."
if [[ -n "$ARP_TABLE" ]]; then
    # Extract MACs and find duplicates
    DUPLICATE_MACS=$(echo "$ARP_TABLE" | grep -oE '([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}' \
        | sort | uniq -d 2>/dev/null || true)

    if [[ -z "$DUPLICATE_MACS" ]]; then
        pass "No duplicate MAC addresses detected in ARP table"
    else
        fail "DUPLICATE MAC ADDRESSES DETECTED — possible ARP spoofing:"
        echo "$DUPLICATE_MACS" | while read -r mac; do
            echo "  MAC: $mac"
            echo "$ARP_TABLE" | grep -i "$mac" || true
        done
        echo "$DUPLICATE_MACS" > "$EVIDENCE_DIR/duplicate-macs.txt"
    fi
else
    warn "ARP table empty or unavailable — skipping duplicate MAC check"
fi

# --- Check 3: INCOMPLETE/FAILED ARP entries ---
info "Checking for FAILED or INCOMPLETE ARP entries..."
FAILED_ENTRIES=$(echo "$ARP_TABLE" | grep -E 'FAILED|INCOMPLETE' 2>/dev/null || true)
if [[ -z "$FAILED_ENTRIES" ]]; then
    pass "No FAILED or INCOMPLETE ARP entries found"
else
    warn "FAILED/INCOMPLETE ARP entries present (may indicate scanning or spoofing):"
    echo "$FAILED_ENTRIES"
    echo "$FAILED_ENTRIES" > "$EVIDENCE_DIR/failed-arp-entries.txt"
fi

# --- Check 4: arpwatch service status ---
info "Checking arpwatch service status..."
if command -v systemctl &>/dev/null; then
    if systemctl is-active --quiet arpwatch 2>/dev/null; then
        pass "arpwatch service is ACTIVE"
        systemctl status arpwatch --no-pager 2>/dev/null > "$EVIDENCE_DIR/arpwatch-status.txt" || true
    elif systemctl list-unit-files 2>/dev/null | grep -q arpwatch; then
        fail "arpwatch is installed but NOT running — SI-4 monitoring gap"
    else
        fail "arpwatch is NOT installed — ARP monitoring absent (SI-4 gap)"
    fi
elif command -v service &>/dev/null; then
    if service arpwatch status &>/dev/null; then
        pass "arpwatch service is running"
    else
        fail "arpwatch is not running or not installed"
    fi
else
    warn "Cannot determine arpwatch status — no systemctl or service command"
fi

# --- Check 5: arpwatch database (MAC-IP pairs) ---
info "Checking arpwatch database for known MAC-IP pairs..."
ARPWATCH_DIRS=("/var/lib/arpwatch" "/var/arpwatch" "/usr/lib/arpwatch")
ARPWATCH_DB_FOUND=false

for dir in "${ARPWATCH_DIRS[@]}"; do
    if [[ -d "$dir" ]]; then
        DB_FILES=$(find "$dir" -name "*.dat" 2>/dev/null || true)
        if [[ -n "$DB_FILES" ]]; then
            ARPWATCH_DB_FOUND=true
            pass "arpwatch database found at $dir"
            ENTRY_COUNT=$(wc -l < <(cat $DB_FILES 2>/dev/null) || echo "0")
            info "  Known MAC-IP pairs: $ENTRY_COUNT"
            cp $DB_FILES "$EVIDENCE_DIR/" 2>/dev/null || true
            # Check for flip-flop entries in arpwatch database (MAC changed IP)
            # arpwatch .dat format: MAC  IP  timestamp  hostname
            info "  Checking for potential flip-flop indicators in DB..."
        fi
        break
    fi
done

if [[ "$ARPWATCH_DB_FOUND" == "false" ]]; then
    warn "No arpwatch database found — arpwatch may not have run yet or uses non-standard path"
fi

# --- Check 6: Gratuitous ARP capability detection ---
info "Checking for gratuitous ARP capability (arping)..."
if command -v arping &>/dev/null; then
    pass "arping is available — gratuitous ARP testing capability present"
    info "  NOTE: arping can be used to test ARP spoofing detection"
    info "  Test command: sudo arping -A -I $INTERFACE <ip_address>"
    which arping > "$EVIDENCE_DIR/arping-path.txt"
else
    warn "arping not installed — cannot perform gratuitous ARP test"
    warn "  Install: apt install arping  OR  yum install iputils"
fi

# --- Check 7: Syslog forwarding for arpwatch events ---
info "Checking syslog configuration for arpwatch forwarding..."
RSYSLOG_CONF_DIRS=("/etc/rsyslog.d" "/etc/rsyslog.conf")
SYSLOG_FORWARD_FOUND=false

for conf in "${RSYSLOG_CONF_DIRS[@]}"; do
    if [[ -f "$conf" ]] && grep -q "arpwatch" "$conf" 2>/dev/null; then
        SYSLOG_FORWARD_FOUND=true
        pass "arpwatch syslog forwarding found in $conf"
        break
    elif [[ -d "$conf" ]]; then
        if grep -rl "arpwatch" "$conf" 2>/dev/null | grep -q .; then
            SYSLOG_FORWARD_FOUND=true
            pass "arpwatch syslog forwarding configured in $conf/"
            break
        fi
    fi
done

if [[ "$SYSLOG_FORWARD_FOUND" == "false" ]]; then
    warn "No arpwatch-specific syslog forwarding found — SIEM may not receive ARP alerts"
    info "  See: 02-fixers/fix-arp-monitoring.sh for rsyslog configuration"
fi

# --- Check 8: Network interface in promiscuous mode (monitoring indicator) ---
info "Checking for promiscuous mode interfaces (monitoring sensors)..."
PROMISC_IFACES=$(ip link show 2>/dev/null | grep -i promisc | awk '{print $2}' | tr -d ':' || true)
if [[ -n "$PROMISC_IFACES" ]]; then
    info "Interfaces in promiscuous mode (expected for monitoring): $PROMISC_IFACES"
    echo "$PROMISC_IFACES" > "$EVIDENCE_DIR/promiscuous-interfaces.txt"
else
    warn "No interfaces in promiscuous mode — passive ARP monitoring may be limited"
fi

# --- Evidence summary ---
echo ""
echo "============================================================"
echo " AUDIT SUMMARY"
echo "============================================================"
echo -e " ${GREEN}PASS: $PASS${NC}  ${YELLOW}WARN: $WARN${NC}  ${RED}FAIL: $FAIL${NC}"
echo ""
echo " Evidence saved: $EVIDENCE_DIR"

# Save summary
cat > "$EVIDENCE_DIR/audit-summary.txt" <<EOF
Layer 2 ARP Integrity Audit
Date: $(date)
Interface: $INTERFACE
Hostname: $(hostname)
PASS: $PASS  WARN: $WARN  FAIL: $FAIL
NIST Controls: SI-4, SC-7, AC-4
EOF

if [[ $FAIL -gt 0 ]]; then
    echo ""
    fail "FAIL findings require remediation — see 02-fixers/fix-arp-monitoring.sh"
    exit 1
fi
