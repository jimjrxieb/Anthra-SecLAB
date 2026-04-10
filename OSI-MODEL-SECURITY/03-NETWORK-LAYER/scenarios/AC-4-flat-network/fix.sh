#!/usr/bin/env bash
set -euo pipefail

# AC-4 Flat Network — Fix
#
# Implements subnet segmentation by adding firewall rules between network zones.
# Creates a zone-based firewall with explicit rules for allowed cross-zone traffic
# and default deny for everything else.
#
# Zone model (customizable):
#   - MGMT zone:   Admin/management subnet (jump boxes, bastion hosts)
#   - APP zone:    Application servers (web, API, middleware)
#   - DATA zone:   Database and storage servers
#   - USER zone:   End-user workstations
#
# REQUIREMENTS:
#   - Root/sudo privileges
#   - iptables (Linux)
#   - Host must be the gateway/router between subnets
#
# USAGE:
#   sudo ./fix.sh <mgmt_cidr> <app_cidr> <data_cidr> <user_cidr>
#
# EXAMPLE:
#   sudo ./fix.sh 10.0.100.0/24 10.0.10.0/24 10.0.20.0/24 10.0.30.0/24

# --- Argument Validation ---

if [[ $# -lt 4 ]]; then
    echo "Usage: $0 <mgmt_cidr> <app_cidr> <data_cidr> <user_cidr>"
    echo ""
    echo "Example: $0 10.0.100.0/24 10.0.10.0/24 10.0.20.0/24 10.0.30.0/24"
    echo ""
    echo "Zone mapping:"
    echo "  mgmt_cidr  — Management subnet (SSH, RDP, admin access)"
    echo "  app_cidr   — Application servers (web, API)"
    echo "  data_cidr  — Database and storage servers"
    echo "  user_cidr  — End-user workstations"
    exit 1
fi

MGMT_CIDR="$1"
APP_CIDR="$2"
DATA_CIDR="$3"
USER_CIDR="$4"

# Verify running as root
if [[ $EUID -ne 0 ]]; then
    echo "[ERROR] This script must be run as root (sudo)."
    exit 1
fi

if ! command -v iptables &>/dev/null; then
    echo "[ERROR] iptables not found."
    exit 1
fi

EVIDENCE_DIR="/tmp/ac4-flat-fix-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$EVIDENCE_DIR"

echo "============================================"
echo "AC-4 Flat Network — Fix (Segmentation)"
echo "============================================"
echo ""
echo "[*] Zone mapping:"
echo "    MGMT: $MGMT_CIDR"
echo "    APP:  $APP_CIDR"
echo "    DATA: $DATA_CIDR"
echo "    USER: $USER_CIDR"
echo "[*] Evidence dir: $EVIDENCE_DIR"
echo ""

# --- Record Pre-Fix State ---

echo "[*] Recording pre-fix state..."
iptables-save > "$EVIDENCE_DIR/iptables-before-fix.txt"
iptables -L FORWARD -n -v --line-numbers > "$EVIDENCE_DIR/forward-before-fix.txt" 2>&1
echo "[+] Pre-fix state saved."
echo ""

# --- Step 1: Flush FORWARD chain ---

echo "[*] Step 1: Flushing FORWARD chain (clean slate)..."
iptables -F FORWARD
echo "[+] FORWARD chain flushed."
echo ""

# --- Step 2: Allow established/related connections ---

echo "[*] Step 2: Allowing established and related connections..."
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT \
    -m comment --comment "AC4-FIX: Allow established connections"
echo "[+] Established/related connections allowed."
echo ""

# --- Step 3: Enable logging for denied traffic ---

echo "[*] Step 3: Adding logging for denied cross-zone traffic..."
# Log before the final DROP so we capture what is being blocked
# (added at the end, before default DROP)
echo "[+] Logging rules will be added before the default deny."
echo ""

# --- Step 4: Define allowed cross-zone traffic ---

echo "[*] Step 4: Adding segmentation rules (zone-to-zone policy)..."
echo ""

# MGMT -> ALL: Management can reach all zones (for administration)
echo "  [*] MGMT -> APP: Allow SSH, HTTP, HTTPS (admin access)"
iptables -A FORWARD -s "$MGMT_CIDR" -d "$APP_CIDR" -p tcp -m multiport --dports 22,80,443,8080,8443 -j ACCEPT \
    -m comment --comment "AC4-FIX: MGMT->APP admin"
echo "  [*] MGMT -> DATA: Allow SSH, DB ports (admin access)"
iptables -A FORWARD -s "$MGMT_CIDR" -d "$DATA_CIDR" -p tcp -m multiport --dports 22,3306,5432,1433,6379,27017 -j ACCEPT \
    -m comment --comment "AC4-FIX: MGMT->DATA admin"
echo "  [*] MGMT -> USER: Allow SSH, RDP (desktop support)"
iptables -A FORWARD -s "$MGMT_CIDR" -d "$USER_CIDR" -p tcp -m multiport --dports 22,3389 -j ACCEPT \
    -m comment --comment "AC4-FIX: MGMT->USER admin"
echo "  [+] MGMT zone rules applied."
echo ""

# APP -> DATA: Application servers can query databases
echo "  [*] APP -> DATA: Allow database ports only"
iptables -A FORWARD -s "$APP_CIDR" -d "$DATA_CIDR" -p tcp -m multiport --dports 3306,5432,1433,6379,27017 -j ACCEPT \
    -m comment --comment "AC4-FIX: APP->DATA db access"
echo "  [+] APP->DATA rules applied."
echo ""

# USER -> APP: Users can access application services
echo "  [*] USER -> APP: Allow HTTP, HTTPS only"
iptables -A FORWARD -s "$USER_CIDR" -d "$APP_CIDR" -p tcp -m multiport --dports 80,443,8080,8443 -j ACCEPT \
    -m comment --comment "AC4-FIX: USER->APP web access"
echo "  [+] USER->APP rules applied."
echo ""

# Allow ICMP for network diagnostics (limited)
echo "  [*] ALL zones: Allow ICMP echo (ping) for diagnostics"
iptables -A FORWARD -p icmp --icmp-type echo-request -j ACCEPT \
    -m comment --comment "AC4-FIX: Allow ping for diagnostics"
iptables -A FORWARD -p icmp --icmp-type echo-reply -j ACCEPT \
    -m comment --comment "AC4-FIX: Allow ping replies"
echo "  [+] ICMP rules applied."
echo ""

# Allow DNS from all zones to DNS servers (usually in MGMT or DATA)
echo "  [*] ALL zones: Allow DNS (UDP/TCP 53)"
iptables -A FORWARD -p udp --dport 53 -j ACCEPT \
    -m comment --comment "AC4-FIX: Allow DNS queries"
iptables -A FORWARD -p tcp --dport 53 -j ACCEPT \
    -m comment --comment "AC4-FIX: Allow DNS queries (TCP)"
echo "  [+] DNS rules applied."
echo ""

# --- Step 5: Log and deny everything else ---

echo "[*] Step 5: Adding logging and default deny..."

# Log denied traffic for forensics and tuning
iptables -A FORWARD -j LOG --log-prefix "AC4-DENIED: " --log-level 4 \
    -m comment --comment "AC4-FIX: Log denied cross-zone traffic"

# Default deny — block all other cross-subnet traffic
iptables -A FORWARD -j DROP \
    -m comment --comment "AC4-FIX: Default deny cross-zone"

echo "[+] Default deny with logging applied."
echo ""

# --- Step 6: Set FORWARD policy to DROP ---

echo "[*] Step 6: Setting FORWARD chain default policy to DROP..."
iptables -P FORWARD DROP
echo "[+] FORWARD policy set to DROP."
echo ""

# --- Post-Fix State ---

echo "[*] Post-fix FORWARD chain rules:"
iptables -L FORWARD -n -v --line-numbers | tee "$EVIDENCE_DIR/forward-after-fix.txt"
echo ""

# Save the complete ruleset for documentation
iptables-save > "$EVIDENCE_DIR/iptables-after-fix.txt"

echo "============================================"
echo "Fix Summary"
echo "============================================"
echo ""
echo "[+] Network segmentation implemented:"
echo "    MGMT ($MGMT_CIDR) -> can administer all zones"
echo "    APP  ($APP_CIDR)  -> can query DATA zone databases only"
echo "    USER ($USER_CIDR) -> can access APP zone web services only"
echo "    DATA ($DATA_CIDR) -> accepts connections only, does not initiate"
echo ""
echo "[+] Default deny: all cross-zone traffic not explicitly allowed is dropped and logged"
echo "[+] Logging: denied traffic logged with 'AC4-DENIED:' prefix for SIEM"
echo ""
echo "[*] Blocked paths (examples):"
echo "    USER -> DATA: BLOCKED (users cannot directly access databases)"
echo "    APP  -> USER: BLOCKED (app servers have no reason to reach workstations)"
echo "    DATA -> APP:  BLOCKED (databases respond via established connections only)"
echo "    DATA -> MGMT: BLOCKED (databases cannot reach management)"
echo ""
echo "[*] Run validate.sh to confirm segmentation is working."
echo "[*] Evidence saved to: $EVIDENCE_DIR"
