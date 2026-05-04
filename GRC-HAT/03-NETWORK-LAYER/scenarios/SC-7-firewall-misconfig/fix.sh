#!/usr/bin/env bash
set -euo pipefail

# SC-7 Firewall Misconfiguration — Fix
#
# Restricts management port access (SSH 22, RDP 3389) to an admin CIDR block,
# enables connection logging, and adds rate limiting to prevent brute force.
#
# REQUIREMENTS:
#   - Root/sudo privileges
#   - iptables (Linux) or netsh (Windows)
#
# USAGE:
#   sudo ./fix.sh <admin_cidr>
#
# EXAMPLE:
#   sudo ./fix.sh 10.0.100.0/24
#   (Restricts SSH and RDP to 10.0.100.0/24 admin subnet only)
#
# WARNING: Ensure you are connecting FROM the admin CIDR before running.
#          Locking yourself out requires console access to recover.
#
# CSF 2.0: PR.PS-01 (Configuration management applied)
# CIS v8: 4.4 (Implement Firewall on Servers)
# NIST: SC-7 (Boundary Protection)
#

# --- Argument Validation ---

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <admin_cidr>"
    echo "Example: $0 10.0.100.0/24"
    echo ""
    echo "admin_cidr: The CIDR block allowed to access management ports."
    echo "            This should be your admin/jump-box subnet."
    echo ""
    echo "[!] WARNING: Make sure your current IP is within the admin CIDR"
    echo "             or you will lose remote access."
    exit 1
fi

ADMIN_CIDR="$1"

# Verify running as root
if [[ $EUID -ne 0 ]]; then
    echo "[ERROR] This script must be run as root (sudo)."
    exit 1
fi

# Basic CIDR validation
if ! echo "$ADMIN_CIDR" | grep -qP '^\d+\.\d+\.\d+\.\d+/\d+$'; then
    echo "[ERROR] Invalid CIDR format: $ADMIN_CIDR"
    echo "Expected format: 10.0.100.0/24"
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
    exit 1
fi

EVIDENCE_DIR="/tmp/sc7-firewall-fix-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$EVIDENCE_DIR"

echo "============================================"
echo "SC-7 Firewall Misconfiguration — Fix"
echo "============================================"
echo ""
echo "[*] Platform:    $PLATFORM"
echo "[*] Admin CIDR:  $ADMIN_CIDR"
echo "[*] Evidence dir: $EVIDENCE_DIR"
echo ""

# --- Record Pre-Fix State ---

echo "[*] Recording pre-fix firewall state..."
if [[ "$PLATFORM" == "linux" ]]; then
    iptables -L -n -v --line-numbers > "$EVIDENCE_DIR/iptables-before-fix.txt" 2>&1
else
    netsh advfirewall firewall show rule name=all > "$EVIDENCE_DIR/firewall-before-fix.txt" 2>&1
fi
echo "[+] Pre-fix state saved."
echo ""

# --- Apply Fix ---

if [[ "$PLATFORM" == "linux" ]]; then

    # Step 1: Remove overpermissive break rules
    echo "[*] Step 1: Removing overpermissive rules (SC7-BREAK markers)..."
    # Remove rules with our break comment markers
    while iptables -L INPUT -n --line-numbers 2>/dev/null | grep -q "SC7-BREAK"; do
        LINE_NUM=$(iptables -L INPUT -n --line-numbers 2>/dev/null | grep "SC7-BREAK" | head -1 | awk '{print $1}')
        iptables -D INPUT "$LINE_NUM"
        echo "[+] Removed rule at line $LINE_NUM"
    done

    # Also remove any other 0.0.0.0/0 rules on management ports
    while iptables -L INPUT -n --line-numbers 2>/dev/null | grep "0\.0\.0\.0/0" | grep -q "dpt:22"; do
        LINE_NUM=$(iptables -L INPUT -n --line-numbers 2>/dev/null | grep "0\.0\.0\.0/0" | grep "dpt:22" | head -1 | awk '{print $1}')
        iptables -D INPUT "$LINE_NUM"
        echo "[+] Removed 0.0.0.0/0 SSH rule at line $LINE_NUM"
    done

    while iptables -L INPUT -n --line-numbers 2>/dev/null | grep "0\.0\.0\.0/0" | grep -q "dpt:3389"; do
        LINE_NUM=$(iptables -L INPUT -n --line-numbers 2>/dev/null | grep "0\.0\.0\.0/0" | grep "dpt:3389" | head -1 | awk '{print $1}')
        iptables -D INPUT "$LINE_NUM"
        echo "[+] Removed 0.0.0.0/0 RDP rule at line $LINE_NUM"
    done
    echo ""

    # Step 2: Add logging rules (before accept rules so all attempts are logged)
    echo "[*] Step 2: Adding connection logging for management ports..."
    iptables -A INPUT -p tcp --dport 22 -j LOG \
        --log-prefix "SSH-ACCESS: " --log-level 4 \
        -m comment --comment "SC7-FIX: Log SSH attempts"
    iptables -A INPUT -p tcp --dport 3389 -j LOG \
        --log-prefix "RDP-ACCESS: " --log-level 4 \
        -m comment --comment "SC7-FIX: Log RDP attempts"
    echo "[+] Logging enabled for SSH and RDP connections"
    echo ""

    # Step 3: Add rate limiting to prevent brute force
    echo "[*] Step 3: Adding rate limiting (5 new connections per minute)..."
    iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW \
        -m hashlimit --hashlimit-above 5/min --hashlimit-burst 5 \
        --hashlimit-mode srcip --hashlimit-name ssh-limit \
        -j DROP -m comment --comment "SC7-FIX: SSH rate limit"
    iptables -A INPUT -p tcp --dport 3389 -m conntrack --ctstate NEW \
        -m hashlimit --hashlimit-above 5/min --hashlimit-burst 5 \
        --hashlimit-mode srcip --hashlimit-name rdp-limit \
        -j DROP -m comment --comment "SC7-FIX: RDP rate limit"
    echo "[+] Rate limiting active: max 5 new connections/min per source IP"
    echo ""

    # Step 4: Allow management ports ONLY from admin CIDR
    echo "[*] Step 4: Allowing management ports from $ADMIN_CIDR only..."
    iptables -A INPUT -p tcp --dport 22 -s "$ADMIN_CIDR" -j ACCEPT \
        -m comment --comment "SC7-FIX: SSH from admin CIDR"
    iptables -A INPUT -p tcp --dport 3389 -s "$ADMIN_CIDR" -j ACCEPT \
        -m comment --comment "SC7-FIX: RDP from admin CIDR"
    echo "[+] SSH (22) — allowed from $ADMIN_CIDR only"
    echo "[+] RDP (3389) — allowed from $ADMIN_CIDR only"
    echo ""

    # Step 5: Explicitly drop management ports from all other sources
    echo "[*] Step 5: Dropping management ports from all other sources..."
    iptables -A INPUT -p tcp --dport 22 -j DROP \
        -m comment --comment "SC7-FIX: SSH deny all others"
    iptables -A INPUT -p tcp --dport 3389 -j DROP \
        -m comment --comment "SC7-FIX: RDP deny all others"
    echo "[+] All non-admin SSH and RDP connections will be dropped"
    echo ""

    # Step 6: Set default INPUT policy to DROP if it is ACCEPT
    INPUT_POLICY=$(iptables -L INPUT -n 2>/dev/null | head -1 | grep -oP '\(policy \K[A-Z]+' || echo "UNKNOWN")
    if [[ "$INPUT_POLICY" == "ACCEPT" ]]; then
        echo "[*] Step 6: Default INPUT policy is ACCEPT — changing to DROP..."
        echo "[!] WARNING: Ensure you have ACCEPT rules for established connections"
        # Add established/related rule first to prevent lockout
        iptables -I INPUT 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT \
            -m comment --comment "SC7-FIX: Allow established connections"
        iptables -P INPUT DROP
        echo "[+] Default INPUT policy set to DROP"
    else
        echo "[*] Step 6: Default INPUT policy is already $INPUT_POLICY — no change needed"
    fi
    echo ""

    # Record post-fix state
    echo "[*] Post-fix iptables rules:"
    iptables -L INPUT -n -v --line-numbers | tee "$EVIDENCE_DIR/iptables-after-fix.txt"

else
    # Windows Firewall — netsh commands

    # Step 1: Remove break rules
    echo "[*] Step 1: Removing overpermissive rules..."
    netsh advfirewall firewall delete rule name="SC7-BREAK: SSH Open to World" 2>/dev/null || true
    netsh advfirewall firewall delete rule name="SC7-BREAK: RDP Open to World" 2>/dev/null || true
    echo "[+] Removed SC7-BREAK rules"
    echo ""

    # Step 2: Enable firewall logging
    echo "[*] Step 2: Enabling firewall logging..."
    netsh advfirewall set allprofiles logging droppedconnections enable
    netsh advfirewall set allprofiles logging allowedconnections enable
    netsh advfirewall set allprofiles logging filename "%systemroot%\system32\LogFiles\Firewall\pfirewall.log"
    netsh advfirewall set allprofiles logging maxfilesize 32676
    echo "[+] Firewall logging enabled for dropped and allowed connections"
    echo ""

    # Step 3: Add restricted rules for admin CIDR only
    echo "[*] Step 3: Adding restricted management port rules..."
    netsh advfirewall firewall add rule name="SC7-FIX: SSH from Admin CIDR" \
        dir=in action=allow protocol=tcp localport=22 \
        remoteip="$ADMIN_CIDR" enable=yes

    netsh advfirewall firewall add rule name="SC7-FIX: RDP from Admin CIDR" \
        dir=in action=allow protocol=tcp localport=3389 \
        remoteip="$ADMIN_CIDR" enable=yes
    echo "[+] SSH (22) — allowed from $ADMIN_CIDR only"
    echo "[+] RDP (3389) — allowed from $ADMIN_CIDR only"
    echo ""

    # Step 4: Add explicit deny rules for management ports from all other sources
    echo "[*] Step 4: Blocking management ports from all other sources..."
    netsh advfirewall firewall add rule name="SC7-FIX: SSH Deny All Others" \
        dir=in action=block protocol=tcp localport=22 \
        remoteip=any enable=yes

    netsh advfirewall firewall add rule name="SC7-FIX: RDP Deny All Others" \
        dir=in action=block protocol=tcp localport=3389 \
        remoteip=any enable=yes
    echo "[+] Management ports blocked from non-admin sources"
    echo ""

    # Record post-fix state
    echo "[*] Post-fix firewall rules:"
    netsh advfirewall firewall show rule name=all dir=in | \
        grep -B 2 -A 8 "SC7-FIX" | tee "$EVIDENCE_DIR/firewall-after-fix.txt"
fi

echo ""
echo "============================================"
echo "Fix Summary"
echo "============================================"
echo ""
echo "[+] Overpermissive rules removed"
echo "[+] Management ports restricted to: $ADMIN_CIDR"
echo "[+] Connection logging enabled"
echo "[+] Rate limiting active (Linux) / deny rules in place (Windows)"
echo ""
echo "[*] Run validate.sh to confirm the fix is effective."
echo "[*] Evidence saved to: $EVIDENCE_DIR"
