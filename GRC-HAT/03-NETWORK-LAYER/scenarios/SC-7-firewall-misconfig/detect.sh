#!/usr/bin/env bash
set -euo pipefail

# SC-7 Firewall Misconfiguration — Detect
#
# Detects overly permissive firewall rules on management ports using:
#   1. Nmap scan against the target to confirm open ports
#   2. Local firewall rule audit for 0.0.0.0/0 source entries
#   3. Connection logging state check
#
# REQUIREMENTS:
#   - nmap (apt-get install nmap)
#   - Root/sudo privileges for firewall rule inspection
#
# USAGE:
#   sudo ./detect.sh <target_ip> [scan_source_ip]
#
# EXAMPLE:
#   sudo ./detect.sh 10.0.1.50
#   sudo ./detect.sh 10.0.1.50 203.0.113.100
#   (Scans target for open management ports)
#
# CSF 2.0: DE.CM-01 (Networks monitored)
# CIS v8: 4.4 (Implement Firewall on Servers)
# NIST: SC-7 (Boundary Protection)
#

# --- Argument Validation ---

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <target_ip> [scan_source_ip]"
    echo "Example: $0 10.0.1.50"
    echo ""
    echo "target_ip:      IP address to scan for open management ports"
    echo "scan_source_ip: Optional source IP to scan from (for remote testing)"
    exit 1
fi

TARGET="$1"
SOURCE="${2:-}"

# Verify running as root
if [[ $EUID -ne 0 ]]; then
    echo "[ERROR] This script must be run as root (sudo)."
    exit 1
fi

EVIDENCE_DIR="/tmp/sc7-firewall-detect-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$EVIDENCE_DIR"

echo "============================================"
echo "SC-7 Firewall Misconfiguration — Detection"
echo "============================================"
echo ""
echo "[*] Target:       $TARGET"
echo "[*] Source:        ${SOURCE:-localhost}"
echo "[*] Evidence dir: $EVIDENCE_DIR"
echo ""

# --- Method 1: Nmap Port Scan ---

echo "[*] Method 1: Nmap scan for management ports"
echo "----------------------------------------------"

if command -v nmap &>/dev/null; then
    NMAP_OUTPUT="$EVIDENCE_DIR/nmap-management-ports.txt"

    echo "[*] Scanning SSH (22), RDP (3389), Telnet (23), VNC (5900-5901)..."
    echo ""

    # Scan management ports — SYN scan for accuracy
    nmap -sS -Pn -p 22,23,3389,5900,5901 -T4 \
        --reason -oN "$NMAP_OUTPUT" "$TARGET" 2>&1 | tee "$EVIDENCE_DIR/nmap-stdout.txt"
    echo ""

    # Parse results for open ports
    OPEN_PORTS=$(grep "^[0-9]" "$NMAP_OUTPUT" 2>/dev/null | grep "open" || true)
    if [[ -n "$OPEN_PORTS" ]]; then
        echo "[ALERT] Open management ports detected!"
        echo "$OPEN_PORTS" | tee "$EVIDENCE_DIR/open-management-ports.txt"
        echo ""

        # Check if SSH is open
        if echo "$OPEN_PORTS" | grep -q "22/tcp.*open"; then
            echo "[ALERT] SSH (port 22) is OPEN — primary brute-force target"
        fi

        # Check if RDP is open
        if echo "$OPEN_PORTS" | grep -q "3389/tcp.*open"; then
            echo "[ALERT] RDP (port 3389) is OPEN — primary ransomware entry vector"
        fi

        # Check if Telnet is open
        if echo "$OPEN_PORTS" | grep -q "23/tcp.*open"; then
            echo "[ALERT] Telnet (port 23) is OPEN — cleartext protocol, critical finding"
        fi
    else
        echo "[OK] No management ports are open on $TARGET."
    fi
    echo ""

    # Full service version detection on open ports
    echo "[*] Running service version detection on open ports..."
    nmap -sV -Pn -p 22,23,3389,5900,5901 -T4 \
        -oN "$EVIDENCE_DIR/nmap-service-versions.txt" "$TARGET" 2>&1 | \
        grep "^[0-9]" | tee -a "$EVIDENCE_DIR/service-versions.txt" || true
    echo ""
else
    echo "[SKIP] nmap not installed. Install with: apt-get install nmap"
fi

# --- Method 2: Local Firewall Rule Audit ---

echo "[*] Method 2: Local firewall rule audit"
echo "----------------------------------------------"

PLATFORM="unknown"
if command -v iptables &>/dev/null; then
    PLATFORM="linux"
elif command -v netsh &>/dev/null || command -v netsh.exe &>/dev/null; then
    PLATFORM="windows"
fi

FINDINGS=0

if [[ "$PLATFORM" == "linux" ]]; then
    echo "[*] Auditing iptables rules for overpermissive entries..."
    echo ""

    # Check for rules allowing 0.0.0.0/0 on management ports
    echo "[*] Rules matching port 22 (SSH):"
    SSH_RULES=$(iptables -L INPUT -n -v --line-numbers 2>/dev/null | grep "dpt:22" || true)
    if [[ -n "$SSH_RULES" ]]; then
        echo "$SSH_RULES" | tee "$EVIDENCE_DIR/ssh-rules.txt"

        # Check if any allow from 0.0.0.0/0
        if echo "$SSH_RULES" | grep -q "0\.0\.0\.0/0.*ACCEPT"; then
            echo "[ALERT] SSH allows inbound from 0.0.0.0/0 — unrestricted access!"
            FINDINGS=$((FINDINGS + 1))
        fi
    else
        echo "[INFO] No SSH rules found in INPUT chain."
    fi
    echo ""

    echo "[*] Rules matching port 3389 (RDP):"
    RDP_RULES=$(iptables -L INPUT -n -v --line-numbers 2>/dev/null | grep "dpt:3389" || true)
    if [[ -n "$RDP_RULES" ]]; then
        echo "$RDP_RULES" | tee "$EVIDENCE_DIR/rdp-rules.txt"

        if echo "$RDP_RULES" | grep -q "0\.0\.0\.0/0.*ACCEPT"; then
            echo "[ALERT] RDP allows inbound from 0.0.0.0/0 — unrestricted access!"
            FINDINGS=$((FINDINGS + 1))
        fi
    else
        echo "[INFO] No RDP rules found in INPUT chain."
    fi
    echo ""

    # Check for default ACCEPT policy (worst case)
    INPUT_POLICY=$(iptables -L INPUT -n 2>/dev/null | head -1 | grep -oP '\(policy \K[A-Z]+' || echo "UNKNOWN")
    echo "[*] INPUT chain default policy: $INPUT_POLICY"
    if [[ "$INPUT_POLICY" == "ACCEPT" ]]; then
        echo "[ALERT] Default INPUT policy is ACCEPT — all ports are implicitly open!"
        FINDINGS=$((FINDINGS + 1))
    fi
    echo ""

    # Check for logging rules
    echo "[*] Checking for connection logging..."
    LOG_RULES=$(iptables -L INPUT -n 2>/dev/null | grep "LOG" || true)
    if [[ -z "$LOG_RULES" ]]; then
        echo "[ALERT] No logging rules in INPUT chain — connections are not being recorded"
        FINDINGS=$((FINDINGS + 1))
    else
        echo "[OK] Logging rules present:"
        echo "$LOG_RULES"
    fi
    echo ""

    # Check for rate limiting
    echo "[*] Checking for connection rate limiting..."
    LIMIT_RULES=$(iptables -L INPUT -n 2>/dev/null | grep -E "connlimit|limit|hashlimit" || true)
    if [[ -z "$LIMIT_RULES" ]]; then
        echo "[ALERT] No rate limiting rules — brute force attacks are unthrottled"
        FINDINGS=$((FINDINGS + 1))
    else
        echo "[OK] Rate limiting rules present:"
        echo "$LIMIT_RULES"
    fi

elif [[ "$PLATFORM" == "windows" ]]; then
    echo "[*] Auditing Windows Firewall rules for overpermissive entries..."
    echo ""

    # Check for rules allowing any remote IP on management ports
    echo "[*] Inbound rules for port 22 (SSH):"
    netsh advfirewall firewall show rule name=all dir=in | \
        grep -B 2 -A 8 "LocalPort.*22" | tee "$EVIDENCE_DIR/ssh-rules-win.txt" || true

    if grep -q "RemoteIP.*Any" "$EVIDENCE_DIR/ssh-rules-win.txt" 2>/dev/null; then
        echo "[ALERT] SSH allows inbound from Any — unrestricted access!"
        FINDINGS=$((FINDINGS + 1))
    fi
    echo ""

    echo "[*] Inbound rules for port 3389 (RDP):"
    netsh advfirewall firewall show rule name=all dir=in | \
        grep -B 2 -A 8 "LocalPort.*3389" | tee "$EVIDENCE_DIR/rdp-rules-win.txt" || true

    if grep -q "RemoteIP.*Any" "$EVIDENCE_DIR/rdp-rules-win.txt" 2>/dev/null; then
        echo "[ALERT] RDP allows inbound from Any — unrestricted access!"
        FINDINGS=$((FINDINGS + 1))
    fi
    echo ""

    # Check firewall logging status
    echo "[*] Checking firewall logging status..."
    netsh advfirewall show allprofiles logging 2>/dev/null | \
        tee "$EVIDENCE_DIR/firewall-logging.txt" || true
else
    echo "[SKIP] No supported firewall found (iptables or netsh)."
fi
echo ""

# --- Method 3: External Exposure Check ---

echo "[*] Method 3: Checking for cloud security group exposure"
echo "----------------------------------------------"

# AWS security group check (if aws cli available)
if command -v aws &>/dev/null; then
    echo "[*] Checking AWS security groups for 0.0.0.0/0 on management ports..."

    # Find security groups with 0.0.0.0/0 on SSH
    aws ec2 describe-security-groups \
        --filters "Name=ip-permission.from-port,Values=22" \
                  "Name=ip-permission.to-port,Values=22" \
                  "Name=ip-permission.cidr,Values=0.0.0.0/0" \
        --query "SecurityGroups[*].[GroupId,GroupName]" \
        --output text 2>/dev/null | tee "$EVIDENCE_DIR/aws-sg-ssh.txt" || true

    # Find security groups with 0.0.0.0/0 on RDP
    aws ec2 describe-security-groups \
        --filters "Name=ip-permission.from-port,Values=3389" \
                  "Name=ip-permission.to-port,Values=3389" \
                  "Name=ip-permission.cidr,Values=0.0.0.0/0" \
        --query "SecurityGroups[*].[GroupId,GroupName]" \
        --output text 2>/dev/null | tee "$EVIDENCE_DIR/aws-sg-rdp.txt" || true

    if [[ -s "$EVIDENCE_DIR/aws-sg-ssh.txt" ]] || [[ -s "$EVIDENCE_DIR/aws-sg-rdp.txt" ]]; then
        echo "[ALERT] AWS security groups with 0.0.0.0/0 on management ports found!"
        FINDINGS=$((FINDINGS + 1))
    else
        echo "[OK] No AWS security groups expose management ports to 0.0.0.0/0."
    fi
else
    echo "[SKIP] AWS CLI not available — skip cloud security group check."
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
    echo "[ALERT] Overpermissive firewall rules detected!"
    echo "[*] Management ports exposed to 0.0.0.0/0 are the #1 ransomware entry vector."
    echo "[*] Run fix.sh to restrict source IP to admin CIDR and enable logging."
else
    echo "[OK] No overpermissive management port rules detected."
fi

echo ""
echo "[*] Evidence saved to: $EVIDENCE_DIR"
echo "[*] Files:"
ls -la "$EVIDENCE_DIR/"
