#!/usr/bin/env bash
set -euo pipefail

# Exposed Management Ports — Detect
#
# Identifies management services (SSH, RDP, WinRM, Telnet, VNC) listening
# on 0.0.0.0 with no source IP restriction. These are the most commonly
# exploited entry points in ransomware attacks.
#
# ATT&CK: T1190 (Exploit Public-Facing Application), T1021 (Remote Services)
# NIST:   SC-7, CM-7
#
# USAGE: ./detect.sh

EVIDENCE_DIR="/tmp/mgmt-ports-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$EVIDENCE_DIR"

echo "============================================"
echo "Exposed Management Ports — Detection"
echo "============================================"
echo ""

MGMT_PORTS="22 23 3389 5985 5986 5900 5901 4899 2222 8022"

echo "--- Listening Management Ports ---"
for port in $MGMT_PORTS; do
    result=$(ss -tlnp 2>/dev/null | grep ":${port} " || true)
    if [ -n "$result" ]; then
        if echo "$result" | grep -q "0.0.0.0\|:::"; then
            echo "[EXPOSED] Port $port listening on all interfaces:"
            echo "$result"
            echo "PORT=$port STATUS=EXPOSED DETAIL=$result" >> "$EVIDENCE_DIR/exposed-ports.txt"
        else
            echo "[RESTRICTED] Port $port listening (restricted to specific IP)"
            echo "$result"
        fi
    fi
done

echo ""
echo "--- All Listening Services (Non-Loopback) ---"
ss -tlnp 2>/dev/null \
    | grep -v "127.0.0.1\|::1\|*:*" \
    | tee "$EVIDENCE_DIR/all-listening-services.txt"

echo ""
echo "--- Firewall Rules on Management Ports ---"
if command -v iptables &>/dev/null; then
    echo "[iptables]"
    iptables -L INPUT -n -v 2>/dev/null \
        | grep -E "22|3389|5985|5986|23" \
        | tee "$EVIDENCE_DIR/firewall-rules.txt"
fi

if command -v ufw &>/dev/null; then
    echo "[ufw status]"
    ufw status verbose 2>/dev/null \
        | grep -E "22|3389|5985|5986|23|Status" \
        | tee -a "$EVIDENCE_DIR/firewall-rules.txt"
fi

echo ""
echo "--- SSH Hardening Configuration ---"
if [ -f /etc/ssh/sshd_config ]; then
    grep -E "^PermitRootLogin|^PasswordAuthentication|^MaxAuthTries|^AllowUsers|^AllowGroups|^ListenAddress|^Port|^LoginGraceTime" \
        /etc/ssh/sshd_config 2>/dev/null \
        | tee "$EVIDENCE_DIR/ssh-config.txt"
fi

echo ""
echo "--- Telnet Check (Should Never Be Running) ---"
if ss -tlnp 2>/dev/null | grep ":23 "; then
    echo "[CRITICAL] Telnet is running — disable immediately"
else
    echo "[PASS] Telnet not detected"
fi

echo ""
echo "Evidence saved to: $EVIDENCE_DIR"

# Summary
EXPOSED_COUNT=$(wc -l < "$EVIDENCE_DIR/exposed-ports.txt" 2>/dev/null || echo 0)
if [ "$EXPOSED_COUNT" -gt 0 ]; then
    echo ""
    echo "[!] $EXPOSED_COUNT management port(s) exposed to 0.0.0.0"
    echo "[!] These are the top ransomware entry vectors — remediate immediately"
fi
