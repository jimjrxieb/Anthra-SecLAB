#!/usr/bin/env bash
set -euo pipefail

# T1021.001 RDP / Remote Services Lateral Movement — Hunt
#
# Hunts for lateral movement via remote services: SSH, RDP (xrdp on Linux),
# internal authentication spikes, and new internal connection pairs.
#
# ATT&CK: T1021.001 (Remote Services: RDP), T1021.004 (SSH)
# NIST:   SI-4, CA-7, AC-17
#
# USAGE: ./detect.sh

EVIDENCE_DIR="/tmp/T1021-hunt-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$EVIDENCE_DIR"

echo "============================================"
echo "T1021.001 Lateral Movement — Hunt"
echo "============================================"
echo ""

echo "--- Internal SSH Lateral Movement Indicators ---"
echo "(successful logins from RFC1918 addresses)"
grep "Accepted" /var/log/auth.log 2>/dev/null \
    | grep -E "from 10\.|from 172\.1[6-9]\.|from 172\.2[0-9]\.|from 172\.3[0-1]\.|from 192\.168\." \
    | awk '{print $1, $2, $3, "user="$9, "from="$11}' \
    | tee "$EVIDENCE_DIR/internal-ssh-logins.txt"

echo ""
echo "--- Unique Internal Source-Destination Pairs (Last 30 days) ---"
grep "Accepted" /var/log/auth.log 2>/dev/null \
    | awk '{print $9, $11}' \
    | grep -E " 10\.|172\.1[6-9]\.|192\.168\." \
    | sort -u \
    | tee "$EVIDENCE_DIR/internal-login-pairs.txt"

echo ""
echo "--- Off-Hours Internal Logins ---"
grep "Accepted" /var/log/auth.log 2>/dev/null \
    | grep -E "from 10\.|from 192\.168\." \
    | awk '{
        split($3, t, ":");
        hour = t[1] + 0;
        if (hour < 6 || hour > 22)
            print "[OFF-HOURS] " $0
    }' \
    | tee "$EVIDENCE_DIR/off-hours-internal.txt"

echo ""
echo "--- Active Remote Sessions ---"
who -a 2>/dev/null | tee "$EVIDENCE_DIR/active-sessions.txt"
echo ""
w 2>/dev/null | tee -a "$EVIDENCE_DIR/active-sessions.txt"

echo ""
echo "--- RDP / xrdp Connections (if applicable) ---"
grep -i "xrdp\|sesman" /var/log/syslog /var/log/auth.log 2>/dev/null \
    | tail -20 \
    | tee "$EVIDENCE_DIR/rdp-events.txt"

echo ""
echo "--- Listening Remote Access Services ---"
ss -tlnp 2>/dev/null \
    | grep -E ":22|:3389|:5985|:5986|:23|:3388|:4899" \
    | tee "$EVIDENCE_DIR/remote-services-listening.txt"

echo ""
echo "--- New Internal Connections in Last Session ---"
ss -tnp 2>/dev/null \
    | grep ESTABLISHED \
    | grep -E "10\.|172\.1[6-9]\.|192\.168\." \
    | tee "$EVIDENCE_DIR/active-internal-connections.txt"

echo ""
echo "Evidence saved to: $EVIDENCE_DIR"
