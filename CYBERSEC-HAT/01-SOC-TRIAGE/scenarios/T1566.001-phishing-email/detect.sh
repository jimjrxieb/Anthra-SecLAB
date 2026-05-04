#!/usr/bin/env bash
set -euo pipefail

# T1566.001 Phishing Email — Detect
#
# Searches system and auth logs for indicators of email-based phishing:
# suspicious processes launched from mail clients, recent executable downloads,
# and suspicious scripting engine execution.
#
# ATT&CK: T1566.001 (Spearphishing Attachment)
# NIST:   SI-4, AU-6
#
# USAGE: sudo ./detect.sh

EVIDENCE_DIR="/tmp/T1566-detect-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$EVIDENCE_DIR"

echo "============================================"
echo "T1566.001 Phishing Email — Detection"
echo "============================================"
echo ""

echo "--- Suspicious Script/Executable Downloads (Last 24h) ---"
find /tmp /var/tmp "$HOME" -maxdepth 3 \
    \( -name "*.exe" -o -name "*.vbs" -o -name "*.js" -o -name "*.ps1" -o -name "*.bat" \) \
    -newer /proc/1 2>/dev/null \
    | tee "$EVIDENCE_DIR/suspicious-downloads.txt"

echo ""
echo "--- Recent Base64 Encoded Commands in Bash History ---"
grep -iE "base64|frombase64|encodedcommand|-enc " ~/.bash_history 2>/dev/null \
    | head -20 \
    | tee "$EVIDENCE_DIR/encoded-commands.txt"

echo ""
echo "--- Suspicious Outbound Connections ---"
ss -tnp 2>/dev/null | grep ESTABLISHED | grep -v "127.0.0.1\|::1\|192.168\|10\." \
    | tee "$EVIDENCE_DIR/outbound-connections.txt"

echo ""
echo "--- Recent curl/wget with Suspicious Patterns ---"
grep -r "curl\|wget" /var/log/syslog /var/log/auth.log 2>/dev/null \
    | grep -iE "base64|execute|payload|shell" \
    | tail -20 \
    | tee "$EVIDENCE_DIR/suspicious-downloads-log.txt"

echo ""
echo "--- New Processes Spawned in Last Hour ---"
ps -eo pid,ppid,user,lstart,cmd --sort=lstart 2>/dev/null \
    | tail -30 \
    | tee "$EVIDENCE_DIR/recent-processes.txt"

echo ""
echo "Evidence saved to: $EVIDENCE_DIR"
echo "Review findings and compare against known-good baseline."
