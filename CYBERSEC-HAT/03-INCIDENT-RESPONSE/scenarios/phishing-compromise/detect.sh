#!/usr/bin/env bash
set -euo pipefail

# Phishing Compromise — Detect (Active Compromise)
#
# Detects indicators of an active phishing-based compromise:
# new persistence, credential abuse, and outbound connections.
# Run when a user has confirmed they clicked a phishing link/attachment.
#
# ATT&CK: T1566 (Phishing), T1078 (Valid Accounts)
# NIST:   IR-4, IR-5
#
# USAGE: ./detect.sh

EVIDENCE_DIR="/tmp/phish-compromise-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$EVIDENCE_DIR"

echo "============================================"
echo "Phishing Compromise — Active Detection"
echo "============================================"
echo ""

echo "--- New User Accounts Created (Last 7 Days) ---"
grep "useradd\|adduser\|new user" /var/log/auth.log 2>/dev/null \
    | tail -20 \
    | tee "$EVIDENCE_DIR/new-accounts.txt"

echo ""
echo "--- New SSH Authorized Keys ---"
find /home /root -name "authorized_keys" -newer /proc/1 -ls 2>/dev/null \
    | tee "$EVIDENCE_DIR/new-ssh-keys.txt"

echo ""
echo "--- New Cron Jobs / Persistence ---"
find /etc/cron* /var/spool/cron/ -newer /proc/1 -ls 2>/dev/null \
    | tee "$EVIDENCE_DIR/new-cron-jobs.txt"

echo ""
echo "--- Successful Logins After Phishing Window ---"
echo "(Review timestamps relative to when user clicked)"
grep "Accepted" /var/log/auth.log 2>/dev/null \
    | tail -30 \
    | tee "$EVIDENCE_DIR/successful-logins.txt"

echo ""
echo "--- Active Outbound Connections ---"
ss -tnp 2>/dev/null \
    | grep ESTABLISHED \
    | grep -v "127.0.0.1\|::1\|192.168\|10\.\|172\.1[6-9]\.\|172\.2[0-9]\.\|172\.3[0-1]\." \
    | tee "$EVIDENCE_DIR/outbound-connections.txt"

echo ""
echo "--- Recent Files in Sensitive Locations ---"
find /tmp /var/tmp /dev/shm "$HOME" -maxdepth 3 \
    \( -name "*.sh" -o -name "*.py" -o -name "*.exe" -o -name "*.vbs" \) \
    -newer /proc/1 2>/dev/null \
    | tee "$EVIDENCE_DIR/suspicious-files.txt"

echo ""
echo "--- Recent Sudo Usage ---"
grep "sudo:" /var/log/auth.log 2>/dev/null \
    | grep -v "pam_unix\|session opened\|session closed" \
    | tail -20 \
    | tee "$EVIDENCE_DIR/sudo-usage.txt"

echo ""
echo "Evidence saved to: $EVIDENCE_DIR"
