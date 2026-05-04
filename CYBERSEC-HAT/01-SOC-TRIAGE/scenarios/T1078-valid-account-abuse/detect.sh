#!/usr/bin/env bash
set -euo pipefail

# T1078 Valid Account Abuse — Detect
#
# Looks for impossible travel indicators, off-hours logins, and
# suspicious authentication patterns that suggest account compromise.
#
# ATT&CK: T1078 (Valid Accounts)
# NIST:   SI-4, AU-6, IA-4
#
# USAGE: ./detect.sh

EVIDENCE_DIR="/tmp/T1078-detect-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$EVIDENCE_DIR"

echo "============================================"
echo "T1078 Valid Account Abuse — Detection"
echo "============================================"
echo ""

echo "--- Recent Successful Logins ---"
grep "Accepted" /var/log/auth.log 2>/dev/null \
    | awk '{print $1, $2, $3, "user="$9, "from="$11}' \
    | tail -30 \
    | tee "$EVIDENCE_DIR/successful-logins.txt"

echo ""
echo "--- Off-Hours Login Activity (before 6am or after 10pm) ---"
grep "Accepted" /var/log/auth.log 2>/dev/null \
    | awk '{
        split($3, t, ":");
        hour = t[1] + 0;
        if (hour < 6 || hour > 22)
            print "[OFF-HOURS] " $1, $2, $3, "user=" $9, "from=" $11
    }' \
    | tee "$EVIDENCE_DIR/off-hours-logins.txt"

OFF_HOURS_COUNT=$(wc -l < "$EVIDENCE_DIR/off-hours-logins.txt")
if [ "$OFF_HOURS_COUNT" -gt 0 ]; then
    echo "[!] $OFF_HOURS_COUNT off-hours login events detected"
fi

echo ""
echo "--- Multiple Source IPs for Same User ---"
grep "Accepted" /var/log/auth.log 2>/dev/null \
    | awk '{print $9, $11}' \
    | sort | uniq \
    | awk '{users[$1]++; ips[$1]=ips[$1]" "$2} END {for (u in users) if (users[u]>1) print u, "logged in from", users[u], "IPs:", ips[u]}' \
    | tee "$EVIDENCE_DIR/multi-ip-users.txt"

echo ""
echo "--- Currently Logged-In Users ---"
who -a 2>/dev/null | tee "$EVIDENCE_DIR/current-sessions.txt"

echo ""
echo "--- Recent Login History ---"
last -n 30 2>/dev/null | tee "$EVIDENCE_DIR/login-history.txt"

echo ""
echo "--- Privileged Account Activity (sudo) ---"
grep "sudo:" /var/log/auth.log 2>/dev/null \
    | grep -v "pam_unix" \
    | tail -20 \
    | tee "$EVIDENCE_DIR/sudo-activity.txt"

echo ""
echo "Evidence saved to: $EVIDENCE_DIR"
