#!/usr/bin/env bash
set -euo pipefail

# SOC Triage — Alert Volume Audit
#
# Checks authentication failure volumes, login patterns, and
# indicators of alert fatigue (too many events = noise, too few = blind).
#
# NIST: SI-4, AU-6
#
# USAGE: ./audit-alert-volume.sh [hours_back]

HOURS="${1:-24}"
EVIDENCE_DIR="/tmp/alert-volume-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$EVIDENCE_DIR"

echo "============================================"
echo "Alert Volume Audit — Last ${HOURS} Hours"
echo "============================================"
echo ""

echo "--- Failed Login Attempts by Source IP ---"
echo ""
grep "Failed password" /var/log/auth.log 2>/dev/null \
    | awk '{print $11}' \
    | sort | uniq -c | sort -rn \
    | head -20 \
    | tee "$EVIDENCE_DIR/failed-by-ip.txt"

echo ""
echo "--- Failed Login Attempts by Target User ---"
echo ""
grep "Failed password" /var/log/auth.log 2>/dev/null \
    | awk '{print $9}' \
    | sort | uniq -c | sort -rn \
    | head -20 \
    | tee "$EVIDENCE_DIR/failed-by-user.txt"

echo ""
echo "--- Successful Logins (Last ${HOURS}h) ---"
echo ""
grep "Accepted" /var/log/auth.log 2>/dev/null \
    | awk '{print $1, $2, $3, $9, $11}' \
    | tail -30 \
    | tee "$EVIDENCE_DIR/successful-logins.txt"

echo ""
echo "--- Account Lockouts ---"
echo ""
grep -i "account locked\|too many failures\|maximum authentication attempts" \
    /var/log/auth.log 2>/dev/null \
    | tail -20 \
    | tee "$EVIDENCE_DIR/lockouts.txt"

LOCKOUT_COUNT=$(wc -l < "$EVIDENCE_DIR/lockouts.txt")
if [ "$LOCKOUT_COUNT" -gt 0 ]; then
    echo ""
    echo "[!] $LOCKOUT_COUNT lockout events detected — investigate brute force activity"
fi

echo ""
echo "--- High-Frequency Sources (Potential Scanners) ---"
THRESHOLD=50
echo "(Sources with more than $THRESHOLD failed attempts)"
echo ""
grep "Failed password" /var/log/auth.log 2>/dev/null \
    | awk '{print $11}' \
    | sort | uniq -c | sort -rn \
    | awk -v t="$THRESHOLD" '$1 > t {print "[ALERT] " $1 " failures from " $2}' \
    | tee "$EVIDENCE_DIR/high-frequency-sources.txt"

echo ""
echo "Evidence saved to: $EVIDENCE_DIR"
