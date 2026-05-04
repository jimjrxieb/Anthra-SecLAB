#!/usr/bin/env bash
set -euo pipefail

# T1110 Brute Force / Account Lockout — Detect
#
# Surfaces failed login spikes, high-frequency source IPs,
# and account lockout events that indicate brute force activity.
#
# ATT&CK: T1110 (Brute Force)
# NIST:   SI-4, AU-6, AC-7
#
# USAGE: ./detect.sh

EVIDENCE_DIR="/tmp/T1110-detect-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$EVIDENCE_DIR"
THRESHOLD=10

echo "============================================"
echo "T1110 Brute Force / Lockout — Detection"
echo "============================================"
echo ""

echo "--- Failed Login Count by Source IP (Top 20) ---"
grep "Failed password" /var/log/auth.log 2>/dev/null \
    | awk '{print $11}' \
    | sort | uniq -c | sort -rn \
    | head -20 \
    | tee "$EVIDENCE_DIR/failed-by-ip.txt"

echo ""
echo "--- High-Volume Sources (>$THRESHOLD failures) ---"
grep "Failed password" /var/log/auth.log 2>/dev/null \
    | awk '{print $11}' \
    | sort | uniq -c | sort -rn \
    | awk -v t="$THRESHOLD" '$1 > t {print "[ALERT] " $1 " failures from " $2}' \
    | tee "$EVIDENCE_DIR/high-volume-sources.txt"

HIGH_COUNT=$(wc -l < "$EVIDENCE_DIR/high-volume-sources.txt")
if [ "$HIGH_COUNT" -gt 0 ]; then
    echo "[!] $HIGH_COUNT high-volume sources detected — investigate brute force"
fi

echo ""
echo "--- Targeted Usernames ---"
grep "Failed password" /var/log/auth.log 2>/dev/null \
    | awk '{print $9}' \
    | sort | uniq -c | sort -rn \
    | head -20 \
    | tee "$EVIDENCE_DIR/targeted-users.txt"

echo ""
echo "--- Invalid Usernames (Enumeration Indicator) ---"
grep "Invalid user" /var/log/auth.log 2>/dev/null \
    | awk '{print $8, $10}' \
    | sort | uniq -c | sort -rn \
    | head -20 \
    | tee "$EVIDENCE_DIR/invalid-users.txt"

echo ""
echo "--- Account Lockout Events ---"
grep -iE "account locked|maximum authentication attempts exceeded|too many failures" \
    /var/log/auth.log 2>/dev/null \
    | tee "$EVIDENCE_DIR/lockouts.txt"

echo ""
echo "--- Success After Failures (Spray Success Indicator) ---"
echo "(Manual check: compare successful logins with IPs that had failures)"
echo ""
grep "Accepted" /var/log/auth.log 2>/dev/null | awk '{print $11}' | sort -u > /tmp/success_ips.txt
grep "Failed password" /var/log/auth.log 2>/dev/null | awk '{print $11}' | sort | uniq -c | sort -rn | awk '{print $2}' > /tmp/fail_ips.txt
comm -12 <(sort /tmp/success_ips.txt) <(sort /tmp/fail_ips.txt) \
    | tee "$EVIDENCE_DIR/success-after-fail-ips.txt"
rm -f /tmp/success_ips.txt /tmp/fail_ips.txt

SUCCESS_AFTER_FAIL=$(wc -l < "$EVIDENCE_DIR/success-after-fail-ips.txt")
if [ "$SUCCESS_AFTER_FAIL" -gt 0 ]; then
    echo "[!] $SUCCESS_AFTER_FAIL IPs had both failures and successes — possible spray success"
fi

echo ""
echo "Evidence saved to: $EVIDENCE_DIR"
