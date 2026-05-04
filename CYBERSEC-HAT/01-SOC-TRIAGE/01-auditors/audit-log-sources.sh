#!/usr/bin/env bash
set -euo pipefail

# SOC Triage — Log Source Audit
#
# Verifies key log sources exist, are current, and contain expected content.
# Run this to confirm your environment is generating the right data for triage.
#
# NIST: AU-12 (Audit Record Generation), SI-4 (System Monitoring)
#
# USAGE: ./audit-log-sources.sh

echo "============================================"
echo "Log Source Inventory Audit"
echo "============================================"
echo ""

PASS=0
FAIL=0

check_log() {
    local path="$1"
    local description="$2"
    local max_age_minutes="${3:-60}"

    if [ ! -f "$path" ]; then
        echo "[FAIL] $description — file not found: $path"
        ((FAIL++))
        return
    fi

    AGE_SECS=$(( $(date +%s) - $(stat -c %Y "$path") ))
    AGE_MIN=$(( AGE_SECS / 60 ))

    if [ "$AGE_MIN" -gt "$max_age_minutes" ]; then
        echo "[WARN] $description — last updated ${AGE_MIN}m ago (path: $path)"
    else
        LINES=$(wc -l < "$path" 2>/dev/null || echo 0)
        echo "[PASS] $description — ${LINES} lines, updated ${AGE_MIN}m ago"
        ((PASS++))
    fi
}

echo "--- Core System Logs ---"
check_log "/var/log/auth.log"    "Authentication log (SSH, sudo, PAM)"       60
check_log "/var/log/syslog"      "System log (kernel, daemons)"               10
check_log "/var/log/kern.log"    "Kernel log"                                 60
check_log "/var/log/dpkg.log"    "Package install/remove log"                1440

echo ""
echo "--- Service Logs ---"
check_log "/var/log/apache2/access.log"  "Apache access log"   5  2>/dev/null || true
check_log "/var/log/nginx/access.log"    "Nginx access log"    5  2>/dev/null || true

echo ""
echo "--- Journald Coverage ---"
echo ""
if command -v journalctl &>/dev/null; then
    JOURNAL_LINES=$(journalctl --since "1 hour ago" 2>/dev/null | wc -l || echo 0)
    echo "[PASS] journald active — $JOURNAL_LINES events in last hour"
    ((PASS++))

    echo ""
    echo "Last 10 journal entries:"
    journalctl -n 10 --no-pager 2>/dev/null | head -10
else
    echo "[FAIL] journalctl not available"
    ((FAIL++))
fi

echo ""
echo "--- Auditd Log ---"
check_log "/var/log/audit/audit.log" "auditd syscall log" 5

echo ""
echo "============================================"
echo "Summary: PASS=$PASS | FAIL=$FAIL"
echo "============================================"
