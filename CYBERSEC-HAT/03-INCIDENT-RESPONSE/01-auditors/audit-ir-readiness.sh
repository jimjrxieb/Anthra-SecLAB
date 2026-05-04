#!/usr/bin/env bash
set -euo pipefail

# Incident Response — Readiness Audit
#
# Checks that IR prerequisites are in place before an incident occurs.
# Run quarterly or after any significant environment change.
#
# NIST: IR-4 (Incident Handling), IR-8 (Incident Response Plan)
#
# USAGE: ./audit-ir-readiness.sh

echo "============================================"
echo "Incident Response Readiness Audit"
echo "============================================"
echo ""

PASS=0
FAIL=0
WARN=0

check() {
    local status="$1"; local msg="$2"
    case "$status" in
        PASS) echo "[PASS] $msg"; ((PASS++)) ;;
        FAIL) echo "[FAIL] $msg"; ((FAIL++)) ;;
        WARN) echo "[WARN] $msg"; ((WARN++)) ;;
    esac
}

echo "--- Evidence Collection Tools ---"

command -v tcpdump &>/dev/null && check PASS "tcpdump available (network capture)" || check WARN "tcpdump not installed"
command -v dd &>/dev/null && check PASS "dd available (disk/memory imaging)" || check FAIL "dd not found"
command -v strings &>/dev/null && check PASS "strings available (binary analysis)" || check WARN "strings not installed"
command -v lsof &>/dev/null && check PASS "lsof available (open file/connection listing)" || check WARN "lsof not installed"
command -v ss &>/dev/null && check PASS "ss available (network connection listing)" || check WARN "ss not installed"
{ command -v volatility3 &>/dev/null || command -v vol.py &>/dev/null; } && check PASS "Volatility available (memory forensics)" || check WARN "Volatility not installed (recommended for memory forensics)"

echo ""
echo "--- Log Retention ---"

# Check how old auth.log is (retention indicator)
if [ -f /var/log/auth.log ]; then
    OLDEST=$(ls -t /var/log/auth.log* 2>/dev/null | tail -1)
    if [ -n "$OLDEST" ]; then
        AGE_DAYS=$(( ( $(date +%s) - $(stat -c %Y "$OLDEST") ) / 86400 ))
        if [ "$AGE_DAYS" -ge 90 ]; then
            check PASS "auth.log retention: ${AGE_DAYS} days (meets 90-day minimum)"
        else
            check WARN "auth.log retention: ${AGE_DAYS} days (recommend 90+ days for IR)"
        fi
    fi
else
    check FAIL "auth.log not found — no authentication log retention"
fi

echo ""
echo "--- Backup Availability ---"

# Check if common backup tools/dirs exist
if command -v restic &>/dev/null || command -v duplicati &>/dev/null || [ -d /var/backups ]; then
    check PASS "Backup tool or backup directory detected"
else
    check WARN "No common backup tool detected — verify backup solution independently"
fi

echo ""
echo "--- auditd Readiness ---"

systemctl is-active auditd &>/dev/null && check PASS "auditd running" || check FAIL "auditd not running — forensic evidence quality reduced"
[ -f /var/log/audit/audit.log ] && check PASS "audit.log present" || check WARN "audit.log not found"

echo ""
echo "--- Network Isolation Capability ---"

command -v iptables &>/dev/null && check PASS "iptables available (host-level network isolation)" || check WARN "iptables not available"
ip link show &>/dev/null && check PASS "ip command available (interface management for isolation)" || check WARN "ip command not found"

echo ""
echo "============================================"
echo "Summary: PASS=$PASS | WARN=$WARN | FAIL=$FAIL"
echo "============================================"
echo ""
[ "$FAIL" -gt 0 ] && echo "[!] IR readiness gaps found. Address FAIL items before an incident occurs." || echo "[+] Core IR readiness confirmed."
