#!/usr/bin/env bash
set -euo pipefail

# Threat Hunting — Telemetry Coverage Audit
#
# Verifies that the data sources required for effective threat hunting
# are present and generating events. Hunting against incomplete telemetry
# produces false negatives.
#
# NIST: SI-4 (Information System Monitoring), CA-7 (Continuous Monitoring)
#
# USAGE: ./audit-telemetry-coverage.sh

echo "============================================"
echo "Threat Hunting — Telemetry Coverage Audit"
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

echo "--- Process Execution Telemetry ---"

if systemctl is-active auditd &>/dev/null; then
    check PASS "auditd running — process execution telemetry available"
    if auditctl -l 2>/dev/null | grep -q "execve"; then
        check PASS "auditd execve rule present — command execution logged"
    else
        check FAIL "auditd missing execve rule — process execution not logged (critical for hunting)"
    fi
else
    check FAIL "auditd not running — no process execution telemetry"
fi

echo ""
echo "--- Memory Access Telemetry ---"

if auditctl -l 2>/dev/null | grep -q "ptrace"; then
    check PASS "auditd ptrace rule present — credential dumping attempts logged"
else
    check WARN "auditd ptrace rule missing — LSASS-equivalent credential dumping not monitored"
fi

echo ""
echo "--- Network Connection Telemetry ---"

if command -v zeek &>/dev/null || [ -d /var/log/zeek ]; then
    check PASS "Zeek present — network connection telemetry available"
    if [ -f /var/log/zeek/current/conn.log ]; then
        check PASS "Zeek conn.log active and current"
    else
        check WARN "Zeek installed but conn.log not found at /var/log/zeek/current/conn.log"
    fi
else
    check WARN "Zeek not installed — network telemetry limited to ss/netstat (live only, no history)"
fi

echo ""
echo "--- Authentication Telemetry ---"

if [ -f /var/log/auth.log ] && [ -s /var/log/auth.log ]; then
    LINES=$(wc -l < /var/log/auth.log)
    check PASS "auth.log present with $LINES entries"
else
    check FAIL "auth.log missing or empty — authentication telemetry unavailable"
fi

echo ""
echo "--- File System Telemetry ---"

if auditctl -l 2>/dev/null | grep -q "openat\|open\|-w /etc"; then
    check PASS "auditd file watch rules present — file system changes logged"
else
    check WARN "auditd file watch rules missing — file system changes not logged (reduces hunt effectiveness)"
fi

echo ""
echo "--- Endpoint Hunting Tools ---"

command -v velociraptor &>/dev/null && check PASS "Velociraptor available" || check WARN "Velociraptor not installed (recommended for scalable hunting)"
command -v osqueryi &>/dev/null && check PASS "OSQuery available" || check WARN "OSQuery not installed (useful for SQL-based endpoint hunting)"

echo ""
echo "============================================"
echo "Summary: PASS=$PASS | WARN=$WARN | FAIL=$FAIL"
echo "============================================"
echo ""
if [ "$FAIL" -gt 0 ]; then
    echo "[!] Critical telemetry gaps detected. Hunting against incomplete data produces false negatives."
    echo "    Address FAIL items before running hunts."
fi
