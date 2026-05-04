#!/usr/bin/env bash
set -euo pipefail

# SOC Triage — SIEM Coverage Audit
#
# Checks what log sources are actively sending logs, identifies
# coverage gaps, and verifies audit logging is configured.
#
# NIST: SI-4 (Information System Monitoring), AU-12 (Audit Record Generation)
#
# USAGE: ./audit-siem-coverage.sh

EVIDENCE_DIR="/tmp/soc-audit-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$EVIDENCE_DIR"

echo "============================================"
echo "SOC Triage — SIEM Coverage Audit"
echo "============================================"
echo ""

PASS=0
FAIL=0
WARN=0

check() {
    local status="$1"
    local msg="$2"
    case "$status" in
        PASS) echo "[PASS] $msg"; ((PASS++)) ;;
        FAIL) echo "[FAIL] $msg"; ((FAIL++)) ;;
        WARN) echo "[WARN] $msg"; ((WARN++)) ;;
    esac
}

echo "--- Log Source Coverage ---"
echo ""

# Check syslog is running
if systemctl is-active rsyslog &>/dev/null || systemctl is-active syslog &>/dev/null; then
    check PASS "syslog daemon is running"
else
    check FAIL "syslog daemon is not running — events not being collected"
fi

# Check auditd is running
if systemctl is-active auditd &>/dev/null; then
    check PASS "auditd is running"
    auditctl -l > "$EVIDENCE_DIR/audit-rules.txt" 2>/dev/null || true
else
    check FAIL "auditd is not running — system call auditing unavailable"
fi

# Check auth log exists and is recent
if [ -f /var/log/auth.log ]; then
    AGE=$(( $(date +%s) - $(stat -c %Y /var/log/auth.log) ))
    if [ "$AGE" -lt 3600 ]; then
        check PASS "auth.log is current (updated in last hour)"
    else
        check WARN "auth.log exists but has not been updated in over 1 hour"
    fi
else
    check FAIL "auth.log not found — authentication events not being logged"
fi

# Check syslog file
if [ -f /var/log/syslog ]; then
    check PASS "syslog file exists"
    wc -l /var/log/syslog >> "$EVIDENCE_DIR/log-sizes.txt" 2>/dev/null || true
else
    check WARN "syslog not at /var/log/syslog — check alternate location"
fi

echo ""
echo "--- Audit Rule Coverage ---"
echo ""

# Check for key audit rules
if auditctl -l 2>/dev/null | grep -q "/etc/passwd"; then
    check PASS "audit rule: /etc/passwd access monitored"
else
    check FAIL "audit rule missing: /etc/passwd access not monitored"
fi

if auditctl -l 2>/dev/null | grep -q "/etc/shadow"; then
    check PASS "audit rule: /etc/shadow access monitored"
else
    check FAIL "audit rule missing: /etc/shadow access not monitored"
fi

if auditctl -l 2>/dev/null | grep -q "execve"; then
    check PASS "audit rule: process execution (execve) monitored"
else
    check WARN "audit rule missing: process execution not monitored — blind to command execution"
fi

echo ""
echo "--- Authentication Logging ---"
echo ""

# Check if SSH logging is verbose enough
SSH_LOG_LEVEL=$(grep -i "^LogLevel" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
if [[ "$SSH_LOG_LEVEL" == "VERBOSE" || "$SSH_LOG_LEVEL" == "DEBUG" ]]; then
    check PASS "SSH LogLevel is $SSH_LOG_LEVEL — sufficient for triage"
elif [[ "$SSH_LOG_LEVEL" == "INFO" ]]; then
    check WARN "SSH LogLevel is INFO — consider VERBOSE for key fingerprint logging"
else
    check WARN "SSH LogLevel not set or unknown: '$SSH_LOG_LEVEL'"
fi

# Check recent authentication events exist
AUTH_COUNT=$(grep -c "Accepted\|Failed" /var/log/auth.log 2>/dev/null || echo 0)
if [ "$AUTH_COUNT" -gt 0 ]; then
    check PASS "Authentication events found in auth.log ($AUTH_COUNT entries)"
else
    check WARN "No authentication events found in auth.log"
fi

echo ""
echo "============================================"
echo "Summary"
echo "============================================"
echo "PASS: $PASS | WARN: $WARN | FAIL: $FAIL"
echo "Evidence: $EVIDENCE_DIR"
echo ""

if [ "$FAIL" -gt 0 ]; then
    echo "[!] Coverage gaps detected. Address FAIL items before relying on this system for SOC operations."
    exit 1
else
    echo "[+] Minimum log coverage confirmed."
fi
