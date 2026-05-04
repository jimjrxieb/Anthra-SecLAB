#!/usr/bin/env bash
set -euo pipefail

# T1003 Credential Dumping — Hunt Detection
#
# Hunts for indicators of credential dumping: processes accessing
# sensitive credential files, ptrace usage, and suspicious memory access.
#
# ATT&CK: T1003 (OS Credential Dumping)
# NIST:   SI-4, CA-7
#
# USAGE: sudo ./detect.sh

EVIDENCE_DIR="/tmp/T1003-hunt-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$EVIDENCE_DIR"

echo "============================================"
echo "T1003 Credential Dumping — Hunt"
echo "============================================"
echo ""

echo "--- Processes Accessing /etc/shadow or /etc/passwd ---"
lsof /etc/shadow /etc/passwd 2>/dev/null \
    | tee "$EVIDENCE_DIR/cred-file-access.txt"
if [ ! -s "$EVIDENCE_DIR/cred-file-access.txt" ]; then
    echo "(none detected — negative finding)"
fi

echo ""
echo "--- auditd: Recent Access to /etc/shadow ---"
ausearch -f /etc/shadow 2>/dev/null | tail -30 \
    | tee "$EVIDENCE_DIR/ausearch-shadow.txt"
if [ ! -s "$EVIDENCE_DIR/ausearch-shadow.txt" ]; then
    echo "(no auditd events — check if auditd file watch rule is in place)"
fi

echo ""
echo "--- Processes Using ptrace (Debuggers / Injectors) ---"
ps aux 2>/dev/null \
    | grep -iE "gdb|strace|ltrace|ptrace" \
    | grep -v grep \
    | tee "$EVIDENCE_DIR/ptrace-processes.txt"

echo ""
echo "--- Processes with RWX Anonymous Memory Segments ---"
echo "(Shellcode / injection indicator)"
for pid in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$'); do
    maps="/proc/$pid/maps"
    if [ -r "$maps" ]; then
        if grep -q "rwxp" "$maps" 2>/dev/null; then
            cmdline=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null || echo "unknown")
            echo "[!] PID $pid has rwx anonymous memory: $cmdline"
            echo "PID=$pid CMD=$cmdline" >> "$EVIDENCE_DIR/rwx-memory.txt"
        fi
    fi
done

echo ""
echo "--- Known Credential Dumping Tools in PATH or /tmp ---"
for tool in mimikatz secretsdump impacket crackmapexec LaZagne; do
    found=$(find /tmp /var/tmp /home /root -name "*${tool}*" 2>/dev/null)
    if [ -n "$found" ]; then
        echo "[!] Found: $found"
        echo "$found" >> "$EVIDENCE_DIR/dumping-tools.txt"
    fi
done
command -v mimikatz &>/dev/null && echo "[!] mimikatz in PATH" || true
command -v secretsdump &>/dev/null && echo "[!] secretsdump in PATH" || true

echo ""
echo "--- Recent Changes to /etc/passwd or /etc/shadow ---"
stat /etc/passwd /etc/shadow 2>/dev/null \
    | grep -E "File:|Modify:" \
    | tee "$EVIDENCE_DIR/cred-file-stats.txt"

echo ""
echo "Evidence saved to: $EVIDENCE_DIR"
echo "Negative findings are documented in $EVIDENCE_DIR — save for CA-7 evidence."
