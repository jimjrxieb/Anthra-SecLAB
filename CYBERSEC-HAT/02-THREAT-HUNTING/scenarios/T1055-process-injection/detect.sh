#!/usr/bin/env bash
set -euo pipefail

# T1055 Process Injection — Hunt Detection
#
# Hunts for process injection indicators: RWX anonymous memory,
# unusual parent-child relationships, and hollowing indicators.
#
# ATT&CK: T1055 (Process Injection)
# NIST:   SI-4, CA-7
#
# USAGE: sudo ./detect.sh

EVIDENCE_DIR="/tmp/T1055-hunt-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$EVIDENCE_DIR"

echo "============================================"
echo "T1055 Process Injection — Hunt"
echo "============================================"
echo ""

echo "--- Processes with Executable Anonymous Memory (RWX) ---"
INJECTED=0
for pid in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$'); do
    maps="/proc/$pid/maps"
    if [ -r "$maps" ]; then
        if grep -qE "^[0-9a-f]+-[0-9a-f]+ rwxp 00000000 00:00 0 *$" "$maps" 2>/dev/null; then
            cmdline=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null || echo "unknown")
            echo "[!] PID $pid — anonymous RWX memory: $cmdline"
            echo "PID=$pid CMD=$cmdline" >> "$EVIDENCE_DIR/rwx-anon-memory.txt"
            ((INJECTED++))
        fi
    fi
done
[ "$INJECTED" -eq 0 ] && echo "(none detected)"

echo ""
echo "--- Unusual Parent-Child Relationships ---"
echo "(web servers, databases spawning shells)"
ps -eo pid,ppid,comm,args --no-headers 2>/dev/null | awk '
{
    procs[$1] = $3
    args[$1] = $4
}
END {
    for (pid in procs) {
        ppid_name = procs[$2]
        if ((procs[pid] == "bash" || procs[pid] == "sh" || procs[pid] == "python3") &&
            (ppid_name ~ /apache|nginx|httpd|mysql|postgres|java/)) {
            print "[SUSPICIOUS] PID=" pid " (" procs[pid] ") parent=(" ppid_name ")"
        }
    }
}' | tee "$EVIDENCE_DIR/suspicious-parent-child.txt"

echo ""
echo "--- Process Hollowing Indicators ---"
echo "(processes running from unexpected paths or with no on-disk executable)"
for pid in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$'); do
    exe_link="/proc/$pid/exe"
    if [ -L "$exe_link" ]; then
        target=$(readlink "$exe_link" 2>/dev/null || echo "")
        if echo "$target" | grep -q "(deleted)"; then
            cmdline=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null || echo "unknown")
            echo "[!] PID $pid running deleted executable: $target — $cmdline"
            echo "PID=$pid EXE=$target CMD=$cmdline" >> "$EVIDENCE_DIR/deleted-exe.txt"
        fi
    fi
done

echo ""
echo "--- Processes with Network Connections (Unexpected Listeners) ---"
ss -tnp 2>/dev/null | grep ESTABLISHED \
    | grep -v "127.0.0.1\|::1" \
    | tee "$EVIDENCE_DIR/network-connections.txt"

echo ""
echo "--- ptrace Active Usage ---"
ausearch -sc ptrace 2>/dev/null | tail -30 \
    | tee "$EVIDENCE_DIR/ptrace-events.txt"
if [ ! -s "$EVIDENCE_DIR/ptrace-events.txt" ]; then
    echo "(no auditd ptrace events — check if ptrace audit rule is configured)"
fi

echo ""
echo "Evidence saved to: $EVIDENCE_DIR"
