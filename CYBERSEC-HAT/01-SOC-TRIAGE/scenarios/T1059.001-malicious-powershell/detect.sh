#!/usr/bin/env bash
set -euo pipefail

# T1059.001 Malicious Scripting — Detect
#
# Surfaces encoded command execution, suspicious interpreter use,
# and script-based execution patterns on Linux systems.
# (On Windows environments, use Splunk/Sysmon queries from tools/siem-queries-splunk.md)
#
# ATT&CK: T1059.001 (Command and Scripting Interpreter: PowerShell / Bash)
# NIST:   SI-4, AU-12
#
# USAGE: ./detect.sh

EVIDENCE_DIR="/tmp/T1059-detect-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$EVIDENCE_DIR"

echo "============================================"
echo "T1059.001 Malicious Scripting — Detection"
echo "============================================"
echo ""

echo "--- Encoded Commands in Shell History ---"
for user_home in /home/* /root; do
    hist_file="$user_home/.bash_history"
    if [ -r "$hist_file" ]; then
        matches=$(grep -nE "base64|frombase64|-enc |encodedcommand|IEX|Invoke-Expression" "$hist_file" 2>/dev/null || true)
        if [ -n "$matches" ]; then
            echo "[!] Suspicious entries in $hist_file:"
            echo "$matches"
            echo "$matches" >> "$EVIDENCE_DIR/encoded-history.txt"
        fi
    fi
done

echo ""
echo "--- Suspicious Interpreter Invocations (Recent Processes) ---"
ps aux 2>/dev/null \
    | grep -iE "python.*-c|perl.*-e|ruby.*-e|bash.*-c|sh.*-c|curl.*bash|wget.*bash" \
    | grep -v grep \
    | tee "$EVIDENCE_DIR/suspicious-interpreters.txt"

echo ""
echo "--- Base64 Strings in /tmp and /var/tmp ---"
find /tmp /var/tmp -type f -readable 2>/dev/null \
    | while read -r f; do
        if file "$f" | grep -qi "text\|script\|ASCII"; then
            if grep -qiE "base64|eval|exec|system\(" "$f" 2>/dev/null; then
                echo "[!] Suspicious file: $f"
                head -5 "$f" 2>/dev/null
                echo "---"
            fi
        fi
    done | tee "$EVIDENCE_DIR/suspicious-tmp-files.txt"

echo ""
echo "--- Recent Script Files Created ---"
find /tmp /var/tmp /dev/shm "$HOME" -maxdepth 3 \
    \( -name "*.sh" -o -name "*.py" -o -name "*.pl" -o -name "*.rb" \) \
    -newer /proc/1 2>/dev/null \
    | tee "$EVIDENCE_DIR/recent-scripts.txt"

echo ""
echo "--- Outbound Connections from Script Interpreters ---"
ss -tnp 2>/dev/null \
    | grep -iE "python|perl|ruby|bash|sh" \
    | tee "$EVIDENCE_DIR/interpreter-connections.txt"

echo ""
echo "--- Syslog: Script Execution Indicators ---"
grep -iE "python|perl|ruby|bash.*-c|curl.*pipe" /var/log/syslog 2>/dev/null \
    | tail -20 \
    | tee "$EVIDENCE_DIR/syslog-script-indicators.txt"

echo ""
echo "Evidence saved to: $EVIDENCE_DIR"
