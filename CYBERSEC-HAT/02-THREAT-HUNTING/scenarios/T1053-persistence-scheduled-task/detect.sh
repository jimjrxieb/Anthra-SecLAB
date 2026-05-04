#!/usr/bin/env bash
set -euo pipefail

# T1053 Scheduled Task Persistence — Hunt
#
# Hunts for persistence established via scheduled tasks (cron, systemd timers,
# at jobs). Looks for new entries, unusual authors, and suspicious commands.
#
# ATT&CK: T1053 (Scheduled Task/Job)
# NIST:   SI-4, CA-7, CM-3
#
# USAGE: ./detect.sh

EVIDENCE_DIR="/tmp/T1053-hunt-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$EVIDENCE_DIR"

echo "============================================"
echo "T1053 Scheduled Task Persistence — Hunt"
echo "============================================"
echo ""

echo "--- All User Crontabs ---"
for user in $(cut -d: -f1 /etc/passwd 2>/dev/null); do
    ct=$(crontab -l -u "$user" 2>/dev/null)
    if [ -n "$ct" ]; then
        echo "=== Crontab: $user ==="
        echo "$ct"
        echo "$ct" >> "$EVIDENCE_DIR/user-crontabs.txt"
    fi
done

echo ""
echo "--- System Cron Directories ---"
ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.weekly/ /etc/cron.monthly/ /etc/crontab 2>/dev/null \
    | tee "$EVIDENCE_DIR/system-cron-dirs.txt"

echo ""
echo "--- Cron File Contents ---"
for dir in /etc/cron.d/ /etc/cron.daily/ /etc/cron.weekly/; do
    if [ -d "$dir" ]; then
        for f in "$dir"*; do
            [ -f "$f" ] || continue
            echo "=== $f ==="
            cat "$f" 2>/dev/null
            echo ""
        done
    fi
done | tee "$EVIDENCE_DIR/cron-file-contents.txt"

echo ""
echo "--- Recently Modified Cron Files (Last 7 Days) ---"
find /etc/cron* /var/spool/cron/ -newer /proc/1 -type f -ls 2>/dev/null \
    | tee "$EVIDENCE_DIR/recently-modified-crons.txt"
if [ ! -s "$EVIDENCE_DIR/recently-modified-crons.txt" ]; then
    echo "(none found)"
fi

echo ""
echo "--- Systemd Timers ---"
systemctl list-timers --all 2>/dev/null \
    | tee "$EVIDENCE_DIR/systemd-timers.txt"

echo ""
echo "--- Recently Created Systemd Units ---"
find /etc/systemd/system/ /usr/lib/systemd/system/ \( -name "*.service" -o -name "*.timer" \) -newer /proc/1 2>/dev/null \
    | tee "$EVIDENCE_DIR/new-systemd-units.txt"
if [ ! -s "$EVIDENCE_DIR/new-systemd-units.txt" ]; then
    echo "(none found)"
fi

echo ""
echo "--- at Jobs (if atd running) ---"
if command -v atq &>/dev/null; then
    atq 2>/dev/null | tee "$EVIDENCE_DIR/at-jobs.txt"
    [ ! -s "$EVIDENCE_DIR/at-jobs.txt" ] && echo "(no at jobs queued)"
else
    echo "(atd not installed)"
fi

echo ""
echo "--- Suspicious Cron Patterns ---"
echo "(Base64, curl|bash, wget|bash, reverse shells)"
grep -rE "base64|curl.*bash|wget.*bash|\|bash|\|sh|nc -e|/dev/tcp" \
    /etc/cron* /var/spool/cron/ 2>/dev/null \
    | tee "$EVIDENCE_DIR/suspicious-cron-content.txt"
if [ ! -s "$EVIDENCE_DIR/suspicious-cron-content.txt" ]; then
    echo "(none found)"
fi

echo ""
echo "Evidence saved to: $EVIDENCE_DIR"
