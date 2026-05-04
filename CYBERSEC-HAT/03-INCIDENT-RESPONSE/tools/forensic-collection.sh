#!/usr/bin/env bash
set -euo pipefail

# Incident Response — Forensic Evidence Collection
#
# Collects volatile and non-volatile evidence in the correct order.
# Run at the start of an investigation BEFORE any containment actions
# that might alter system state.
#
# NIST: IR-4 (Incident Handling)
#
# USAGE: sudo ./forensic-collection.sh [output_dir]

OUTPUT_DIR="${1:-/tmp/ir-evidence-$(date +%Y%m%d-%H%M%S)}"
mkdir -p "$OUTPUT_DIR"

echo "============================================"
echo "Forensic Evidence Collection"
echo "Saving to: $OUTPUT_DIR"
echo "============================================"
echo ""
echo "[*] Start time: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo "[*] Hostname: $(hostname)"
echo "[*] Kernel: $(uname -r)"
echo ""

# Metadata
{
    echo "Collection date: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    echo "Analyst: $(whoami)"
    echo "Hostname: $(hostname)"
    echo "Kernel: $(uname -r)"
    echo "Uptime: $(uptime)"
} > "$OUTPUT_DIR/collection-metadata.txt"

echo "[1/8] Collecting volatile: running processes..."
ps aux --forest > "$OUTPUT_DIR/processes-tree.txt" 2>/dev/null
ps -eo pid,ppid,user,lstart,args > "$OUTPUT_DIR/processes-detail.txt" 2>/dev/null

echo "[2/8] Collecting volatile: network connections..."
ss -tnp > "$OUTPUT_DIR/network-connections.txt" 2>/dev/null
ss -ulnp >> "$OUTPUT_DIR/network-connections.txt" 2>/dev/null
ip route show > "$OUTPUT_DIR/routing-table.txt" 2>/dev/null
ip addr show > "$OUTPUT_DIR/interfaces.txt" 2>/dev/null

echo "[3/8] Collecting volatile: logged-in users..."
who -a > "$OUTPUT_DIR/logged-in-users.txt" 2>/dev/null
w >> "$OUTPUT_DIR/logged-in-users.txt" 2>/dev/null
last -n 100 > "$OUTPUT_DIR/login-history.txt" 2>/dev/null

echo "[4/8] Collecting volatile: open files..."
lsof > "$OUTPUT_DIR/open-files.txt" 2>/dev/null || true

echo "[5/8] Collecting: authentication logs..."
cp /var/log/auth.log "$OUTPUT_DIR/auth.log" 2>/dev/null || true
cp /var/log/auth.log.1 "$OUTPUT_DIR/auth.log.1" 2>/dev/null || true

echo "[6/8] Collecting: system logs..."
cp /var/log/syslog "$OUTPUT_DIR/syslog" 2>/dev/null || true
journalctl --since "7 days ago" > "$OUTPUT_DIR/journald-7days.txt" 2>/dev/null || true

echo "[7/8] Collecting: auditd logs..."
cp /var/log/audit/audit.log "$OUTPUT_DIR/audit.log" 2>/dev/null || true
ausearch -ts today > "$OUTPUT_DIR/auditd-today.txt" 2>/dev/null || true

echo "[8/8] Collecting: persistence locations..."
for user in $(cut -d: -f1 /etc/passwd 2>/dev/null); do
    crontab -l -u "$user" 2>/dev/null && echo "---$user---"
done > "$OUTPUT_DIR/all-crontabs.txt"
find /home /root -name "authorized_keys" -exec echo "=== {} ===" \; -exec cat {} \; > "$OUTPUT_DIR/authorized-keys.txt" 2>/dev/null || true
systemctl list-timers --all > "$OUTPUT_DIR/systemd-timers.txt" 2>/dev/null || true
find /tmp /var/tmp /dev/shm -type f -ls > "$OUTPUT_DIR/tmp-files.txt" 2>/dev/null || true

echo ""
echo "============================================"
echo "Collection Complete"
echo "Evidence directory: $OUTPUT_DIR"
echo "File count: $(find "$OUTPUT_DIR" -type f | wc -l)"
echo "============================================"
echo ""
echo "Hash all evidence files for chain of custody:"
find "$OUTPUT_DIR" -type f | xargs sha256sum > "$OUTPUT_DIR/SHA256SUMS.txt" 2>/dev/null
echo "[+] Hashes written to $OUTPUT_DIR/SHA256SUMS.txt"
