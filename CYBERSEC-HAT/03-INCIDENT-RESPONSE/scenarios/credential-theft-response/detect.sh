#!/usr/bin/env bash
set -euo pipefail

# Credential Theft Response — Detect
#
# Detects indicators of credential theft and unauthorized credential use:
# access to credential stores, unusual authentication patterns, and
# pass-the-hash / pass-the-ticket indicators.
#
# ATT&CK: T1003 (OS Credential Dumping), T1550 (Use Alternate Authentication Material)
# NIST:   IR-4, IR-5, IA-5
#
# USAGE: sudo ./detect.sh

EVIDENCE_DIR="/tmp/cred-theft-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$EVIDENCE_DIR"

echo "============================================"
echo "Credential Theft — Active Response Detection"
echo "============================================"
echo ""

echo "--- auditd: Credential File Access ---"
ausearch -f /etc/shadow 2>/dev/null \
    | tail -30 \
    | tee "$EVIDENCE_DIR/shadow-access-auditd.txt"

ausearch -f /etc/passwd 2>/dev/null \
    | grep -v "PAM\|nscd\|sshd\|sudo\|getent" \
    | tail -20 \
    | tee -a "$EVIDENCE_DIR/passwd-access-auditd.txt"

echo ""
echo "--- Processes Currently Accessing Credential Files ---"
lsof /etc/shadow /etc/passwd 2>/dev/null \
    | tee "$EVIDENCE_DIR/live-cred-file-access.txt"

echo ""
echo "--- Recent Password Changes ---"
grep -E "password changed|passwd|chpasswd" /var/log/auth.log 2>/dev/null \
    | tail -20 \
    | tee "$EVIDENCE_DIR/password-changes.txt"

echo ""
echo "--- New SSH Authorized Keys (Last 24h) ---"
find /home /root -name "authorized_keys" -newer /proc/1 -ls 2>/dev/null \
    | tee "$EVIDENCE_DIR/new-ssh-keys.txt"

NEW_KEYS=$(wc -l < "$EVIDENCE_DIR/new-ssh-keys.txt")
[ "$NEW_KEYS" -gt 0 ] && echo "[!] $NEW_KEYS new authorized_keys file(s) detected"

echo ""
echo "--- Unusual Authentication Patterns ---"
echo "(Multiple accounts logged in from same IP — lateral use of stolen creds)"
grep "Accepted" /var/log/auth.log 2>/dev/null \
    | awk '{print $11, $9}' \
    | sort | awk '{ips[$1]=ips[$1]" "$2; count[$1]++} END {for (ip in count) if (count[ip]>1) print ip, "—", count[ip], "accounts:", ips[ip]}' \
    | tee "$EVIDENCE_DIR/multi-account-same-ip.txt"

echo ""
echo "--- Active Sessions by Source IP ---"
who -a 2>/dev/null | tee "$EVIDENCE_DIR/active-sessions.txt"
last -n 20 2>/dev/null | tee -a "$EVIDENCE_DIR/recent-logins.txt"

echo ""
echo "--- LDAP / Kerberos Port Activity (AD environments) ---"
ss -tnp 2>/dev/null \
    | grep -E ":88|:389|:636|:3268" \
    | tee "$EVIDENCE_DIR/ldap-kerberos-connections.txt"

echo ""
echo "Evidence saved to: $EVIDENCE_DIR"
