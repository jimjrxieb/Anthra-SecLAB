#!/usr/bin/env bash
set -euo pipefail

# Ransomware Response — Detect
#
# Detects active ransomware indicators: mass file modification,
# ransom notes, suspicious processes, and C2 connections.
#
# ATT&CK: T1486 (Data Encrypted for Impact), T1490 (Inhibit System Recovery)
# NIST:   IR-4, IR-5
#
# USAGE: sudo ./detect.sh

EVIDENCE_DIR="/tmp/ransomware-detect-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$EVIDENCE_DIR"

echo "============================================"
echo "Ransomware Response — Detection"
echo "============================================"
echo ""

echo "--- Ransom Note Files ---"
find / -maxdepth 6 \
    \( -name "README_DECRYPT*" -o -name "HOW_TO_DECRYPT*" -o -name "RECOVER_FILES*" \
       -o -name "YOUR_FILES_ARE_ENCRYPTED*" -o -name "DECRYPT_INSTRUCTIONS*" \) \
    2>/dev/null \
    | tee "$EVIDENCE_DIR/ransom-notes.txt"

RANSOM_NOTE_COUNT=$(wc -l < "$EVIDENCE_DIR/ransom-notes.txt")
if [ "$RANSOM_NOTE_COUNT" -gt 0 ]; then
    echo "[!!!] CRITICAL: $RANSOM_NOTE_COUNT ransom note(s) found — active ransomware confirmed"
fi

echo ""
echo "--- Encrypted File Extensions ---"
find /home /var /srv /opt -maxdepth 5 \
    \( -name "*.encrypted" -o -name "*.locked" -o -name "*.crypto" \
       -o -name "*.enc" -o -name "*.crypted" -o -name "*.crypt" \) \
    -newer /proc/1 2>/dev/null \
    | head -20 \
    | tee "$EVIDENCE_DIR/encrypted-files.txt"

ENCRYPTED_COUNT=$(wc -l < "$EVIDENCE_DIR/encrypted-files.txt")
[ "$ENCRYPTED_COUNT" -gt 0 ] && echo "[!] $ENCRYPTED_COUNT encrypted file(s) detected"

echo ""
echo "--- Processes with High File I/O ---"
echo "(Processes opening many files — potential active encryption)"
lsof 2>/dev/null \
    | awk '{print $1}' \
    | sort | uniq -c | sort -rn \
    | head -20 \
    | tee "$EVIDENCE_DIR/high-io-processes.txt"

echo ""
echo "--- Volume Shadow Copy / Backup Deletion Indicators ---"
echo "(T1490: Inhibit System Recovery)"
grep -i "vssadmin\|wbadmin\|bcdedit\|shadow" /var/log/syslog /var/log/auth.log 2>/dev/null \
    | tail -20 \
    | tee "$EVIDENCE_DIR/backup-deletion-indicators.txt"

echo ""
echo "--- Active Outbound Connections (C2) ---"
ss -tnp 2>/dev/null \
    | grep ESTABLISHED \
    | grep -v "127.0.0.1\|::1\|192.168\|10\.\|172\.1[6-9]\.\|172\.2[0-9]\.\|172\.3[0-1]\." \
    | tee "$EVIDENCE_DIR/c2-connections.txt"

C2_COUNT=$(wc -l < "$EVIDENCE_DIR/c2-connections.txt")
[ "$C2_COUNT" -gt 0 ] && echo "[!] $C2_COUNT external connection(s) active — possible C2"

echo ""
echo "--- Suspicious CPU/IO Load ---"
top -bn1 | head -20 | tee "$EVIDENCE_DIR/top-output.txt"

echo ""
echo "Evidence saved to: $EVIDENCE_DIR"

if [ "$RANSOM_NOTE_COUNT" -gt 0 ] || [ "$ENCRYPTED_COUNT" -gt 0 ]; then
    echo ""
    echo "============================================"
    echo "[!!!] RANSOMWARE INDICATORS CONFIRMED"
    echo "[!!!] Initiate containment IMMEDIATELY"
    echo "[!!!] Do NOT reboot. Isolate from network."
    echo "============================================"
fi
