#!/usr/bin/env bash
set -euo pipefail

# Vulnerability Management — Scan Coverage Audit
#
# Verifies that vulnerability scanning tools are installed and configured.
# Runs a basic host security assessment using available tools.
#
# NIST: RA-5 (Vulnerability Monitoring and Scanning)
#
# USAGE: ./audit-scan-coverage.sh

echo "============================================"
echo "Vulnerability Scan Coverage Audit"
echo "============================================"
echo ""

PASS=0
WARN=0

check() {
    local status="$1"; local msg="$2"
    case "$status" in
        PASS) echo "[PASS] $msg"; ((PASS++)) ;;
        WARN) echo "[WARN] $msg"; ((WARN++)) ;;
    esac
}

echo "--- Scanning Tools Available ---"
command -v lynis    &>/dev/null && check PASS "lynis available (host security audit)"            || check WARN "lynis not installed: sudo apt install lynis"
command -v trivy    &>/dev/null && check PASS "trivy available (container/filesystem scanning)"  || check WARN "trivy not installed: https://aquasecurity.github.io/trivy"
command -v nuclei   &>/dev/null && check PASS "nuclei available (template-based vuln scanning)"  || check WARN "nuclei not installed: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
command -v nmap     &>/dev/null && check PASS "nmap available (port/service discovery)"          || check WARN "nmap not installed: sudo apt install nmap"
command -v nikto    &>/dev/null && check PASS "nikto available (web server scanning)"            || check WARN "nikto not installed: sudo apt install nikto"
{ command -v openvas &>/dev/null || command -v gvm-cli &>/dev/null; } \
    && check PASS "OpenVAS/GVM available (comprehensive scanner)" \
    || check WARN "OpenVAS not installed (recommended for comprehensive scanning)"

echo ""
echo "--- Quick Host Security Spot Check ---"
echo ""

# Check for world-writable files in sensitive locations
echo "[*] World-writable files in /etc:"
find /etc -maxdepth 2 -perm -o+w -type f 2>/dev/null | head -10
WORLD_WRITABLE=$(find /etc -maxdepth 2 -perm -o+w -type f 2>/dev/null | wc -l)
[ "$WORLD_WRITABLE" -gt 0 ] && echo "[WARN] $WORLD_WRITABLE world-writable file(s) in /etc" || echo "[PASS] No world-writable files in /etc"

echo ""
# Check for SUID binaries (unusual ones)
echo "[*] Unusual SUID binaries:"
find / -perm -4000 -type f 2>/dev/null \
    | grep -vE "^/usr/bin/(passwd|sudo|su|ping|mount|umount|newgrp|chsh|chfn)|^/usr/sbin|^/bin/ping|^/sbin" \
    | head -10

echo ""
# Check for listening services
echo "[*] Listening network services:"
ss -tlnp 2>/dev/null | grep -v "127.0.0.1\|::1" | head -20

echo ""
echo "============================================"
echo "Summary: PASS=$PASS | WARN=$WARN"
echo "============================================"
echo ""
echo "Run 'sudo lynis audit system' for a comprehensive host security assessment."
