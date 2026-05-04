#!/usr/bin/env bash
set -euo pipefail

# Vulnerability Management — Patch Compliance Audit
#
# Checks for available security patches, assesses current patch age,
# and identifies high-priority unpatched components.
#
# NIST: RA-5 (Vulnerability Scanning), SI-2 (Flaw Remediation)
#
# USAGE: ./audit-patch-compliance.sh

echo "============================================"
echo "Patch Compliance Audit"
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

echo "--- OS and Kernel ---"
echo "OS: $(lsb_release -ds 2>/dev/null || grep PRETTY_NAME /etc/os-release | cut -d'"' -f2)"
echo "Kernel: $(uname -r)"
echo ""

echo "--- Available Security Updates ---"
if command -v apt &>/dev/null; then
    apt-get update -qq 2>/dev/null || true
    SECURITY_UPDATES=$(apt-get -s upgrade 2>/dev/null | grep -c "^Inst" || echo 0)
    TOTAL_UPDATES=$(apt list --upgradable 2>/dev/null | grep -c "upgradable" || echo 0)

    if [ "$SECURITY_UPDATES" -eq 0 ] && [ "$TOTAL_UPDATES" -eq 0 ]; then
        check PASS "System is fully patched (no pending updates)"
    elif [ "$SECURITY_UPDATES" -gt 0 ]; then
        check FAIL "$SECURITY_UPDATES security update(s) pending — apply immediately"
        apt list --upgradable 2>/dev/null | head -20
    else
        check WARN "$TOTAL_UPDATES update(s) pending (non-security)"
    fi
elif command -v yum &>/dev/null; then
    SECURITY_UPDATES=$(yum check-update --security 2>/dev/null | grep -c "^[A-Z]" || echo 0)
    if [ "$SECURITY_UPDATES" -gt 0 ]; then
        check FAIL "$SECURITY_UPDATES security update(s) pending"
    else
        check PASS "No pending security updates (yum)"
    fi
fi

echo ""
echo "--- Critical Package Versions ---"

# OpenSSH
if command -v ssh &>/dev/null; then
    SSH_VER=$(ssh -V 2>&1 | head -1)
    echo "[INFO] $SSH_VER"
fi

# OpenSSL
if command -v openssl &>/dev/null; then
    SSL_VER=$(openssl version)
    echo "[INFO] $SSL_VER"
fi

# Kernel age
KERNEL_INSTALL=$(ls -la /boot/vmlinuz-"$(uname -r)" 2>/dev/null | awk '{print $6, $7, $8}')
echo "[INFO] Kernel installed: $KERNEL_INSTALL"

echo ""
echo "--- Unattended Upgrades ---"
if dpkg -l unattended-upgrades &>/dev/null 2>&1; then
    if systemctl is-active unattended-upgrades &>/dev/null; then
        check PASS "unattended-upgrades active (automatic security patches enabled)"
    else
        check WARN "unattended-upgrades installed but not active"
    fi
else
    check WARN "unattended-upgrades not installed — no automatic security patching"
fi

echo ""
echo "--- Last Package Update ---"
if [ -f /var/log/dpkg.log ]; then
    LAST_UPDATE=$(grep "status installed" /var/log/dpkg.log 2>/dev/null | tail -1 | awk '{print $1, $2}')
    if [ -n "$LAST_UPDATE" ]; then
        echo "[INFO] Last package installed: $LAST_UPDATE"
    fi
fi

echo ""
echo "============================================"
echo "Summary: PASS=$PASS | WARN=$WARN | FAIL=$FAIL"
echo "============================================"
[ "$FAIL" -gt 0 ] && echo "[!] Critical patch gaps found." || echo "[+] Patch compliance check passed."
