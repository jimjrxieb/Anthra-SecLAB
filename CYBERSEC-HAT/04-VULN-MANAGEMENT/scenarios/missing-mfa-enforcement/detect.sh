#!/usr/bin/env bash
set -euo pipefail

# Missing MFA Enforcement — Detect
#
# Checks whether MFA is configured and enforced for privileged accounts
# and remote access. Identifies accounts that can authenticate with
# password alone.
#
# ATT&CK: T1078 (Valid Accounts — enabled by missing MFA)
# NIST:   IA-2, AC-7
#
# USAGE: ./detect.sh

EVIDENCE_DIR="/tmp/mfa-detect-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$EVIDENCE_DIR"

echo "============================================"
echo "Missing MFA Enforcement — Detection"
echo "============================================"
echo ""

echo "--- PAM MFA Configuration Check ---"
MFA_CONFIGURED=false

if grep -rq "pam_google_authenticator\|pam_duo\|pam_oath\|pam_u2f" /etc/pam.d/ 2>/dev/null; then
    MFA_CONFIGURED=true
    echo "[PASS] MFA module found in PAM configuration:"
    grep -r "pam_google_authenticator\|pam_duo\|pam_oath\|pam_u2f" /etc/pam.d/ | head -10
else
    echo "[FAIL] No MFA PAM module configured"
    echo "       Common options: pam_google_authenticator, pam_duo, pam_oath, pam_u2f"
fi

echo ""
echo "--- SSH MFA Configuration ---"
if [ -f /etc/ssh/sshd_config ]; then
    AUTH_METHODS=$(grep -i "AuthenticationMethods\|ChallengeResponseAuthentication\|UsePAM\|KbdInteractiveAuthentication" /etc/ssh/sshd_config 2>/dev/null || true)
    if [ -n "$AUTH_METHODS" ]; then
        echo "$AUTH_METHODS" | tee "$EVIDENCE_DIR/ssh-mfa-config.txt"
        if echo "$AUTH_METHODS" | grep -qi "publickey,keyboard-interactive\|publickey,password\|publickey,totp"; then
            echo "[PASS] SSH requires multi-factor authentication"
        else
            echo "[WARN] SSH AuthenticationMethods may not require MFA — review configuration"
        fi
    else
        echo "[WARN] SSH AuthenticationMethods not explicitly set"
    fi
fi

echo ""
echo "--- Users Without MFA Configured ---"
echo "(Checking for Google Authenticator token files)"
NO_MFA_COUNT=0
while IFS=: read -r username _ uid _ _ homedir _; do
    # Only check interactive users (UID >= 1000, not system accounts)
    if [ "$uid" -ge 1000 ] 2>/dev/null; then
        if [ ! -f "${homedir}/.google_authenticator" ]; then
            echo "[NO MFA] $username (home: $homedir)"
            echo "$username" >> "$EVIDENCE_DIR/users-without-mfa.txt"
            ((NO_MFA_COUNT++))
        else
            echo "[MFA OK] $username"
        fi
    fi
done < /etc/passwd

echo ""
echo "--- Privileged Accounts Without MFA ---"
echo "(Sudo group members)"
getent group sudo 2>/dev/null | cut -d: -f4 | tr ',' '\n' | while read -r user; do
    [ -z "$user" ] && continue
    homedir=$(getent passwd "$user" | cut -d: -f6)
    if [ -n "$homedir" ] && [ ! -f "${homedir}/.google_authenticator" ]; then
        echo "[CRITICAL] Sudo user '$user' has no MFA configured"
        echo "$user" >> "$EVIDENCE_DIR/privileged-no-mfa.txt"
    fi
done

echo ""
echo "--- Sudo Configuration: NOPASSWD Check ---"
grep -r "NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null \
    | tee "$EVIDENCE_DIR/sudo-nopasswd.txt" || true
NOPASSWD_COUNT=$(wc -l < "$EVIDENCE_DIR/sudo-nopasswd.txt")
[ "$NOPASSWD_COUNT" -gt 0 ] && echo "[WARN] $NOPASSWD_COUNT NOPASSWD sudo rule(s) — these bypass authentication entirely"

echo ""
echo "--- Password-Only SSH (No Key Required) ---"
PASSWD_AUTH=$(grep -i "^PasswordAuthentication" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || true)
if [[ "$PASSWD_AUTH" == "yes" ]]; then
    echo "[FAIL] PasswordAuthentication is enabled — password-only SSH possible"
else
    echo "[PASS] PasswordAuthentication is disabled (key-based auth required)"
fi

echo ""
echo "Evidence saved to: $EVIDENCE_DIR"

if [ "$NO_MFA_COUNT" -gt 0 ]; then
    echo ""
    echo "[!] $NO_MFA_COUNT user(s) have no MFA configured"
fi
