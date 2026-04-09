#!/usr/bin/env bash
set -euo pipefail

# SC-7 Firewall Misconfiguration — Validate
#
# Confirms that management ports are no longer accessible from outside the admin CIDR
# and that logging and rate limiting are active.
#
# Checks:
#   1. Nmap scan confirms management ports are filtered (not open)
#   2. Firewall rules restrict source to admin CIDR only
#   3. Logging is enabled for management port connections
#   4. Rate limiting is active (Linux) or deny rules exist (Windows)
#   5. Default INPUT policy is DROP (Linux)
#
# REQUIREMENTS:
#   - nmap (apt-get install nmap)
#   - Root/sudo privileges
#   - Run AFTER fix.sh
#
# USAGE:
#   sudo ./validate.sh <target_ip> <admin_cidr>
#
# EXAMPLE:
#   sudo ./validate.sh 10.0.1.50 10.0.100.0/24

# --- Argument Validation ---

if [[ $# -ne 2 ]]; then
    echo "Usage: $0 <target_ip> <admin_cidr>"
    echo "Example: $0 10.0.1.50 10.0.100.0/24"
    exit 1
fi

TARGET="$1"
ADMIN_CIDR="$2"

# Verify running as root
if [[ $EUID -ne 0 ]]; then
    echo "[ERROR] This script must be run as root (sudo)."
    exit 1
fi

EVIDENCE_DIR="/tmp/sc7-firewall-validate-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$EVIDENCE_DIR"

PASS_COUNT=0
FAIL_COUNT=0
TOTAL_CHECKS=0

echo "============================================"
echo "SC-7 Firewall Misconfiguration — Validation"
echo "============================================"
echo ""
echo "[*] Target:       $TARGET"
echo "[*] Admin CIDR:   $ADMIN_CIDR"
echo "[*] Evidence dir: $EVIDENCE_DIR"
echo ""

# --- Helper function for pass/fail ---

check_result() {
    local test_name="$1"
    local passed="$2"
    local detail="$3"
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if [[ "$passed" == "true" ]]; then
        PASS_COUNT=$((PASS_COUNT + 1))
        echo "[PASS] $test_name"
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        echo "[FAIL] $test_name"
    fi
    echo "       $detail"
    echo ""
}

# --- Check 1: Nmap Scan — Management Ports Should Be Filtered ---

echo "[*] Check 1: Nmap scan for management port state"
echo "---------------------------------------------------"

if command -v nmap &>/dev/null; then
    NMAP_OUTPUT="$EVIDENCE_DIR/nmap-validate.txt"

    nmap -sS -Pn -p 22,3389 -T4 --reason \
        -oN "$NMAP_OUTPUT" "$TARGET" 2>&1 | tee "$EVIDENCE_DIR/nmap-stdout.txt"
    echo ""

    # Check if ports are filtered or closed (not open)
    SSH_STATE=$(grep "22/tcp" "$NMAP_OUTPUT" 2>/dev/null | awk '{print $2}' || echo "unknown")
    RDP_STATE=$(grep "3389/tcp" "$NMAP_OUTPUT" 2>/dev/null | awk '{print $2}' || echo "unknown")

    if [[ "$SSH_STATE" == "filtered" ]] || [[ "$SSH_STATE" == "closed" ]]; then
        check_result "SSH (22) not open from scan source" "true" \
            "Port 22 state: $SSH_STATE — management port is properly restricted."
    else
        check_result "SSH (22) not open from scan source" "false" \
            "Port 22 state: $SSH_STATE — management port is still accessible."
    fi

    if [[ "$RDP_STATE" == "filtered" ]] || [[ "$RDP_STATE" == "closed" ]]; then
        check_result "RDP (3389) not open from scan source" "true" \
            "Port 3389 state: $RDP_STATE — management port is properly restricted."
    else
        check_result "RDP (3389) not open from scan source" "false" \
            "Port 3389 state: $RDP_STATE — management port is still accessible."
    fi
else
    echo "[SKIP] nmap not installed — cannot validate port state externally."
    TOTAL_CHECKS=$((TOTAL_CHECKS + 2))
    FAIL_COUNT=$((FAIL_COUNT + 2))
    echo ""
fi

# --- Platform Detection ---

PLATFORM="unknown"
if command -v iptables &>/dev/null; then
    PLATFORM="linux"
elif command -v netsh &>/dev/null || command -v netsh.exe &>/dev/null; then
    PLATFORM="windows"
fi

# --- Check 2: Firewall Rules Restrict Source to Admin CIDR ---

echo "[*] Check 2: Firewall rules restrict source to admin CIDR"
echo "---------------------------------------------------"

if [[ "$PLATFORM" == "linux" ]]; then
    # Check that SSH accept rule specifies admin CIDR, not 0.0.0.0/0
    SSH_ACCEPT=$(iptables -L INPUT -n 2>/dev/null | grep "dpt:22" | grep "ACCEPT" || true)
    if echo "$SSH_ACCEPT" | grep -q "$ADMIN_CIDR"; then
        check_result "SSH restricted to admin CIDR" "true" \
            "SSH ACCEPT rule references $ADMIN_CIDR."
    else
        check_result "SSH restricted to admin CIDR" "false" \
            "SSH ACCEPT rule does not reference $ADMIN_CIDR. Current rules: $SSH_ACCEPT"
    fi

    RDP_ACCEPT=$(iptables -L INPUT -n 2>/dev/null | grep "dpt:3389" | grep "ACCEPT" || true)
    if echo "$RDP_ACCEPT" | grep -q "$ADMIN_CIDR"; then
        check_result "RDP restricted to admin CIDR" "true" \
            "RDP ACCEPT rule references $ADMIN_CIDR."
    else
        check_result "RDP restricted to admin CIDR" "false" \
            "RDP ACCEPT rule does not reference $ADMIN_CIDR. Current rules: $RDP_ACCEPT"
    fi

    # Verify no 0.0.0.0/0 ACCEPT rules remain on management ports
    WIDE_OPEN=$(iptables -L INPUT -n 2>/dev/null | grep "0\.0\.0\.0/0" | grep -E "dpt:22|dpt:3389" | grep "ACCEPT" || true)
    if [[ -z "$WIDE_OPEN" ]]; then
        check_result "No 0.0.0.0/0 rules on management ports" "true" \
            "No overpermissive ACCEPT rules found."
    else
        check_result "No 0.0.0.0/0 rules on management ports" "false" \
            "Overpermissive rules still exist: $WIDE_OPEN"
    fi

elif [[ "$PLATFORM" == "windows" ]]; then
    RULES_OUTPUT="$EVIDENCE_DIR/win-rules-check.txt"
    netsh advfirewall firewall show rule name=all dir=in > "$RULES_OUTPUT" 2>&1

    if grep -A 8 "SC7-FIX.*SSH" "$RULES_OUTPUT" | grep -q "$ADMIN_CIDR"; then
        check_result "SSH restricted to admin CIDR" "true" \
            "SSH rule references $ADMIN_CIDR."
    else
        check_result "SSH restricted to admin CIDR" "false" \
            "SSH rule does not reference $ADMIN_CIDR."
    fi

    if grep -A 8 "SC7-FIX.*RDP" "$RULES_OUTPUT" | grep -q "$ADMIN_CIDR"; then
        check_result "RDP restricted to admin CIDR" "true" \
            "RDP rule references $ADMIN_CIDR."
    else
        check_result "RDP restricted to admin CIDR" "false" \
            "RDP rule does not reference $ADMIN_CIDR."
    fi

    # Check no SC7-BREAK rules remain
    if ! grep -q "SC7-BREAK" "$RULES_OUTPUT"; then
        check_result "No overpermissive break rules remain" "true" \
            "All SC7-BREAK rules have been removed."
    else
        check_result "No overpermissive break rules remain" "false" \
            "SC7-BREAK rules still present in firewall."
    fi
fi

# --- Check 3: Logging Enabled ---

echo "[*] Check 3: Connection logging is active"
echo "---------------------------------------------------"

if [[ "$PLATFORM" == "linux" ]]; then
    LOG_RULES=$(iptables -L INPUT -n 2>/dev/null | grep "LOG" | grep -E "dpt:22|dpt:3389" || true)
    if [[ -n "$LOG_RULES" ]]; then
        check_result "Management port logging enabled" "true" \
            "LOG rules found for management ports."
    else
        check_result "Management port logging enabled" "false" \
            "No LOG rules for management ports — connections not being recorded."
    fi
elif [[ "$PLATFORM" == "windows" ]]; then
    LOG_STATUS=$(netsh advfirewall show allprofiles logging 2>/dev/null || true)
    if echo "$LOG_STATUS" | grep -qi "enable"; then
        check_result "Management port logging enabled" "true" \
            "Windows Firewall logging is enabled."
    else
        check_result "Management port logging enabled" "false" \
            "Windows Firewall logging is disabled."
    fi
fi

# --- Check 4: Rate Limiting Active (Linux) ---

echo "[*] Check 4: Rate limiting / brute force protection"
echo "---------------------------------------------------"

if [[ "$PLATFORM" == "linux" ]]; then
    RATE_RULES=$(iptables -L INPUT -n 2>/dev/null | grep -E "hashlimit|connlimit" || true)
    if [[ -n "$RATE_RULES" ]]; then
        check_result "Rate limiting active on management ports" "true" \
            "hashlimit or connlimit rules found."
    else
        check_result "Rate limiting active on management ports" "false" \
            "No rate limiting rules — brute force is unthrottled."
    fi
elif [[ "$PLATFORM" == "windows" ]]; then
    # Windows Firewall does not natively support rate limiting
    # Check that deny rules exist as the alternative
    DENY_RULES=$(netsh advfirewall firewall show rule name=all dir=in 2>/dev/null | grep "SC7-FIX.*Deny" || true)
    if [[ -n "$DENY_RULES" ]]; then
        check_result "Deny rules for non-admin traffic" "true" \
            "Explicit deny rules block non-admin management port access."
    else
        check_result "Deny rules for non-admin traffic" "false" \
            "No explicit deny rules found for management ports."
    fi
fi

# --- Check 5: Default Policy (Linux) ---

echo "[*] Check 5: Default INPUT policy"
echo "---------------------------------------------------"

if [[ "$PLATFORM" == "linux" ]]; then
    INPUT_POLICY=$(iptables -L INPUT -n 2>/dev/null | head -1 | grep -oP '\(policy \K[A-Z]+' || echo "UNKNOWN")
    if [[ "$INPUT_POLICY" == "DROP" ]]; then
        check_result "Default INPUT policy is DROP" "true" \
            "Default deny — only explicitly allowed traffic passes."
    else
        check_result "Default INPUT policy is DROP" "false" \
            "Default policy is $INPUT_POLICY — should be DROP for defense-in-depth."
    fi
elif [[ "$PLATFORM" == "windows" ]]; then
    FW_STATE=$(netsh advfirewall show allprofiles state 2>/dev/null | grep -i "State" | head -1 || true)
    if echo "$FW_STATE" | grep -qi "ON"; then
        check_result "Windows Firewall is enabled" "true" \
            "Firewall is active on all profiles."
    else
        check_result "Windows Firewall is enabled" "false" \
            "Firewall may be disabled — check all profiles."
    fi
fi

# --- Validation Report ---

echo "============================================"
echo "Validation Report"
echo "============================================"
echo ""
echo "Date:        $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "Target:      $TARGET"
echo "Admin CIDR:  $ADMIN_CIDR"
echo "Platform:    $PLATFORM"
echo ""
echo "Results:     $PASS_COUNT passed / $FAIL_COUNT failed / $TOTAL_CHECKS total"
echo ""

if [[ "$FAIL_COUNT" -eq 0 ]]; then
    echo "OVERALL: PASS — Firewall is properly configured for SC-7 compliance."
    echo ""
    echo "Management ports are restricted to admin CIDR, logging is active,"
    echo "and rate limiting is in place. This host is no longer exposed to"
    echo "internet-wide brute force or ransomware entry via management ports."
else
    echo "OVERALL: FAIL — Firewall configuration needs additional work."
    echo ""
    echo "Recommended actions:"
    if [[ "$PLATFORM" == "linux" ]]; then
        POLICY=$(iptables -L INPUT -n 2>/dev/null | head -1 | grep -oP '\(policy \K[A-Z]+' || echo "UNKNOWN")
        if [[ "$POLICY" != "DROP" ]]; then
            echo "  - Set default INPUT policy to DROP: iptables -P INPUT DROP"
        fi
    fi
    echo "  - Re-run fix.sh with the correct admin CIDR"
    echo "  - Verify no other rules allow 0.0.0.0/0 on management ports"
fi
echo ""
echo "[*] Evidence saved to: $EVIDENCE_DIR"

# Save report
{
    echo "SC-7 Firewall Misconfiguration Validation Report"
    echo "Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "Target: $TARGET | Admin CIDR: $ADMIN_CIDR | Platform: $PLATFORM"
    echo "Result: $PASS_COUNT/$TOTAL_CHECKS passed"
    echo "Overall: $(if [[ $FAIL_COUNT -eq 0 ]]; then echo PASS; else echo FAIL; fi)"
} > "$EVIDENCE_DIR/validation-report.txt"
