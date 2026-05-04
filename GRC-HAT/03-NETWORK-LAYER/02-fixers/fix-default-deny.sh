#!/usr/bin/env bash
# fix-default-deny.sh — Apply Default-Deny Firewall Policy
# NIST Controls: SC-7 (Boundary Protection), AC-4 (Information Flow Enforcement)
# Platform-aware: Linux iptables / Windows netsh advfirewall
#
# SAFETY: This script detects your current SSH session source IP and
# explicitly allows it before applying DROP policies to prevent lockout.
#
# CSF 2.0: PR.IR-01 (Networks protected)
# CIS v8: 12.8 (Establish Deny-Default Network ACLs)
# NIST: AC-4 (Information Flow Enforcement)
#
set -euo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; NC='\033[0m'; BOLD='\033[1m'

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
EVIDENCE_DIR="/tmp/jsa-evidence/default-deny-${TIMESTAMP}"
mkdir -p "$EVIDENCE_DIR"
LOG="$EVIDENCE_DIR/fix.log"

log() { echo -e "$1" | tee -a "$LOG"; }
log_step() { log "\n${BOLD}[STEP $1]${NC} $2"; }
log_ok()   { log "${GREEN}[OK]${NC}    $1"; }
log_warn() { log "${YELLOW}[WARN]${NC}  $1"; }
log_fail() { log "${RED}[FAIL]${NC}  $1"; }

log "${BOLD}========================================${NC}"
log "${BOLD}Fix: Default-Deny Firewall Policy — NIST SC-7${NC}"
log "Timestamp: $(date)"
log "Evidence: $EVIDENCE_DIR"
log "${BOLD}WARNING: This modifies active firewall rules.${NC}"
log "${BOLD}========================================${NC}"

# ─── Root check ──────────────────────────────────────────────────────────────
if [[ "$(uname -s)" == "Linux" ]] && [[ $EUID -ne 0 ]]; then
  log_fail "Must run as root on Linux (sudo $0)"
  exit 1
fi

# ─── Platform detection ───────────────────────────────────────────────────────
if [[ "$(uname -s)" == "Linux" ]]; then
  PLATFORM="linux"
elif [[ "$(uname -s)" == *"MINGW"* ]] || [[ "$(uname -s)" == *"CYGWIN"* ]]; then
  PLATFORM="windows"
else
  log_warn "Unknown platform — attempting Linux path"
  PLATFORM="linux"
fi

# ─── Linux: iptables default-deny ────────────────────────────────────────────
apply_linux_default_deny() {
  log_step "L1" "Detecting current SSH session source IP"

  # Get SSH client IP — multiple detection methods
  SSH_SRC=""
  if [[ -n "${SSH_CLIENT:-}" ]]; then
    SSH_SRC=$(echo "$SSH_CLIENT" | awk '{print $1}')
    log_ok "SSH_CLIENT: ${SSH_SRC}"
  elif [[ -n "${SSH_CONNECTION:-}" ]]; then
    SSH_SRC=$(echo "$SSH_CONNECTION" | awk '{print $1}')
    log_ok "SSH_CONNECTION: ${SSH_SRC}"
  else
    # Detect via who/last
    SSH_SRC=$(who am i 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo "")
    [[ -n "$SSH_SRC" ]] && log_ok "Detected via who: ${SSH_SRC}"
  fi

  if [[ -z "$SSH_SRC" ]]; then
    log_warn "Could not detect SSH source IP"
    log "  If running locally (console), lockout risk is lower"
    log "  If running over SSH, STOP and verify your client IP before continuing"
    read -rp "  Enter your source IP to whitelist (or press Enter to skip): " MANUAL_IP
    [[ -n "$MANUAL_IP" ]] && SSH_SRC="$MANUAL_IP"
  fi

  log_step "L2" "Capturing pre-fix firewall state"
  iptables -L -n -v --line-numbers > "$EVIDENCE_DIR/iptables-before.txt" 2>&1 || true
  iptables-save > "$EVIDENCE_DIR/iptables-save-before.txt" 2>&1 || true
  log_ok "Pre-fix state saved to $EVIDENCE_DIR/iptables-before.txt"

  log_step "L3" "Preserving ESTABLISHED/RELATED connections (prevent session drop)"
  # Allow already-established connections — prevents current SSH session from dropping
  iptables -C INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
    iptables -I INPUT 1 -m state --state ESTABLISHED,RELATED -j ACCEPT
  log_ok "ESTABLISHED/RELATED INPUT rule in place"

  iptables -C OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
    iptables -I OUTPUT 1 -m state --state ESTABLISHED,RELATED -j ACCEPT
  log_ok "ESTABLISHED/RELATED OUTPUT rule in place"

  log_step "L4" "Whitelisting SSH from current source IP"
  if [[ -n "$SSH_SRC" ]]; then
    iptables -C INPUT -s "$SSH_SRC" -p tcp --dport 22 -j ACCEPT 2>/dev/null || \
      iptables -I INPUT 2 -s "$SSH_SRC" -p tcp --dport 22 -j ACCEPT
    log_ok "SSH allowed from ${SSH_SRC} -> port 22"
  else
    log_warn "No SSH source IP to whitelist — ensure you have console access before proceeding"
    # Always keep loopback
    iptables -C INPUT -i lo -j ACCEPT 2>/dev/null || \
      iptables -I INPUT 1 -i lo -j ACCEPT
  fi

  # Always allow loopback
  iptables -C INPUT -i lo -j ACCEPT 2>/dev/null || \
    iptables -I INPUT 1 -i lo -j ACCEPT
  log_ok "Loopback (lo) always ACCEPT"

  log_step "L5" "Applying default DROP policies — SC-7"
  # SC-7: Default INPUT DROP
  iptables -P INPUT DROP
  log_ok "iptables -P INPUT DROP"

  # SC-7: Default FORWARD DROP
  iptables -P FORWARD DROP
  log_ok "iptables -P FORWARD DROP"

  # OUTPUT policy — ACCEPT by default (apply egress controls separately)
  # Note: Changing OUTPUT to DROP without egress rules breaks most services
  log_warn "OUTPUT policy left at ACCEPT — apply egress rules in fix-management-ports.sh"

  log_step "L6" "Capturing post-fix state"
  iptables -L -n -v --line-numbers > "$EVIDENCE_DIR/iptables-after.txt" 2>&1 || true
  iptables-save > "$EVIDENCE_DIR/iptables-save-after.txt" 2>&1 || true

  # Verify INPUT policy is DROP
  FINAL_POLICY=$(iptables -L INPUT --line-numbers -n 2>/dev/null | head -1 | awk '{print $NF}')
  if [[ "$FINAL_POLICY" == "DROP" ]]; then
    log_ok "Verified: INPUT policy = DROP"
  else
    log_fail "INPUT policy is ${FINAL_POLICY} — apply failed"
    exit 1
  fi

  log_step "L7" "Persisting rules across reboot"
  if command -v iptables-save &>/dev/null; then
    # Try netfilter-persistent (Debian/Ubuntu)
    if command -v netfilter-persistent &>/dev/null; then
      netfilter-persistent save 2>/dev/null && log_ok "Rules saved via netfilter-persistent"
    # Try iptables-save to rules file
    elif [[ -d /etc/iptables ]]; then
      iptables-save > /etc/iptables/rules.v4
      log_ok "Rules saved to /etc/iptables/rules.v4"
    else
      iptables-save > "$EVIDENCE_DIR/iptables-rules-to-persist.txt"
      log_warn "Persistence not configured — save to /etc/iptables/rules.v4 manually"
      log "  iptables-save output in: $EVIDENCE_DIR/iptables-rules-to-persist.txt"
    fi
  fi
}

# ─── Windows: netsh advfirewall ───────────────────────────────────────────────
apply_windows_default_deny() {
  log_step "W1" "Capturing pre-fix Windows Firewall state"

  PS_CMD=$(command -v powershell.exe 2>/dev/null || command -v pwsh 2>/dev/null || echo "")
  if [[ -z "$PS_CMD" ]]; then
    log_fail "PowerShell not found — cannot configure Windows Firewall"
    exit 1
  fi

  "$PS_CMD" -Command "Get-NetFirewallProfile | Select-Object Name,DefaultInboundAction,Enabled | Format-Table" \
    > "$EVIDENCE_DIR/windows-firewall-before.txt" 2>&1 || true
  log_ok "Pre-fix state saved"

  log_step "W2" "Ensuring management access is preserved (RDP/WinRM)"
  # Allow RDP from localhost/admin CIDR before blocking
  netsh advfirewall firewall add rule \
    name="Allow-RDP-Admin-PreFix" \
    dir=in protocol=tcp localport=3389 \
    action=allow remoteip=127.0.0.1 \
    > /dev/null 2>&1 || log_warn "Could not add pre-fix RDP allow rule"

  log_step "W3" "Applying default-deny inbound policy — SC-7"
  # Block inbound on all profiles, allow outbound
  netsh advfirewall set allprofiles firewallpolicy "blockinbound,allowoutbound"
  log_ok "Windows Firewall: BlockInbound,AllowOutbound on all profiles"

  # Verify
  RESULT=$(netsh advfirewall show allprofiles | grep -i "firewall policy" | head -1)
  log "  Policy result: ${RESULT}"

  log_step "W4" "Capturing post-fix state"
  "$PS_CMD" -Command "Get-NetFirewallProfile | Select-Object Name,DefaultInboundAction,Enabled | Format-Table" \
    > "$EVIDENCE_DIR/windows-firewall-after.txt" 2>&1 || true
  log_ok "Post-fix state saved"

  log_warn "RDP rule allows only localhost — add specific admin CIDR via fix-management-ports.sh"
}

# ─── Execute ──────────────────────────────────────────────────────────────────
case "$PLATFORM" in
  linux)   apply_linux_default_deny ;;
  windows) apply_windows_default_deny ;;
esac

# ─── Evidence diff ────────────────────────────────────────────────────────────
log "\n${BOLD}--- Before/After Diff ---${NC}"
if [[ -f "$EVIDENCE_DIR/iptables-before.txt" ]] && [[ -f "$EVIDENCE_DIR/iptables-after.txt" ]]; then
  diff "$EVIDENCE_DIR/iptables-before.txt" "$EVIDENCE_DIR/iptables-after.txt" \
    > "$EVIDENCE_DIR/iptables-diff.txt" 2>&1 || true
  DIFF_LINES=$(wc -l < "$EVIDENCE_DIR/iptables-diff.txt" 2>/dev/null || echo "0")
  log_ok "Diff saved (${DIFF_LINES} lines changed): $EVIDENCE_DIR/iptables-diff.txt"
fi

log "\n${BOLD}========================================${NC}"
log "${BOLD}Default-Deny Fix Complete${NC}"
log "Evidence: $EVIDENCE_DIR"
log "${BOLD}Next step:${NC} Run fix-management-ports.sh to restrict mgmt ports to admin CIDR"
log "${BOLD}========================================${NC}"
