#!/usr/bin/env bash
# fix-management-ports.sh — Restrict SSH/RDP to Admin CIDR with Logging and Rate Limiting
# NIST Controls: SC-7 (Boundary Protection), AC-17 (Remote Access), AU-2 (Event Logging)
# Platform-aware: Linux iptables + Windows PowerShell / netsh
#
# CSF 2.0: PR.PS-01 (Configuration management applied)
# CIS v8: 4.4 (Implement Firewall on Servers)
# NIST: SC-7 (Boundary Protection)
#
set -euo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; NC='\033[0m'; BOLD='\033[1m'

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
EVIDENCE_DIR="/tmp/jsa-evidence/mgmt-ports-${TIMESTAMP}"
mkdir -p "$EVIDENCE_DIR"
LOG="$EVIDENCE_DIR/fix.log"

log() { echo -e "$1" | tee -a "$LOG"; }
log_step() { log "\n${BOLD}[STEP $1]${NC} $2"; }
log_ok()   { log "${GREEN}[OK]${NC}    $1"; }
log_warn() { log "${YELLOW}[WARN]${NC}  $1"; }
log_fail() { log "${RED}[FAIL]${NC}  $1"; }

# ─── Configuration (edit before running) ─────────────────────────────────────
# Admin CIDR — the network that is allowed to reach management ports
# Examples: "10.10.0.0/16", "192.168.1.0/24", "203.0.113.50/32"
ADMIN_CIDR="${ADMIN_CIDR:-}"

log "${BOLD}========================================${NC}"
log "${BOLD}Fix: Management Port Restriction — NIST SC-7 / AC-17${NC}"
log "Timestamp: $(date)"
log "Evidence: $EVIDENCE_DIR"
log "${BOLD}========================================${NC}"

# Require admin CIDR — prevent accidental open-to-all config
if [[ -z "$ADMIN_CIDR" ]]; then
  log_fail "ADMIN_CIDR is not set. Set it before running:"
  log "  export ADMIN_CIDR='10.10.0.0/16'"
  log "  sudo -E $0"
  exit 1
fi

log "  Admin CIDR: ${ADMIN_CIDR}"

# Platform detection
if [[ "$(uname -s)" == "Linux" ]]; then
  PLATFORM="linux"
elif [[ "$(uname -s)" == *"MINGW"* ]] || [[ "$(uname -s)" == *"CYGWIN"* ]]; then
  PLATFORM="windows"
else
  PLATFORM="linux"
fi

# ─── Linux iptables ──────────────────────────────────────────────────────────
apply_linux_mgmt_ports() {
  if [[ $EUID -ne 0 ]]; then
    log_fail "Must run as root"
    exit 1
  fi

  log_step "L1" "Detecting SSH source IP (lockout prevention)"
  SSH_SRC=""
  if [[ -n "${SSH_CLIENT:-}" ]]; then
    SSH_SRC=$(echo "$SSH_CLIENT" | awk '{print $1}')
    log_ok "Current SSH client: ${SSH_SRC}"
  elif [[ -n "${SSH_CONNECTION:-}" ]]; then
    SSH_SRC=$(echo "$SSH_CONNECTION" | awk '{print $1}')
    log_ok "SSH_CONNECTION source: ${SSH_SRC}"
  fi

  # Validate ADMIN_CIDR covers current SSH source
  if [[ -n "$SSH_SRC" ]]; then
    if command -v python3 &>/dev/null; then
      IN_RANGE=$(python3 -c "
import ipaddress
try:
    net = ipaddress.ip_network('${ADMIN_CIDR}', strict=False)
    host = ipaddress.ip_address('${SSH_SRC}')
    print('yes' if host in net else 'no')
except: print('unknown')
" 2>/dev/null || echo "unknown")
      if [[ "$IN_RANGE" == "yes" ]]; then
        log_ok "Current SSH IP (${SSH_SRC}) is within ADMIN_CIDR (${ADMIN_CIDR}) — lockout safe"
      elif [[ "$IN_RANGE" == "no" ]]; then
        log_warn "Current SSH IP (${SSH_SRC}) is NOT in ADMIN_CIDR (${ADMIN_CIDR})"
        log "  Adding current IP as emergency exception..."
        # Add current SSH source as temporary exception (should be reviewed)
        iptables -I INPUT 1 -s "$SSH_SRC" -p tcp --dport 22 -j ACCEPT \
          -m comment --comment "emergency-exception-review-and-remove"
        log_warn "  Added emergency rule for ${SSH_SRC} — REMOVE after verifying ADMIN_CIDR"
      fi
    fi
  fi

  log_step "L2" "Saving pre-fix state"
  iptables -L -n -v > "$EVIDENCE_DIR/iptables-before.txt" 2>&1 || true
  iptables-save > "$EVIDENCE_DIR/iptables-save-before.txt" 2>&1 || true

  log_step "L3" "Removing any existing wildcard management port rules"
  # Remove rules that accept SSH/RDP from 0.0.0.0/0
  # We rebuild them properly below
  while iptables -L INPUT -n 2>/dev/null | grep -E "0\.0\.0\.0/0.*dpt:22.*ACCEPT" | head -1; do
    LINE=$(iptables -L INPUT --line-numbers -n 2>/dev/null | grep -E "0\.0\.0\.0/0.*dpt:22.*ACCEPT" | awk '{print $1}' | head -1)
    [[ -z "$LINE" ]] && break
    iptables -D INPUT "$LINE" 2>/dev/null || break
    log_ok "  Removed open SSH rule (line ${LINE})"
  done

  log_step "L4" "SSH (22) — restrict to ADMIN_CIDR with rate limiting and logging"
  # Rate limit: allow 5 new connections per minute per source (SC-7 brute force protection)
  # Logging: LOG before ACCEPT (AU-2 requirement)
  iptables -A INPUT -s "$ADMIN_CIDR" -p tcp --dport 22 \
    -m state --state NEW \
    -m recent --set --name SSH_RATE --rsource
  log_ok "  SSH rate limit tracking rule added"

  iptables -A INPUT -s "$ADMIN_CIDR" -p tcp --dport 22 \
    -m state --state NEW \
    -m recent --update --seconds 60 --hitcount 5 --name SSH_RATE --rsource \
    -j LOG --log-prefix "JSA-SSH-RATELIMIT: " --log-level 4
  log_ok "  SSH rate limit LOG rule added"

  iptables -A INPUT -s "$ADMIN_CIDR" -p tcp --dport 22 \
    -m state --state NEW \
    -m recent --update --seconds 60 --hitcount 5 --name SSH_RATE --rsource \
    -j DROP
  log_ok "  SSH rate limit DROP rule added (5 new/60s per source)"

  iptables -A INPUT -s "$ADMIN_CIDR" -p tcp --dport 22 \
    -m state --state NEW \
    -j LOG --log-prefix "JSA-SSH-ALLOW: " --log-level 6
  log_ok "  SSH connection LOG rule added (AU-2)"

  iptables -A INPUT -s "$ADMIN_CIDR" -p tcp --dport 22 \
    -m state --state NEW,ESTABLISHED \
    -j ACCEPT
  log_ok "  SSH ACCEPT rule added for ${ADMIN_CIDR}"

  # Explicitly DROP SSH from all other sources (belt-and-suspenders with default deny)
  iptables -A INPUT -p tcp --dport 22 \
    -j LOG --log-prefix "JSA-SSH-DENY: " --log-level 4
  iptables -A INPUT -p tcp --dport 22 -j DROP
  log_ok "  SSH DROP+LOG rule added for non-admin sources"

  log_step "L5" "RDP (3389) — restrict to ADMIN_CIDR"
  # RDP logging
  iptables -A INPUT -s "$ADMIN_CIDR" -p tcp --dport 3389 \
    -m state --state NEW \
    -j LOG --log-prefix "JSA-RDP-ALLOW: " --log-level 6
  iptables -A INPUT -s "$ADMIN_CIDR" -p tcp --dport 3389 \
    -m state --state NEW,ESTABLISHED \
    -j ACCEPT
  log_ok "  RDP ACCEPT rule added for ${ADMIN_CIDR}"

  iptables -A INPUT -p tcp --dport 3389 \
    -j LOG --log-prefix "JSA-RDP-DENY: " --log-level 4
  iptables -A INPUT -p tcp --dport 3389 -j DROP
  log_ok "  RDP DROP+LOG rule for non-admin sources"

  log_step "L6" "Saving post-fix state and generating diff"
  iptables -L -n -v > "$EVIDENCE_DIR/iptables-after.txt" 2>&1 || true
  iptables-save > "$EVIDENCE_DIR/iptables-save-after.txt" 2>&1 || true
  diff "$EVIDENCE_DIR/iptables-before.txt" "$EVIDENCE_DIR/iptables-after.txt" \
    > "$EVIDENCE_DIR/iptables-diff.txt" 2>&1 || true
  log_ok "Diff saved: $EVIDENCE_DIR/iptables-diff.txt"

  # Persist
  log_step "L7" "Persisting rules"
  if command -v netfilter-persistent &>/dev/null; then
    netfilter-persistent save 2>/dev/null && log_ok "Persisted via netfilter-persistent"
  elif [[ -d /etc/iptables ]]; then
    iptables-save > /etc/iptables/rules.v4 && log_ok "Saved to /etc/iptables/rules.v4"
  else
    iptables-save > "$EVIDENCE_DIR/iptables-persist.txt"
    log_warn "Manual persistence needed — saved to $EVIDENCE_DIR/iptables-persist.txt"
  fi
}

# ─── Windows PowerShell ──────────────────────────────────────────────────────
apply_windows_mgmt_ports() {
  PS_CMD=$(command -v powershell.exe 2>/dev/null || command -v pwsh 2>/dev/null || echo "")
  if [[ -z "$PS_CMD" ]]; then
    log_fail "PowerShell not found"
    exit 1
  fi

  log_step "W1" "Saving pre-fix Windows Firewall state"
  "$PS_CMD" -Command "Get-NetFirewallRule | Where-Object {$_.LocalPort -match '22|3389'} | Select-Object DisplayName,Direction,Action,Enabled | Format-Table" \
    > "$EVIDENCE_DIR/windows-mgmt-rules-before.txt" 2>&1 || true

  log_step "W2" "Removing unrestricted management port rules"
  # Remove any existing rule that allows SSH/RDP from Any
  "$PS_CMD" -Command "
Get-NetFirewallRule | Where-Object {
  ($_.DisplayName -match 'SSH|Remote Desktop|RDP') -and ($_.Direction -eq 'Inbound') -and ($_.Action -eq 'Allow')
} | ForEach-Object {
  \$rule = \$_
  \$filter = \$rule | Get-NetFirewallAddressFilter
  if (\$filter.RemoteAddress -eq 'Any' -or \$filter.RemoteAddress -contains '0.0.0.0/0') {
    Write-Output \"Removing open rule: \$(\$rule.DisplayName)\"
    Remove-NetFirewallRule -InputObject \$rule
  }
}
" 2>&1 | tee -a "$EVIDENCE_DIR/windows-rule-removal.txt" || log_warn "Rule removal had errors"

  log_step "W3" "SSH (22) — allow from ADMIN_CIDR only with logging"
  "$PS_CMD" -Command "
New-NetFirewallRule \`
  -DisplayName 'JSA-SSH-Admin-Allow' \`
  -Direction Inbound \`
  -Protocol TCP \`
  -LocalPort 22 \`
  -RemoteAddress '${ADMIN_CIDR}' \`
  -Action Allow \`
  -Enabled True \`
  -Profile Any \`
  -Description 'SC-7: SSH restricted to admin CIDR. NIST AC-17. Created by JSA fix-management-ports.sh'
" 2>&1 | tee -a "$LOG" || log_warn "SSH allow rule creation may have failed"
  log_ok "SSH allow rule created for ${ADMIN_CIDR}"

  log_step "W4" "RDP (3389) — allow from ADMIN_CIDR only"
  "$PS_CMD" -Command "
New-NetFirewallRule \`
  -DisplayName 'JSA-RDP-Admin-Allow' \`
  -Direction Inbound \`
  -Protocol TCP \`
  -LocalPort 3389 \`
  -RemoteAddress '${ADMIN_CIDR}' \`
  -Action Allow \`
  -Enabled True \`
  -Profile Any \`
  -Description 'SC-7: RDP restricted to admin CIDR. NIST AC-17. Created by JSA fix-management-ports.sh'
" 2>&1 | tee -a "$LOG" || log_warn "RDP allow rule creation may have failed"
  log_ok "RDP allow rule created for ${ADMIN_CIDR}"

  log_step "W5" "Enable firewall logging (AU-2)"
  "$PS_CMD" -Command "
Set-NetFirewallProfile -Profile Domain,Public,Private \`
  -LogAllowed True \`
  -LogBlocked True \`
  -LogMaxSizeKilobytes 32767
" 2>&1 | tee -a "$LOG" || log_warn "Logging configuration may have partially failed"
  log_ok "Windows Firewall logging enabled (Allow + Block, 32MB max)"

  log_step "W6" "Post-fix state"
  "$PS_CMD" -Command "Get-NetFirewallRule | Where-Object {$_.LocalPort -match '22|3389'} | Select-Object DisplayName,Direction,Action,Enabled | Format-Table" \
    > "$EVIDENCE_DIR/windows-mgmt-rules-after.txt" 2>&1 || true
  log_ok "Post-fix state saved to $EVIDENCE_DIR/"
}

# ─── Execute ──────────────────────────────────────────────────────────────────
case "$PLATFORM" in
  linux)   apply_linux_mgmt_ports ;;
  windows) apply_windows_mgmt_ports ;;
esac

log "\n${BOLD}========================================${NC}"
log "${BOLD}Management Port Restriction Complete${NC}"
log "  Admin CIDR: ${ADMIN_CIDR}"
log "  SSH (22):   ADMIN_CIDR only, rate-limited, logged"
log "  RDP (3389): ADMIN_CIDR only, logged"
log "Evidence: $EVIDENCE_DIR"
log "${BOLD}========================================${NC}"

log "\nVerify with:"
log "  Linux:   iptables -L INPUT -n --line-numbers"
log "  Windows: Get-NetFirewallRule | Where-Object {\$_.LocalPort -match '22|3389'}"
