#!/usr/bin/env bash
# audit-firewall-rules.sh — Layer 3 Firewall Rule Audit
# NIST Controls: SC-7 (Boundary Protection), AC-4 (Information Flow Enforcement)
# Dual-stack: iptables / nftables / Windows Firewall / Azure NSG
set -euo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; NC='\033[0m'; BOLD='\033[1m'
PASS="${GREEN}[PASS]${NC}"; WARN="${YELLOW}[WARN]${NC}"; FAIL="${RED}[FAIL]${NC}"

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
EVIDENCE_DIR="/tmp/jsa-evidence/firewall-audit-${TIMESTAMP}"
mkdir -p "$EVIDENCE_DIR"
LOG="$EVIDENCE_DIR/audit.log"

pass_count=0; warn_count=0; fail_count=0

log() { echo -e "$1" | tee -a "$LOG"; }
pass() { log "${PASS} $1"; ((pass_count++)); }
warn() { log "${WARN} $1"; ((warn_count++)); }
fail() { log "${FAIL} $1"; ((fail_count++)); }

log "${BOLD}========================================${NC}"
log "${BOLD}Layer 3 — Firewall Rule Audit${NC}"
log "Timestamp: $(date)"
log "Host: $(hostname)"
log "Evidence: $EVIDENCE_DIR"
log "${BOLD}========================================${NC}"

# ─── Platform Detection ──────────────────────────────────────────────────────
detect_platform() {
  if [[ "$(uname -s)" == "Linux" ]]; then
    if command -v nft &>/dev/null && nft list ruleset 2>/dev/null | grep -q "table"; then
      echo "nftables"
    elif command -v iptables &>/dev/null; then
      echo "iptables"
    else
      echo "linux-unknown"
    fi
  elif [[ "$(uname -s)" == *"MINGW"* ]] || [[ "$(uname -s)" == *"CYGWIN"* ]]; then
    echo "windows"
  elif command -v az &>/dev/null; then
    echo "azure"
  else
    echo "unknown"
  fi
}

PLATFORM=$(detect_platform)
log "\nPlatform detected: ${BOLD}${PLATFORM}${NC}\n"

# ─── iptables Audit ──────────────────────────────────────────────────────────
audit_iptables() {
  log "${BOLD}--- iptables Audit ---${NC}"

  # Save full ruleset as evidence
  iptables -L -n -v --line-numbers > "$EVIDENCE_DIR/iptables-rules.txt" 2>&1 || true
  iptables -t nat -L -n -v >> "$EVIDENCE_DIR/iptables-nat.txt" 2>&1 || true

  # SC-7: Default INPUT policy
  INPUT_POLICY=$(iptables -L INPUT --line-numbers -n 2>/dev/null | head -1 | awk '{print $NF}')
  if [[ "$INPUT_POLICY" == "DROP" ]] || [[ "$INPUT_POLICY" == "REJECT" ]]; then
    pass "SC-7: Default INPUT policy is ${INPUT_POLICY}"
  else
    fail "SC-7: Default INPUT policy is ${INPUT_POLICY} — must be DROP or REJECT"
  fi

  # SC-7: Default FORWARD policy
  FWD_POLICY=$(iptables -L FORWARD --line-numbers -n 2>/dev/null | head -1 | awk '{print $NF}')
  if [[ "$FWD_POLICY" == "DROP" ]] || [[ "$FWD_POLICY" == "REJECT" ]]; then
    pass "SC-7: Default FORWARD policy is ${FWD_POLICY}"
  else
    fail "SC-7: Default FORWARD policy is ${FWD_POLICY} — must be DROP/REJECT on gateways"
  fi

  # SC-7: SSH (22) not exposed to 0.0.0.0/0
  if iptables -L INPUT -n 2>/dev/null | grep -qE "0\.0\.0\.0/0.*dpt:22.*ACCEPT"; then
    fail "SC-7: SSH port 22 is ACCEPT from 0.0.0.0/0 — no source restriction"
  elif iptables -L INPUT -n 2>/dev/null | grep -qE "dpt:22.*ACCEPT"; then
    pass "SC-7: SSH port 22 has source-restricted ACCEPT rule"
  else
    warn "SC-7: No SSH rule found — verify SSH is blocked by default-deny or disabled"
  fi

  # SC-7: RDP (3389) not exposed to 0.0.0.0/0
  if iptables -L INPUT -n 2>/dev/null | grep -qE "0\.0\.0\.0/0.*dpt:3389.*ACCEPT"; then
    fail "SC-7: RDP port 3389 is ACCEPT from 0.0.0.0/0 — no source restriction"
  else
    pass "SC-7: RDP port 3389 not exposed to 0.0.0.0/0"
  fi

  # SC-7: Logging on management ports
  if iptables -L INPUT -n 2>/dev/null | grep -qE "dpt:22.*LOG"; then
    pass "SC-7: SSH connection logging rule exists"
  else
    warn "SC-7: No LOG rule for SSH port 22 — blind to brute force attempts"
  fi

  # SC-7: Rate limiting on SSH
  if iptables -L INPUT -n 2>/dev/null | grep -qE "dpt:22.*(limit|recent|state)"; then
    pass "SC-7: Rate limiting or state tracking on SSH port 22"
  else
    warn "SC-7: No rate limiting on SSH port 22 — brute force not throttled"
  fi

  # SC-7: Egress filtering
  OUTPUT_POLICY=$(iptables -L OUTPUT --line-numbers -n 2>/dev/null | head -1 | awk '{print $NF}')
  if [[ "$OUTPUT_POLICY" == "DROP" ]] || [[ "$OUTPUT_POLICY" == "REJECT" ]]; then
    pass "SC-7: Egress filtering enabled (OUTPUT policy: ${OUTPUT_POLICY})"
  else
    warn "SC-7: No egress filtering (OUTPUT policy: ${OUTPUT_POLICY}) — exfiltration uncontrolled"
  fi

  # Look for any unrestricted ACCEPT rules
  OPEN_RULES=$(iptables -L INPUT -n 2>/dev/null | grep -cE "0\.0\.0\.0/0.*ACCEPT" || true)
  if [[ "$OPEN_RULES" -gt 2 ]]; then
    warn "SC-7: ${OPEN_RULES} rules accepting traffic from 0.0.0.0/0 — review for over-permissiveness"
    iptables -L INPUT -n 2>/dev/null | grep -E "0\.0\.0\.0/0.*ACCEPT" >> "$EVIDENCE_DIR/open-rules.txt" || true
  fi
}

# ─── nftables Audit ──────────────────────────────────────────────────────────
audit_nftables() {
  log "${BOLD}--- nftables Audit ---${NC}"

  nft list ruleset > "$EVIDENCE_DIR/nftables-ruleset.txt" 2>&1 || true

  # Check for default drop policy
  if grep -qE "policy drop|type filter hook input.*drop" "$EVIDENCE_DIR/nftables-ruleset.txt" 2>/dev/null; then
    pass "SC-7: nftables default drop policy found"
  else
    fail "SC-7: No default drop policy in nftables ruleset"
  fi

  # SSH restriction
  if grep -qE "tcp dport 22" "$EVIDENCE_DIR/nftables-ruleset.txt" 2>/dev/null; then
    if grep -qE "saddr.*tcp dport 22.*accept" "$EVIDENCE_DIR/nftables-ruleset.txt" 2>/dev/null; then
      pass "SC-7: SSH port 22 has source-restricted accept rule"
    else
      warn "SC-7: SSH port 22 rule exists but source restriction not confirmed — review manually"
    fi
  else
    warn "SC-7: No explicit SSH rule in nftables — verify default policy covers it"
  fi

  # Logging
  if grep -q "log" "$EVIDENCE_DIR/nftables-ruleset.txt" 2>/dev/null; then
    pass "SC-7: Logging statements found in nftables ruleset"
  else
    warn "SC-7: No logging found in nftables ruleset"
  fi
}

# ─── Windows Firewall Audit (via PowerShell) ─────────────────────────────────
audit_windows_firewall() {
  log "${BOLD}--- Windows Firewall Audit ---${NC}"

  # Run via PowerShell if available
  if ! command -v powershell.exe &>/dev/null && ! command -v pwsh &>/dev/null; then
    warn "PowerShell not found — cannot audit Windows Firewall"
    return
  fi
  PS_CMD=$(command -v powershell.exe 2>/dev/null || command -v pwsh 2>/dev/null)

  # Default inbound policy
  "$PS_CMD" -Command "Get-NetFirewallProfile | Select-Object Name,DefaultInboundAction,DefaultOutboundAction | Format-Table" \
    > "$EVIDENCE_DIR/windows-firewall-profiles.txt" 2>&1 || true

  if grep -qi "Block" "$EVIDENCE_DIR/windows-firewall-profiles.txt" 2>/dev/null; then
    pass "SC-7: Windows Firewall has Block policy on at least one profile"
  else
    fail "SC-7: Windows Firewall DefaultInboundAction is not Block on any profile"
  fi

  # RDP restriction
  "$PS_CMD" -Command "Get-NetFirewallRule -DisplayName '*Remote Desktop*' | Select-Object DisplayName,Enabled,Direction,Action,Profile | Format-Table" \
    > "$EVIDENCE_DIR/windows-rdp-rules.txt" 2>&1 || true

  if grep -qi "Inbound" "$EVIDENCE_DIR/windows-rdp-rules.txt" 2>/dev/null; then
    warn "SC-7: RDP inbound rules present — verify RemoteAddress restriction is not 'Any'"
  else
    pass "SC-7: No unrestricted RDP rules found"
  fi

  # Logging enabled
  "$PS_CMD" -Command "Get-NetFirewallProfile | Select-Object Name,LogAllowed,LogBlocked,LogFileName | Format-Table" \
    > "$EVIDENCE_DIR/windows-firewall-logging.txt" 2>&1 || true

  if grep -qi "True" "$EVIDENCE_DIR/windows-firewall-logging.txt" 2>/dev/null; then
    pass "SC-7: Windows Firewall logging is enabled"
  else
    warn "SC-7: Windows Firewall logging may not be enabled for all profiles"
  fi
}

# ─── Azure NSG Audit ─────────────────────────────────────────────────────────
audit_azure_nsg() {
  log "${BOLD}--- Azure NSG Audit (az cli) ---${NC}"

  if ! command -v az &>/dev/null; then
    warn "az CLI not found — skipping Azure NSG audit"
    return
  fi

  if ! az account show &>/dev/null; then
    warn "Not authenticated to Azure — run 'az login' first"
    return
  fi

  # List all NSGs
  az network nsg list --output table > "$EVIDENCE_DIR/azure-nsgs.txt" 2>&1 || true

  NSG_COUNT=$(az network nsg list --query "length(@)" -o tsv 2>/dev/null || echo "0")
  if [[ "$NSG_COUNT" -gt 0 ]]; then
    log "Found ${NSG_COUNT} NSG(s)"
  else
    warn "SC-7: No NSGs found in current subscription/resource group"
    return
  fi

  # Check each NSG for unrestricted management port rules
  az network nsg list --query "[].{name:name,rg:resourceGroup}" -o tsv 2>/dev/null | \
  while IFS=$'\t' read -r NSG_NAME RG; do
    log "Checking NSG: ${NSG_NAME} (RG: ${RG})"

    az network nsg rule list --nsg-name "$NSG_NAME" -g "$RG" \
      --query "[?destinationPortRange=='22' || destinationPortRange=='3389']" \
      --output table > "$EVIDENCE_DIR/nsg-mgmt-rules-${NSG_NAME}.txt" 2>&1 || true

    # Check for rules allowing * from * on management ports
    OPEN_MGMT=$(az network nsg rule list --nsg-name "$NSG_NAME" -g "$RG" \
      --query "[?((destinationPortRange=='22' || destinationPortRange=='3389') && sourceAddressPrefix=='*' && access=='Allow')].name" \
      -o tsv 2>/dev/null || echo "")

    if [[ -n "$OPEN_MGMT" ]]; then
      fail "SC-7: NSG ${NSG_NAME} has management port open to '*' (any source): ${OPEN_MGMT}"
    else
      pass "SC-7: NSG ${NSG_NAME} management ports not open to wildcard source"
    fi

    # Check NSG flow logs
    FLOW_LOG=$(az network watcher flow-log list --location "$(az network nsg show -g "$RG" -n "$NSG_NAME" --query location -o tsv 2>/dev/null)" \
      --query "[?contains(storageId, '$(echo "$NSG_NAME" | tr '[:upper:]' '[:lower:]')')].enabled" \
      -o tsv 2>/dev/null || echo "")
    if [[ "$FLOW_LOG" == "true" ]]; then
      pass "SC-7: NSG flow logs enabled for ${NSG_NAME}"
    else
      warn "SC-7: NSG flow logs not confirmed for ${NSG_NAME} — verify in Azure portal"
    fi
  done
}

# ─── Run audit based on platform ─────────────────────────────────────────────
case "$PLATFORM" in
  iptables)    audit_iptables ;;
  nftables)    audit_nftables ;;
  windows)     audit_windows_firewall ;;
  azure)       audit_azure_nsg ;;
  *)
    log "Unknown platform — attempting iptables, then nftables"
    if command -v iptables &>/dev/null; then audit_iptables
    elif command -v nft &>/dev/null; then audit_nftables
    else warn "No supported firewall tool found"; fi
    ;;
esac

# ─── Summary ─────────────────────────────────────────────────────────────────
log "\n${BOLD}========================================${NC}"
log "${BOLD}Summary${NC}"
log "  ${GREEN}PASS${NC}: ${pass_count}"
log "  ${YELLOW}WARN${NC}: ${warn_count}"
log "  ${RED}FAIL${NC}: ${fail_count}"
log "Evidence: $EVIDENCE_DIR"
log "${BOLD}========================================${NC}"

if [[ $fail_count -gt 0 ]]; then
  log "\n${RED}CRITICAL: ${fail_count} SC-7 control failure(s). Remediate before next audit.${NC}"
  exit 1
fi
exit 0
