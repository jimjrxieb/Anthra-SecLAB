#!/usr/bin/env bash
# audit-network-segmentation.sh — Network Segmentation Audit
# NIST Controls: AC-4 (Information Flow), SC-7 (Boundary Protection)
# Dual-platform: Linux (ip route) + Windows (route print / PowerShell)
set -euo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; NC='\033[0m'; BOLD='\033[1m'
PASS="${GREEN}[PASS]${NC}"; WARN="${YELLOW}[WARN]${NC}"; FAIL="${RED}[FAIL]${NC}"

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
EVIDENCE_DIR="/tmp/jsa-evidence/segmentation-audit-${TIMESTAMP}"
mkdir -p "$EVIDENCE_DIR"
LOG="$EVIDENCE_DIR/audit.log"

pass_count=0; warn_count=0; fail_count=0

log() { echo -e "$1" | tee -a "$LOG"; }
pass() { log "${PASS} $1"; ((pass_count++)); }
warn() { log "${WARN} $1"; ((warn_count++)); }
fail() { log "${FAIL} $1"; ((fail_count++)); }

log "${BOLD}========================================${NC}"
log "${BOLD}Layer 3 — Network Segmentation Audit${NC}"
log "Timestamp: $(date)"
log "Host: $(hostname)"
log "Evidence: $EVIDENCE_DIR"
log "${BOLD}========================================${NC}"

IS_LINUX=false; IS_WINDOWS=false
[[ "$(uname -s)" == "Linux" ]] && IS_LINUX=true
[[ "$(uname -s)" == *"MINGW"* ]] || [[ "$(uname -s)" == *"CYGWIN"* ]] && IS_WINDOWS=true

# ─── Linux: Routing and Subnet Analysis ─────────────────────────────────────
if $IS_LINUX; then
  log "\n${BOLD}--- Linux Routing Table ---${NC}"
  ip route show > "$EVIDENCE_DIR/ip-route.txt" 2>&1 || route -n > "$EVIDENCE_DIR/ip-route.txt" 2>&1 || true
  ip addr show > "$EVIDENCE_DIR/ip-addr.txt" 2>&1 || true

  # Count distinct subnets reachable via interface (not default route)
  SUBNET_COUNT=$(ip route show 2>/dev/null | grep -vE "^default" | grep -cE "^[0-9]" || echo "0")

  if [[ $SUBNET_COUNT -ge 3 ]]; then
    pass "AC-4: Multiple subnets detected (${SUBNET_COUNT} routes) — segmentation present"
  elif [[ $SUBNET_COUNT -eq 2 ]]; then
    warn "AC-4: Only 2 subnets detected — minimal segmentation, verify zone isolation"
  elif [[ $SUBNET_COUNT -eq 1 ]]; then
    fail "AC-4: Single subnet detected — flat network with no segmentation"
    log "  Recommendation: Implement VLANs/subnets for DMZ, management, user, server zones"
  else
    warn "AC-4: Could not determine subnet count — check ip route output manually"
  fi

  # Check for interface count (multiple NICs = potential zone boundary)
  NIC_COUNT=$(ip link show 2>/dev/null | grep -c "^[0-9]" || echo "0")
  if [[ $NIC_COUNT -ge 3 ]]; then
    pass "AC-4: ${NIC_COUNT} network interfaces detected — gateway-style host with multiple zones"
  else
    log "  Network interfaces: ${NIC_COUNT}"
  fi

  log "\n${BOLD}--- Cross-Zone Deny Rules ---${NC}"
  # Check iptables FORWARD chain for cross-zone deny rules
  if command -v iptables &>/dev/null; then
    FORWARD_RULES=$(iptables -L FORWARD -n 2>/dev/null || echo "")
    echo "$FORWARD_RULES" > "$EVIDENCE_DIR/forward-rules.txt"

    FWD_POLICY=$(echo "$FORWARD_RULES" | head -1 | awk '{print $NF}')
    if [[ "$FWD_POLICY" == "DROP" ]]; then
      pass "AC-4: FORWARD chain default policy is DROP — cross-zone traffic denied by default"
    else
      fail "AC-4: FORWARD chain policy is ${FWD_POLICY} — cross-zone traffic not denied by default"
    fi

    # Check for explicit inter-zone deny rules
    if echo "$FORWARD_RULES" | grep -qE "DROP|REJECT"; then
      pass "AC-4: Explicit DROP/REJECT rules present in FORWARD chain"
    else
      warn "AC-4: No explicit cross-zone deny rules in FORWARD chain — relying on default policy only"
    fi
  elif command -v nft &>/dev/null; then
    nft list ruleset 2>/dev/null | grep -A 20 "forward" > "$EVIDENCE_DIR/nft-forward.txt" || true
    if grep -q "drop\|reject" "$EVIDENCE_DIR/nft-forward.txt" 2>/dev/null; then
      pass "AC-4: nftables forward chain has drop/reject rules"
    else
      warn "AC-4: nftables forward chain deny rules not confirmed"
    fi
  else
    warn "AC-4: No firewall tool found to check cross-zone rules"
  fi

  log "\n${BOLD}--- Flat Network Detection ---${NC}"
  # Flat network = single /8, /16, /24 covering everything with no segmentation
  DEFAULT_IFACE=$(ip route show default 2>/dev/null | awk '/dev/ {for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -1)
  if [[ -n "$DEFAULT_IFACE" ]]; then
    LOCAL_SUBNETS=$(ip addr show dev "$DEFAULT_IFACE" 2>/dev/null | grep "inet " | awk '{print $2}')
    echo "Default interface ${DEFAULT_IFACE} subnets: ${LOCAL_SUBNETS}" >> "$EVIDENCE_DIR/flat-network-check.txt"

    # If only one subnet and it's a /8, likely flat
    if echo "$LOCAL_SUBNETS" | grep -qE "/8$"; then
      fail "AC-4: Host is on a /8 network — extremely flat, no meaningful segmentation"
    elif [[ $SUBNET_COUNT -le 1 ]]; then
      fail "AC-4: Only one routable subnet — flat network"
    else
      pass "AC-4: Multiple subnets, not a flat /8 network"
    fi
  fi
fi

# ─── Windows: Route and Segmentation Analysis ───────────────────────────────
if $IS_WINDOWS || command -v powershell.exe &>/dev/null || command -v pwsh &>/dev/null; then
  PS_CMD=$(command -v powershell.exe 2>/dev/null || command -v pwsh 2>/dev/null || echo "")
  if [[ -n "$PS_CMD" ]]; then
    log "\n${BOLD}--- Windows Routing Table ---${NC}"

    "$PS_CMD" -Command "Get-NetRoute | Select-Object DestinationPrefix,NextHop,InterfaceAlias,RouteMetric | Format-Table" \
      > "$EVIDENCE_DIR/windows-routes.txt" 2>&1 || true

    WIN_SUBNET_COUNT=$(grep -cE "^\d+\.\d+\.\d+\.\d+/[0-9]+" "$EVIDENCE_DIR/windows-routes.txt" 2>/dev/null || echo "0")
    if [[ $WIN_SUBNET_COUNT -ge 3 ]]; then
      pass "AC-4: Windows routing table shows ${WIN_SUBNET_COUNT} network routes"
    else
      warn "AC-4: Only ${WIN_SUBNET_COUNT} routes in Windows routing table — verify segmentation"
    fi

    "$PS_CMD" -Command "Get-NetAdapter | Select-Object Name,Status,LinkSpeed | Format-Table" \
      > "$EVIDENCE_DIR/windows-adapters.txt" 2>&1 || true
  fi
fi

# ─── K8s NetworkPolicy Check ─────────────────────────────────────────────────
log "\n${BOLD}--- Kubernetes NetworkPolicy ---${NC}"
if command -v kubectl &>/dev/null; then
  if kubectl cluster-info &>/dev/null 2>&1; then
    # Count NetworkPolicies across all namespaces
    NP_COUNT=$(kubectl get networkpolicy --all-namespaces --no-headers 2>/dev/null | wc -l || echo "0")
    kubectl get networkpolicy --all-namespaces -o wide > "$EVIDENCE_DIR/k8s-networkpolicies.txt" 2>&1 || true

    if [[ $NP_COUNT -ge 1 ]]; then
      pass "AC-4: ${NP_COUNT} Kubernetes NetworkPolicy resource(s) found"

      # Check for default-deny policies
      DEFAULT_DENY=$(kubectl get networkpolicy --all-namespaces -o json 2>/dev/null | \
        python3 -c "
import sys, json
data = json.load(sys.stdin)
count = 0
for item in data.get('items', []):
    spec = item.get('spec', {})
    if spec.get('podSelector', {}) == {} and 'Ingress' in spec.get('policyTypes', []) and 'Egress' in spec.get('policyTypes', []):
        count += 1
print(count)
" 2>/dev/null || echo "0")

      if [[ "$DEFAULT_DENY" -ge 1 ]]; then
        pass "AC-4: ${DEFAULT_DENY} default-deny NetworkPolicy found (blocks all ingress+egress by default)"
      else
        warn "AC-4: No default-deny-all NetworkPolicy detected — pods may communicate freely"
        log "  Apply: kubectl apply -f 03-templates/network-policies/default-deny.yaml"
      fi
    else
      fail "AC-4: No Kubernetes NetworkPolicies found — all pods can communicate freely (flat cluster network)"
    fi

    # Check for namespaces without any policy
    NAMESPACES=$(kubectl get namespaces --no-headers -o custom-columns=NAME:.metadata.name 2>/dev/null || echo "")
    UNPROTECTED=0
    while IFS= read -r NS; do
      [[ -z "$NS" ]] && continue
      [[ "$NS" =~ ^(kube-system|kube-public|kube-node-lease)$ ]] && continue
      NP_IN_NS=$(kubectl get networkpolicy -n "$NS" --no-headers 2>/dev/null | wc -l || echo "0")
      if [[ $NP_IN_NS -eq 0 ]]; then
        ((UNPROTECTED++))
        log "  ${WARN} Namespace '${NS}' has no NetworkPolicy"
      fi
    done <<< "$NAMESPACES"

    if [[ $UNPROTECTED -gt 0 ]]; then
      warn "AC-4: ${UNPROTECTED} namespace(s) have no NetworkPolicy applied"
    else
      pass "AC-4: All non-system namespaces have NetworkPolicy coverage"
    fi
  else
    log "  kubectl available but no cluster connection — skipping K8s checks"
  fi
else
  log "  kubectl not available — skipping Kubernetes NetworkPolicy audit"
fi

# ─── Segment Validation Summary ──────────────────────────────────────────────
log "\n${BOLD}--- Segmentation Evidence Summary ---${NC}"
log "  Routing data: $EVIDENCE_DIR/ip-route.txt"
log "  Interface data: $EVIDENCE_DIR/ip-addr.txt"
[[ -f "$EVIDENCE_DIR/k8s-networkpolicies.txt" ]] && log "  K8s policies: $EVIDENCE_DIR/k8s-networkpolicies.txt"

# ─── Summary ─────────────────────────────────────────────────────────────────
log "\n${BOLD}========================================${NC}"
log "${BOLD}Summary${NC}"
log "  ${GREEN}PASS${NC}: ${pass_count}"
log "  ${YELLOW}WARN${NC}: ${warn_count}"
log "  ${RED}FAIL${NC}: ${fail_count}"
log "Evidence: $EVIDENCE_DIR"
log "${BOLD}========================================${NC}"

if [[ $fail_count -gt 0 ]]; then
  log "\n${RED}CRITICAL: Flat network or missing segmentation. AC-4 controls not met.${NC}"
  exit 1
fi
exit 0
