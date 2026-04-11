#!/usr/bin/env bash
# audit-service-accounts.sh — L5 Session Layer K8s service account security audit
# NIST: AC-2 (account management), AC-6 (least privilege), IA-2 (identification/authentication)
# Usage: ./audit-service-accounts.sh [namespace]
set -euo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; NC='\033[0m'
PASS() { echo -e "${GREEN}[PASS]${NC} $*"; }
WARN() { echo -e "${YELLOW}[WARN]${NC} $*"; }
FAIL() { echo -e "${RED}[FAIL]${NC} $*"; }
INFO() { echo -e "       $*"; }

NAMESPACE="${1:-}"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
EVIDENCE_DIR="/tmp/jsa-evidence/sa-audit-${TIMESTAMP}"
mkdir -p "$EVIDENCE_DIR"

echo "======================================================"
echo " L5 Service Account Audit — AC-2 / AC-6 / IA-2"
echo " Evidence: ${EVIDENCE_DIR}"
echo " $(date)"
echo "======================================================"
echo ""

FINDINGS=0

# ─── 1. Inventory all service accounts ───────────────────────────────────
echo "── 1. Service Account Inventory ─────────────────────────────────────"
if [[ -n "$NAMESPACE" ]]; then
    SA_OUTPUT=$(kubectl get serviceaccounts -n "${NAMESPACE}" -o json 2>/dev/null)
    INFO "Scope: namespace=${NAMESPACE}"
else
    SA_OUTPUT=$(kubectl get serviceaccounts --all-namespaces -o json 2>/dev/null)
    INFO "Scope: all namespaces"
fi
echo "$SA_OUTPUT" > "${EVIDENCE_DIR}/serviceaccounts-raw.json"

SA_COUNT=$(echo "$SA_OUTPUT" | python3 -c "import json,sys; d=json.load(sys.stdin); print(len(d.get('items',[])))" 2>/dev/null || echo "?")
INFO "Total service accounts found: ${SA_COUNT}"
echo ""

# ─── 2. Check automountServiceAccountToken on default SA ─────────────────
echo "── 2. automountServiceAccountToken on Default SAs ───────────────────"
DEFAULT_SA_CHECK=$(echo "$SA_OUTPUT" | \
    python3 -c "
import json, sys
data = json.load(sys.stdin)
results = []
for item in data.get('items', []):
    if item['metadata']['name'] == 'default':
        ns = item['metadata'].get('namespace', 'unknown')
        automount = item.get('automountServiceAccountToken', True)  # default is True if not set
        results.append((ns, automount))
for ns, am in results:
    status = 'UNSAFE' if am else 'OK'
    print(f'{status} ns={ns} automountServiceAccountToken={am}')
" 2>/dev/null || echo "PARSE_ERROR")

echo "$DEFAULT_SA_CHECK" > "${EVIDENCE_DIR}/default-sa-automount.txt"

if [[ -z "$DEFAULT_SA_CHECK" || "$DEFAULT_SA_CHECK" == "PARSE_ERROR" ]]; then
    WARN "Could not check default SA automount status"
else
    while IFS= read -r line; do
        if [[ "$line" == UNSAFE* ]]; then
            FAIL "$line"
            INFO "WHY: automountServiceAccountToken=true allows any pod to access K8s API"
            INFO "FIX: kubectl patch serviceaccount default -n <ns> -p '{\"automountServiceAccountToken\": false}'"
            FINDINGS=$((FINDINGS + 1))
        else
            PASS "$line"
        fi
    done <<< "$DEFAULT_SA_CHECK"
fi
echo ""

# ─── 3. Identify SAs bound to cluster-admin ──────────────────────────────
echo "── 3. Service Accounts Bound to cluster-admin ───────────────────────"
CRB_OUTPUT=$(kubectl get clusterrolebindings -o json 2>/dev/null)
echo "$CRB_OUTPUT" > "${EVIDENCE_DIR}/clusterrolebindings.json"

SA_CLUSTER_ADMIN=$(echo "$CRB_OUTPUT" | \
    python3 -c "
import json, sys
data = json.load(sys.stdin)
for item in data.get('items', []):
    if item.get('roleRef', {}).get('name') == 'cluster-admin':
        for s in item.get('subjects', []):
            if s.get('kind') == 'ServiceAccount':
                print(f\"{s.get('namespace','cluster')}/{s.get('name','unknown')}\")
" 2>/dev/null || echo "")

echo "$SA_CLUSTER_ADMIN" > "${EVIDENCE_DIR}/sa-cluster-admin.txt"

if [[ -z "$SA_CLUSTER_ADMIN" ]]; then
    PASS "No service accounts have cluster-admin ClusterRoleBinding"
else
    COUNT=$(echo "$SA_CLUSTER_ADMIN" | grep -c . || true)
    FAIL "Found ${COUNT} service account(s) with cluster-admin:"
    while IFS= read -r line; do
        INFO "  $line"
    done <<< "$SA_CLUSTER_ADMIN"
    FINDINGS=$((FINDINGS + COUNT))
fi
echo ""

# ─── 4. Check for long-lived SA tokens (pre-1.24 style secrets) ──────────
echo "── 4. Long-lived Service Account Tokens (pre-1.24 style) ────────────"
if [[ -n "$NAMESPACE" ]]; then
    SECRETS_OUTPUT=$(kubectl get secrets -n "${NAMESPACE}" -o json 2>/dev/null)
else
    SECRETS_OUTPUT=$(kubectl get secrets --all-namespaces -o json 2>/dev/null)
fi
echo "$SECRETS_OUTPUT" > "${EVIDENCE_DIR}/secrets-raw.json"

LONG_LIVED_TOKENS=$(echo "$SECRETS_OUTPUT" | \
    python3 -c "
import json, sys
data = json.load(sys.stdin)
results = []
for item in data.get('items', []):
    if item.get('type') == 'kubernetes.io/service-account-token':
        name = item['metadata']['name']
        ns = item['metadata'].get('namespace', 'unknown')
        # Check if it has an expiry annotation (1.24+ time-limited tokens do)
        annotations = item['metadata'].get('annotations', {})
        has_expiry = 'kubernetes.io/token-expiration' in annotations
        if not has_expiry:
            sa = annotations.get('kubernetes.io/service-account.name', 'unknown')
            results.append(f'{ns}/{name} (sa: {sa}) — no expiry, long-lived')
for r in results:
    print(r)
" 2>/dev/null || echo "PARSE_ERROR")

echo "$LONG_LIVED_TOKENS" > "${EVIDENCE_DIR}/long-lived-tokens.txt"

if [[ -z "$LONG_LIVED_TOKENS" || "$LONG_LIVED_TOKENS" == "PARSE_ERROR" ]]; then
    PASS "No long-lived service account tokens found (or parse error)"
else
    COUNT=$(echo "$LONG_LIVED_TOKENS" | grep -c . || true)
    WARN "Found ${COUNT} long-lived SA token(s) without expiry:"
    while IFS= read -r line; do
        INFO "  $line"
    done <<< "$LONG_LIVED_TOKENS"
    INFO "WHY: Pre-1.24 style SA tokens never expire; prefer TokenRequest API (1.22+)"
    FINDINGS=$((FINDINGS + COUNT))
fi
echo ""

# ─── 5. SAs with non-default automount enabled ────────────────────────────
echo "── 5. Non-Default SAs with automountServiceAccountToken=true ────────"
NON_DEFAULT_AUTOMOUNT=$(echo "$SA_OUTPUT" | \
    python3 -c "
import json, sys
data = json.load(sys.stdin)
results = []
for item in data.get('items', []):
    name = item['metadata']['name']
    ns = item['metadata'].get('namespace', 'unknown')
    if name == 'default':
        continue
    # Only flag if explicitly set to True (not just absent — absence means inherited)
    if item.get('automountServiceAccountToken') is True:
        results.append(f'{ns}/{name}')
for r in results:
    print(r)
" 2>/dev/null || echo "PARSE_ERROR")

echo "$NON_DEFAULT_AUTOMOUNT" > "${EVIDENCE_DIR}/non-default-automount-true.txt"

if [[ -z "$NON_DEFAULT_AUTOMOUNT" || "$NON_DEFAULT_AUTOMOUNT" == "PARSE_ERROR" ]]; then
    PASS "No non-default SAs with automountServiceAccountToken explicitly set true"
else
    COUNT=$(echo "$NON_DEFAULT_AUTOMOUNT" | grep -c . || true)
    WARN "Found ${COUNT} non-default SA(s) with automount explicitly enabled:"
    while IFS= read -r line; do
        INFO "  $line"
    done <<< "$NON_DEFAULT_AUTOMOUNT"
    FINDINGS=$((FINDINGS + COUNT))
fi
echo ""

# ─── Summary ──────────────────────────────────────────────────────────────
echo "======================================================"
echo " Service Account Audit Summary"
echo " Total SAs inventoried: ${SA_COUNT}"
echo " Total findings: ${FINDINGS}"
echo " Evidence: ${EVIDENCE_DIR}"
echo " $(date)"
echo "======================================================"

cat > "${EVIDENCE_DIR}/summary.txt" <<EOF
L5 Service Account Audit Summary
Date: $(date)
Total SAs: ${SA_COUNT}
Total Findings: ${FINDINGS}

Files:
- serviceaccounts-raw.json: Full SA inventory
- default-sa-automount.txt: Default SA automount check per namespace
- clusterrolebindings.json: CRB dump for SA privilege check
- sa-cluster-admin.txt: SAs with cluster-admin
- secrets-raw.json: Secrets dump for token type analysis
- long-lived-tokens.txt: Pre-1.24 style tokens without expiry
- non-default-automount-true.txt: Non-default SAs with automount explicitly true
EOF

if [[ $FINDINGS -gt 0 ]]; then
    echo ""
    WARN "Remediation: see 02-fixers/fix-overprivileged-sa.sh"
fi
