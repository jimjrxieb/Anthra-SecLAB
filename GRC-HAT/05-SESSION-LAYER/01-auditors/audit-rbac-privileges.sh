#!/usr/bin/env bash
# audit-rbac-privileges.sh — L5 Session Layer K8s RBAC privilege audit
# NIST: AC-2 (account management), AC-6 (least privilege)
# Usage: ./audit-rbac-privileges.sh [namespace]
#
# CSF 2.0: PR.AA-05 (Access permissions managed)
# CIS v8: 5.4 (Restrict Admin Privileges)
# NIST: AC-6 (Least Privilege)
#
set -euo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; NC='\033[0m'
PASS() { echo -e "${GREEN}[PASS]${NC} $*"; }
WARN() { echo -e "${YELLOW}[WARN]${NC} $*"; }
FAIL() { echo -e "${RED}[FAIL]${NC} $*"; }
INFO() { echo -e "       $*"; }

NAMESPACE="${1:-}"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
EVIDENCE_DIR="/tmp/jsa-evidence/rbac-audit-${TIMESTAMP}"
mkdir -p "$EVIDENCE_DIR"

echo "======================================================"
echo " L5 RBAC Privilege Audit — AC-2 / AC-6"
echo " Evidence: ${EVIDENCE_DIR}"
echo " $(date)"
echo "======================================================"
echo ""

FINDINGS=0

# ─── 1. ClusterRoleBindings to cluster-admin ──────────────────────────────
echo "── 1. ClusterRoleBindings: cluster-admin ────────────────────────────"
CRB_OUTPUT=$(kubectl get clusterrolebindings -o json 2>/dev/null)
echo "$CRB_OUTPUT" > "${EVIDENCE_DIR}/clusterrolebindings-raw.json"

CLUSTER_ADMIN_BINDINGS=$(echo "$CRB_OUTPUT" | \
    python3 -c "
import json, sys
data = json.load(sys.stdin)
results = []
for item in data.get('items', []):
    if item.get('roleRef', {}).get('name') == 'cluster-admin':
        name = item['metadata']['name']
        subjects = item.get('subjects', [])
        for s in subjects:
            results.append(f\"{name} -> {s.get('kind','?')}/{s.get('name','?')} (ns: {s.get('namespace','cluster')})\")
for r in results:
    print(r)
" 2>/dev/null || echo "PARSE_ERROR")

echo "$CLUSTER_ADMIN_BINDINGS" > "${EVIDENCE_DIR}/cluster-admin-bindings.txt"

if [[ -z "$CLUSTER_ADMIN_BINDINGS" || "$CLUSTER_ADMIN_BINDINGS" == "PARSE_ERROR" ]]; then
    PASS "No cluster-admin ClusterRoleBindings found (or parse error)"
else
    COUNT=$(echo "$CLUSTER_ADMIN_BINDINGS" | grep -c . || true)
    FAIL "Found ${COUNT} cluster-admin binding(s):"
    while IFS= read -r line; do
        INFO "  $line"
    done <<< "$CLUSTER_ADMIN_BINDINGS"
    FINDINGS=$((FINDINGS + COUNT))
fi
echo ""

# ─── 2. Wildcard permissions in ClusterRoles ──────────────────────────────
echo "── 2. Wildcard Permissions (verbs: [\"*\"] or resources: [\"*\"]) ──────────"
CR_OUTPUT=$(kubectl get clusterroles -o json 2>/dev/null)
echo "$CR_OUTPUT" > "${EVIDENCE_DIR}/clusterroles-raw.json"

WILDCARD_ROLES=$(echo "$CR_OUTPUT" | \
    python3 -c "
import json, sys
data = json.load(sys.stdin)
results = []
for item in data.get('items', []):
    name = item['metadata']['name']
    # Skip system roles
    if name.startswith('system:') or name in ['cluster-admin', 'edit', 'view', 'admin']:
        continue
    for rule in item.get('rules', []):
        has_wildcard_verb = '*' in rule.get('verbs', [])
        has_wildcard_resource = '*' in rule.get('resources', [])
        if has_wildcard_verb or has_wildcard_resource:
            wtype = []
            if has_wildcard_verb: wtype.append('verbs:*')
            if has_wildcard_resource: wtype.append('resources:*')
            results.append(f\"{name} [{', '.join(wtype)}]\")
            break
for r in results:
    print(r)
" 2>/dev/null || echo "PARSE_ERROR")

echo "$WILDCARD_ROLES" > "${EVIDENCE_DIR}/wildcard-roles.txt"

if [[ -z "$WILDCARD_ROLES" || "$WILDCARD_ROLES" == "PARSE_ERROR" ]]; then
    PASS "No non-system ClusterRoles with wildcard permissions found"
else
    COUNT=$(echo "$WILDCARD_ROLES" | grep -c . || true)
    WARN "Found ${COUNT} ClusterRole(s) with wildcard permissions:"
    while IFS= read -r line; do
        INFO "  $line"
    done <<< "$WILDCARD_ROLES"
    FINDINGS=$((FINDINGS + COUNT))
fi
echo ""

# ─── 3. Wildcard permissions in namespace Roles ──────────────────────────
echo "── 3. Wildcard Permissions in Namespace Roles ───────────────────────"
if [[ -n "$NAMESPACE" ]]; then
    NS_FLAG="-n ${NAMESPACE}"
else
    NS_FLAG="--all-namespaces"
fi

ROLES_OUTPUT=$(kubectl get roles ${NS_FLAG} -o json 2>/dev/null)
echo "$ROLES_OUTPUT" > "${EVIDENCE_DIR}/roles-raw.json"

WILDCARD_NS_ROLES=$(echo "$ROLES_OUTPUT" | \
    python3 -c "
import json, sys
data = json.load(sys.stdin)
results = []
for item in data.get('items', []):
    name = item['metadata']['name']
    ns = item['metadata'].get('namespace', 'unknown')
    for rule in item.get('rules', []):
        has_wildcard_verb = '*' in rule.get('verbs', [])
        has_wildcard_resource = '*' in rule.get('resources', [])
        if has_wildcard_verb or has_wildcard_resource:
            wtype = []
            if has_wildcard_verb: wtype.append('verbs:*')
            if has_wildcard_resource: wtype.append('resources:*')
            results.append(f\"{ns}/{name} [{', '.join(wtype)}]\")
            break
for r in results:
    print(r)
" 2>/dev/null || echo "PARSE_ERROR")

echo "$WILDCARD_NS_ROLES" > "${EVIDENCE_DIR}/wildcard-namespace-roles.txt"

if [[ -z "$WILDCARD_NS_ROLES" || "$WILDCARD_NS_ROLES" == "PARSE_ERROR" ]]; then
    PASS "No namespace Roles with wildcard permissions found"
else
    COUNT=$(echo "$WILDCARD_NS_ROLES" | grep -c . || true)
    WARN "Found ${COUNT} namespace Role(s) with wildcard permissions:"
    while IFS= read -r line; do
        INFO "  $line"
    done <<< "$WILDCARD_NS_ROLES"
    FINDINGS=$((FINDINGS + COUNT))
fi
echo ""

# ─── 4. High-risk operations — kubectl auth can-i --list ──────────────────
echo "── 4. Current User High-Risk Capabilities ───────────────────────────"
HIGH_RISK_OUTPUT=$(kubectl auth can-i --list 2>/dev/null || echo "ERROR: kubectl auth can-i failed")
echo "$HIGH_RISK_OUTPUT" > "${EVIDENCE_DIR}/current-user-capabilities.txt"

HIGH_RISK_ITEMS=("create secrets" "delete secrets" "get secrets" "* *" "create clusterrolebindings" "create rolebindings")
echo "Checking current user can-i for high-risk operations:"
for op in "${HIGH_RISK_ITEMS[@]}"; do
    VERB="${op%% *}"
    RESOURCE="${op##* }"
    RESULT=$(kubectl auth can-i "${VERB}" "${RESOURCE}" 2>/dev/null || echo "no")
    if [[ "$RESULT" == "yes" ]]; then
        WARN "Current user CAN: ${op}"
        FINDINGS=$((FINDINGS + 1))
    else
        PASS "Current user CANNOT: ${op}"
    fi
done
echo ""

# ─── 5. Overprivileged service accounts ───────────────────────────────────
echo "── 5. Service Accounts Bound to cluster-admin ───────────────────────"
OVERPRIVILEGED_SA=$(echo "$CRB_OUTPUT" | \
    python3 -c "
import json, sys
data = json.load(sys.stdin)
results = []
for item in data.get('items', []):
    if item.get('roleRef', {}).get('name') == 'cluster-admin':
        for s in item.get('subjects', []):
            if s.get('kind') == 'ServiceAccount':
                results.append(f\"{s.get('namespace', 'unknown')}/{s.get('name', 'unknown')}\")
for r in results:
    print(r)
" 2>/dev/null || echo "")

echo "$OVERPRIVILEGED_SA" > "${EVIDENCE_DIR}/overprivileged-serviceaccounts.txt"

if [[ -z "$OVERPRIVILEGED_SA" ]]; then
    PASS "No service accounts bound to cluster-admin"
else
    COUNT=$(echo "$OVERPRIVILEGED_SA" | grep -c . || true)
    FAIL "Found ${COUNT} service account(s) with cluster-admin:"
    while IFS= read -r line; do
        INFO "  $line"
    done <<< "$OVERPRIVILEGED_SA"
    FINDINGS=$((FINDINGS + COUNT))
fi
echo ""

# ─── Summary ──────────────────────────────────────────────────────────────
echo "======================================================"
echo " RBAC Audit Summary"
echo " Total findings: ${FINDINGS}"
echo " Evidence: ${EVIDENCE_DIR}"
echo " $(date)"
echo "======================================================"

# Save summary
cat > "${EVIDENCE_DIR}/summary.txt" <<EOF
L5 RBAC Privilege Audit Summary
Date: $(date)
Total Findings: ${FINDINGS}

Files:
- clusterrolebindings-raw.json: Raw CRB dump
- cluster-admin-bindings.txt: Subjects with cluster-admin
- clusterroles-raw.json: Raw ClusterRole dump
- wildcard-roles.txt: ClusterRoles with wildcard permissions
- roles-raw.json: Raw namespace Role dump
- wildcard-namespace-roles.txt: Namespace Roles with wildcard permissions
- current-user-capabilities.txt: kubectl auth can-i --list output
- overprivileged-serviceaccounts.txt: SAs with cluster-admin
EOF

if [[ $FINDINGS -gt 0 ]]; then
    echo ""
    WARN "Remediation: see 02-fixers/fix-overprivileged-sa.sh"
fi
