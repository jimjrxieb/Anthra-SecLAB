#!/usr/bin/env bash
# fix-overprivileged-sa.sh — L5 Session Layer K8s RBAC remediation
# NIST: AC-6 (least privilege), AC-2 (account management)
# Usage: ./fix-overprivileged-sa.sh <namespace> [--dry-run]
# WARNING: Review output before applying. Removing cluster-admin may break workloads.
set -euo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; NC='\033[0m'
PASS() { echo -e "${GREEN}[PASS]${NC} $*"; }
WARN() { echo -e "${YELLOW}[WARN]${NC} $*"; }
FAIL() { echo -e "${RED}[FAIL]${NC} $*"; }
INFO() { echo -e "       $*"; }

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <namespace> [--dry-run]"
    echo "  Example: $0 default"
    echo "  Example: $0 my-app --dry-run"
    exit 1
fi

NAMESPACE="$1"
DRY_RUN=false
[[ "${2:-}" == "--dry-run" ]] && DRY_RUN=true

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
EVIDENCE_DIR="/tmp/jsa-evidence/fix-rbac-sa-${NAMESPACE}-${TIMESTAMP}"
mkdir -p "$EVIDENCE_DIR"

echo "======================================================"
echo " L5 RBAC SA Remediation — AC-6 / AC-2"
echo " Namespace: ${NAMESPACE} | Dry-run: ${DRY_RUN}"
echo " Evidence: ${EVIDENCE_DIR}"
echo " $(date)"
echo "======================================================"
echo ""

# ─── 1. Capture before state ──────────────────────────────────────────────
echo "── 1. Before State ──────────────────────────────────────────────────"
kubectl get clusterrolebindings -o yaml > "${EVIDENCE_DIR}/before-clusterrolebindings.yaml"
kubectl get rolebindings -n "${NAMESPACE}" -o yaml > "${EVIDENCE_DIR}/before-rolebindings.yaml" 2>/dev/null || true
kubectl get serviceaccounts -n "${NAMESPACE}" -o yaml > "${EVIDENCE_DIR}/before-serviceaccounts.yaml"
PASS "Before state captured in ${EVIDENCE_DIR}"
echo ""

# ─── 2. Remove cluster-admin CRBs for SAs in this namespace ──────────────
echo "── 2. Remove cluster-admin ClusterRoleBindings ───────────────────────"
CRB_LIST=$(kubectl get clusterrolebindings -o json | \
    python3 -c "
import json, sys
data = json.load(sys.stdin)
results = []
for item in data.get('items', []):
    if item.get('roleRef', {}).get('name') == 'cluster-admin':
        for s in item.get('subjects', []):
            if s.get('kind') == 'ServiceAccount' and s.get('namespace') == '${NAMESPACE}':
                results.append(item['metadata']['name'])
for r in results:
    print(r)
" 2>/dev/null || echo "")

if [[ -z "$CRB_LIST" ]]; then
    PASS "No cluster-admin CRBs found for service accounts in namespace ${NAMESPACE}"
else
    while IFS= read -r CRB_NAME; do
        if [[ "$DRY_RUN" == "true" ]]; then
            WARN "[DRY-RUN] Would delete ClusterRoleBinding: ${CRB_NAME}"
        else
            INFO "Deleting ClusterRoleBinding: ${CRB_NAME}"
            kubectl delete clusterrolebinding "${CRB_NAME}" 2>&1 | tee -a "${EVIDENCE_DIR}/crb-deletions.log"
            PASS "Deleted CRB: ${CRB_NAME}"
        fi
    done <<< "$CRB_LIST"
fi
echo ""

# ─── 3. Create scoped Role with minimum verbs ─────────────────────────────
echo "── 3. Create Scoped Role (least-privilege) ───────────────────────────"
ROLE_NAME="app-minimal-${TIMESTAMP}"
ROLE_MANIFEST=$(cat <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: ${ROLE_NAME}
  namespace: ${NAMESPACE}
  labels:
    created-by: fix-overprivileged-sa
    nist-control: AC-6
  annotations:
    purpose: "Minimum permissions for application workloads — NIST AC-6 least privilege"
    created: "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
rules:
  # WHY: Most app workloads need to read ConfigMaps for configuration
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["get", "list", "watch"]
  # WHY: Secrets access should be explicitly requested, not inherited
  # Remove this if application does not need secret access
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get"]
  # WHY: Pod listing is required for health check scripts and sidecar coordination
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list"]
  # WHY: Services needed for service discovery in some applications
  - apiGroups: [""]
    resources: ["services"]
    verbs: ["get", "list"]
EOF
)

echo "$ROLE_MANIFEST" > "${EVIDENCE_DIR}/role-app-minimal.yaml"

if [[ "$DRY_RUN" == "true" ]]; then
    WARN "[DRY-RUN] Would create Role: ${ROLE_NAME} in namespace ${NAMESPACE}"
    INFO "Manifest saved: ${EVIDENCE_DIR}/role-app-minimal.yaml"
else
    echo "$ROLE_MANIFEST" | kubectl apply -f - 2>&1 | tee -a "${EVIDENCE_DIR}/role-creation.log"
    PASS "Created Role: ${ROLE_NAME} in namespace ${NAMESPACE}"
fi
echo ""

# ─── 4. Create RoleBinding for default SA to scoped Role ─────────────────
echo "── 4. Create RoleBinding (default SA → scoped Role) ─────────────────"
RB_NAME="default-sa-minimal-${TIMESTAMP}"
RB_MANIFEST=$(cat <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: ${RB_NAME}
  namespace: ${NAMESPACE}
  labels:
    created-by: fix-overprivileged-sa
    nist-control: AC-6
  annotations:
    purpose: "Bind default SA to scoped role — NIST AC-6 least privilege"
    created: "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
subjects:
  # WHY: Binding default SA to scoped role replaces any cluster-admin binding
  - kind: ServiceAccount
    name: default
    namespace: ${NAMESPACE}
roleRef:
  kind: Role
  name: ${ROLE_NAME}
  apiGroup: rbac.authorization.k8s.io
EOF
)

echo "$RB_MANIFEST" > "${EVIDENCE_DIR}/rolebinding-default-sa.yaml"

if [[ "$DRY_RUN" == "true" ]]; then
    WARN "[DRY-RUN] Would create RoleBinding: ${RB_NAME}"
    INFO "Manifest saved: ${EVIDENCE_DIR}/rolebinding-default-sa.yaml"
else
    echo "$RB_MANIFEST" | kubectl apply -f - 2>&1 | tee -a "${EVIDENCE_DIR}/rb-creation.log"
    PASS "Created RoleBinding: ${RB_NAME}"
fi
echo ""

# ─── 5. Disable automountServiceAccountToken on default SA ───────────────
echo "── 5. Disable automountServiceAccountToken on Default SA ────────────"
INFO "WHY: automountServiceAccountToken=true allows any pod to call the K8s API"
INFO "     Most workloads do not need K8s API access — disable by default (AC-6)"

CURRENT_AUTOMOUNT=$(kubectl get serviceaccount default -n "${NAMESPACE}" \
    -o jsonpath='{.automountServiceAccountToken}' 2>/dev/null || echo "true")

if [[ "$CURRENT_AUTOMOUNT" == "false" ]]; then
    PASS "automountServiceAccountToken already false on default SA in ${NAMESPACE}"
else
    if [[ "$DRY_RUN" == "true" ]]; then
        WARN "[DRY-RUN] Would patch default SA: automountServiceAccountToken=false"
    else
        # Capture before patching
        kubectl get serviceaccount default -n "${NAMESPACE}" -o yaml > "${EVIDENCE_DIR}/before-default-sa.yaml"

        kubectl patch serviceaccount default \
            -n "${NAMESPACE}" \
            -p '{"automountServiceAccountToken": false}' 2>&1 | tee -a "${EVIDENCE_DIR}/sa-patch.log"

        # Capture after
        kubectl get serviceaccount default -n "${NAMESPACE}" -o yaml > "${EVIDENCE_DIR}/after-default-sa.yaml"

        NEW_VALUE=$(kubectl get serviceaccount default -n "${NAMESPACE}" \
            -o jsonpath='{.automountServiceAccountToken}' 2>/dev/null || echo "unknown")
        if [[ "$NEW_VALUE" == "false" ]]; then
            PASS "automountServiceAccountToken=false applied on default SA in ${NAMESPACE}"
        else
            FAIL "Patch may not have applied — current value: ${NEW_VALUE}"
        fi
    fi
fi
echo ""

# ─── 6. After state ───────────────────────────────────────────────────────
echo "── 6. After State ───────────────────────────────────────────────────"
if [[ "$DRY_RUN" != "true" ]]; then
    kubectl get rolebindings -n "${NAMESPACE}" -o yaml > "${EVIDENCE_DIR}/after-rolebindings.yaml" 2>/dev/null || true
    kubectl get serviceaccounts -n "${NAMESPACE}" -o yaml > "${EVIDENCE_DIR}/after-serviceaccounts.yaml"
    PASS "After state captured in ${EVIDENCE_DIR}"

    echo ""
    echo "── Verify: kubectl auth can-i tests ─────────────────────────────"
    INFO "Testing if default SA lost cluster-admin capabilities:"
    for OP in "create deployments" "delete pods" "get secrets" "create clusterrolebindings"; do
        VERB="${OP%% *}"
        RESOURCE="${OP##* }"
        RESULT=$(kubectl auth can-i "${VERB}" "${RESOURCE}" \
            --namespace "${NAMESPACE}" \
            --as "system:serviceaccount:${NAMESPACE}:default" \
            2>/dev/null || echo "no")
        if [[ "$RESULT" == "no" ]]; then
            PASS "SA default CANNOT: ${OP}"
        else
            WARN "SA default CAN: ${OP} — may need further restriction"
        fi
    done
fi
echo ""

# ─── Summary ──────────────────────────────────────────────────────────────
echo "======================================================"
echo " RBAC SA Remediation Summary"
echo " Namespace: ${NAMESPACE} | Dry-run: ${DRY_RUN}"
echo " Evidence: ${EVIDENCE_DIR}"
echo " $(date)"
echo "======================================================"

cat > "${EVIDENCE_DIR}/summary.txt" <<EOF
L5 RBAC SA Remediation Summary
Date: $(date)
Namespace: ${NAMESPACE}
Dry-run: ${DRY_RUN}

Actions performed:
1. Removed cluster-admin CRBs for SAs in ${NAMESPACE}
2. Created scoped Role: ${ROLE_NAME}
3. Created RoleBinding: ${RB_NAME}
4. Disabled automountServiceAccountToken on default SA

Files:
- before-clusterrolebindings.yaml: CRBs before remediation
- before-rolebindings.yaml: RBs before remediation
- before-serviceaccounts.yaml: SAs before remediation
- role-app-minimal.yaml: Created Role manifest
- rolebinding-default-sa.yaml: Created RoleBinding manifest
- after-rolebindings.yaml: RBs after remediation
- after-serviceaccounts.yaml: SAs after remediation
EOF
