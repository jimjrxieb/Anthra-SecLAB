#!/usr/bin/env bash
# AC-6 Least Privilege — Fix
# NIST 800-53: AC-6 | Layer: L3 Cluster | Package: 02-CLUSTER-HARDEN
# Type: Preventive
#
# Removes cluster-admin binding from default SA and scopes it to
# namespace-level read-only. Idempotent.

set -euo pipefail

NAMESPACE="anthra"

echo "=== AC-6 Fix: Removing overprivileged SA binding ==="

# Remove the dangerous ClusterRoleBinding
kubectl delete clusterrolebinding seclab-default-sa-cluster-admin --ignore-not-found

# Create namespace-scoped read-only Role and RoleBinding
cat <<'POLICY' | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: seclab-readonly
  namespace: anthra
  labels:
    seclab-scenario: AC-6
rules:
  - apiGroups: [""]
    resources: ["pods", "services", "configmaps"]
    verbs: ["get", "list", "watch"]
POLICY

cat <<'POLICY' | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: seclab-default-sa-readonly
  namespace: anthra
  labels:
    seclab-scenario: AC-6
subjects:
  - kind: ServiceAccount
    name: default
    namespace: anthra
roleRef:
  kind: Role
  name: seclab-readonly
  apiGroup: rbac.authorization.k8s.io
POLICY

echo "=== AC-6 Fix complete ==="
echo ""
echo "ClusterRoleBindings for default SA:"
kubectl get clusterrolebinding -o json | python3 -c "
import sys, json
data = json.load(sys.stdin)
for item in data.get('items', []):
    for subj in item.get('subjects', []):
        if subj.get('name') == 'default' and subj.get('namespace') == 'anthra':
            print(f\"  {item['metadata']['name']} -> {item['roleRef']['name']}\")
" 2>/dev/null || echo "  (none)"
echo ""
echo "RoleBindings in ${NAMESPACE}:"
kubectl get rolebinding -n "${NAMESPACE}" -l seclab-scenario=AC-6 -o wide
