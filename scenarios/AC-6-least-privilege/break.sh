#!/usr/bin/env bash
# AC-6 Least Privilege — Break
# NIST 800-53: AC-6 | Layer: L3 Cluster | Package: 02-CLUSTER-HARDEN
#
# Binds the default service account in anthra namespace to cluster-admin.
# This gives every pod in the namespace full cluster access. Idempotent.

set -euo pipefail

NAMESPACE="anthra"

echo "=== AC-6 Break: Binding default SA to cluster-admin ==="

cat <<'POLICY' | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: seclab-default-sa-cluster-admin
  labels:
    seclab-scenario: AC-6
subjects:
  - kind: ServiceAccount
    name: default
    namespace: anthra
roleRef:
  kind: ClusterRole
  name: cluster-admin
  apiGroup: rbac.authorization.k8s.io
POLICY

echo "=== AC-6 Break complete — default SA is now cluster-admin ==="
echo ""
echo "Verify — can default SA create deployments cluster-wide?"
kubectl auth can-i create deployments --as=system:serviceaccount:anthra:default -A
