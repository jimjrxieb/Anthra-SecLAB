#!/usr/bin/env bash
# AC-6 Least Privilege — Detect
# NIST 800-53: AC-6 | Layer: L3 Cluster | Package: 02-CLUSTER-HARDEN
#
# Detection tools:
#   1. kubectl auth can-i — verify SA permissions directly
#   2. kubescape — RBAC risk controls (C-0035 cluster-admin binding)
#   3. kubectl — dump ClusterRoleBindings for evidence
#
# Outputs JSON evidence to stdout or to $EVIDENCE_DIR if set.

set -euo pipefail

NAMESPACE="anthra"
EVIDENCE_DIR="${EVIDENCE_DIR:-}"
TIMESTAMP="$(date -u +%Y-%m-%dT%H%M%SZ)"

echo "=== AC-6 Detect: Checking least privilege ==="

# 1. Direct check — can default SA do things it shouldn't?
echo ""
echo "--- kubectl auth can-i check ---"
SA="system:serviceaccount:anthra:default"
CHECKS=(
    "create deployments"
    "delete pods"
    "get secrets"
    "create clusterrolebindings"
)
FAIL_COUNT=0
for CHECK in "${CHECKS[@]}"; do
    RESULT=$(kubectl auth can-i ${CHECK} --as="${SA}" -A 2>/dev/null || true)
    if [ "${RESULT}" = "yes" ]; then
        echo "FAIL: ${SA} can ${CHECK} (cluster-wide)"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    else
        echo "PASS: ${SA} cannot ${CHECK} (cluster-wide)"
    fi
done
echo ""
echo "${FAIL_COUNT} privilege escalation(s) detected"

# 2. kubescape — RBAC controls
echo ""
echo "--- kubescape RBAC scan ---"
KUBESCAPE_OUT="/tmp/ac6-kubescape-${TIMESTAMP}.json"
kubescape scan control C-0035,C-0188 --format json --output "${KUBESCAPE_OUT}" 2>/dev/null || true
echo "kubescape output saved to ${KUBESCAPE_OUT}"

# 3. ClusterRoleBinding dump
echo ""
echo "--- ClusterRoleBinding check ---"
CRB_OUT="/tmp/ac6-crb-${TIMESTAMP}.json"
kubectl get clusterrolebinding -o json | python3 -c "
import sys, json
data = json.load(sys.stdin)
findings = []
for item in data.get('items', []):
    for subj in item.get('subjects', []):
        if subj.get('name') == 'default' and subj.get('namespace') == 'anthra':
            findings.append({
                'binding': item['metadata']['name'],
                'role': item['roleRef']['name'],
                'sa': f\"{subj['namespace']}/{subj['name']}\"
            })
json.dump(findings, sys.stdout, indent=2)
" > "${CRB_OUT}" 2>/dev/null || echo '[]' > "${CRB_OUT}"
echo "ClusterRoleBindings for anthra/default:"
cat "${CRB_OUT}"

# Copy to evidence dir if set
if [ -n "${EVIDENCE_DIR}" ]; then
    mkdir -p "${EVIDENCE_DIR}"
    cp "${KUBESCAPE_OUT}" "${EVIDENCE_DIR}/ac6-kubescape.json"
    cp "${CRB_OUT}" "${EVIDENCE_DIR}/ac6-crb-state.json"
    echo ""
    echo "Evidence saved to ${EVIDENCE_DIR}/"
fi

echo ""
echo "=== AC-6 Detect complete ==="
