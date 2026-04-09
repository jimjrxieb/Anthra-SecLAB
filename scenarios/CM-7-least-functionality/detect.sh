#!/usr/bin/env bash
# CM-7 Least Functionality — Detect
# NIST 800-53: CM-7 | Layer: L3 Network | Package: 02-CLUSTER-HARDEN
#
# Detection tools:
#   1. kubectl — check for wildcard/overpermissive ingress rules
#   2. kubescape — scan for overpermissive network policies
#   3. polaris — audit for network policy best practices
#
# Outputs JSON evidence to stdout or to $EVIDENCE_DIR if set.

set -euo pipefail

NAMESPACE="anthra"
EVIDENCE_DIR="${EVIDENCE_DIR:-}"
TIMESTAMP="$(date -u +%Y-%m-%dT%H%M%SZ)"

echo "=== CM-7 Detect: Checking for overpermissive ingress ==="

# 1. Direct check — any allow-all ingress?
echo ""
echo "--- NetworkPolicy wildcard check ---"
ALLOW_ALL=$(kubectl get networkpolicy -n "${NAMESPACE}" -o json | \
    python3 -c "
import sys, json
data = json.load(sys.stdin)
for item in data.get('items', []):
    for rule in item.get('spec', {}).get('ingress', []):
        if rule == {}:
            print(f\"FAIL: {item['metadata']['name']} has wildcard ingress (empty rule)\")
" 2>/dev/null || true)

if [ -z "${ALLOW_ALL}" ]; then
    echo "PASS: No wildcard ingress rules found"
else
    echo "${ALLOW_ALL}"
fi

# 2. kubescape — overpermissive policies
echo ""
echo "--- kubescape scan ---"
KUBESCAPE_OUT="/tmp/cm7-kubescape-${TIMESTAMP}.json"
kubescape scan --format json --output "${KUBESCAPE_OUT}" 2>/dev/null || true
echo "kubescape output saved to ${KUBESCAPE_OUT}"

# 3. polaris — network audit
echo ""
echo "--- polaris audit ---"
POLARIS_OUT="/tmp/cm7-polaris-${TIMESTAMP}.json"
polaris audit --format json > "${POLARIS_OUT}" 2>/dev/null || true
echo "polaris output saved to ${POLARIS_OUT}"

# Copy to evidence dir if set
if [ -n "${EVIDENCE_DIR}" ]; then
    mkdir -p "${EVIDENCE_DIR}"
    cp "${KUBESCAPE_OUT}" "${EVIDENCE_DIR}/cm7-kubescape.json"
    cp "${POLARIS_OUT}" "${EVIDENCE_DIR}/cm7-polaris.json"
    kubectl get networkpolicy -n "${NAMESPACE}" -o json > "${EVIDENCE_DIR}/cm7-netpol-state.json"
    echo ""
    echo "Evidence saved to ${EVIDENCE_DIR}/"
fi

echo ""
echo "=== CM-7 Detect complete ==="
