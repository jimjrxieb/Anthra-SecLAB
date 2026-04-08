#!/usr/bin/env bash
# SC-7 Boundary Protection — Detect
# NIST 800-53: SC-7 | Layer: L3 Network | Package: 02-CLUSTER-HARDEN
#
# Detection tools:
#   1. kubectl — check if NetworkPolicies exist
#   2. kube-hunter — probe for exposed services from outside the cluster
#   3. kubescape — scan for NSA/CISA network policy controls
#
# Outputs JSON evidence to stdout or to $EVIDENCE_DIR if set.

set -euo pipefail

NAMESPACE="anthra"
EVIDENCE_DIR="${EVIDENCE_DIR:-}"
TIMESTAMP="$(date -u +%Y-%m-%dT%H%M%SZ)"

echo "=== SC-7 Detect: Checking boundary protection ==="

# 1. Direct check — any NetworkPolicies?
echo ""
echo "--- NetworkPolicy check ---"
NETPOL_COUNT=$(kubectl get networkpolicy -n "${NAMESPACE}" --no-headers 2>/dev/null | wc -l)
if [ "${NETPOL_COUNT}" -eq 0 ]; then
    echo "FAIL: No NetworkPolicies in namespace ${NAMESPACE}"
else
    echo "PASS: ${NETPOL_COUNT} NetworkPolicies found"
    kubectl get networkpolicy -n "${NAMESPACE}" -o wide
fi

# 2. kube-hunter — network probe
echo ""
echo "--- kube-hunter scan ---"
HUNTER_OUT="/tmp/sc7-kube-hunter-${TIMESTAMP}.json"
kube-hunter --pod --quick --report json > "${HUNTER_OUT}" 2>/dev/null || true
VULN_COUNT=$(python3 -c "import json; d=json.load(open('${HUNTER_OUT}')); print(len(d.get('vulnerabilities', [])))" 2>/dev/null || echo "0")
echo "kube-hunter found ${VULN_COUNT} vulnerabilities"

# 3. kubescape — network policy controls
echo ""
echo "--- kubescape scan (network controls) ---"
KUBESCAPE_OUT="/tmp/sc7-kubescape-${TIMESTAMP}.json"
kubescape scan control C-0260 --format json --output "${KUBESCAPE_OUT}" 2>/dev/null || true
echo "kubescape output saved to ${KUBESCAPE_OUT}"

# Copy to evidence dir if set
if [ -n "${EVIDENCE_DIR}" ]; then
    mkdir -p "${EVIDENCE_DIR}"
    cp "${HUNTER_OUT}" "${EVIDENCE_DIR}/sc7-kube-hunter.json"
    cp "${KUBESCAPE_OUT}" "${EVIDENCE_DIR}/sc7-kubescape.json"
    kubectl get networkpolicy -n "${NAMESPACE}" -o json > "${EVIDENCE_DIR}/sc7-netpol-state.json" 2>/dev/null || echo '{"items":[]}' > "${EVIDENCE_DIR}/sc7-netpol-state.json"
    echo ""
    echo "Evidence saved to ${EVIDENCE_DIR}/"
fi

echo ""
echo "=== SC-7 Detect complete ==="
