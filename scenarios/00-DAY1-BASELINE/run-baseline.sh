#!/usr/bin/env bash
# run-baseline.sh — Day 1 automated baseline capture
#
# CSF 2.0: ID.AM-01 (Inventories maintained)
# CIS v8:  1.1 (Establish Enterprise Asset Inventory)
# NIST:    CM-2 (Baseline Configuration)
#
# Usage:
#   bash scenarios/00-DAY1-BASELINE/run-baseline.sh
#
# Output:
#   evidence/YYYY-MM-DD/baseline-TIMESTAMP/
#
# Run this before any break/fix scenarios execute.
# This script is read-only — it captures state, never modifies.

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

NAMESPACE="anthra"
CONTEXT="k3d-seclab"
DATE="$(date +%Y-%m-%d)"
TIMESTAMP="$(date +%H%M%S)"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
EVIDENCE_BASE="${REPO_ROOT}/evidence/${DATE}/baseline-${TIMESTAMP}"

# ---------------------------------------------------------------------------
# Preflight checks
# ---------------------------------------------------------------------------

echo "=== Anthra-SecLAB Day 1 Baseline Capture ==="
echo "Date:      ${DATE}"
echo "Timestamp: ${TIMESTAMP}"
echo "Namespace: ${NAMESPACE}"
echo "Evidence:  ${EVIDENCE_BASE}"
echo ""

# Verify cluster context
CURRENT_CONTEXT="$(kubectl config current-context 2>/dev/null || echo NONE)"
if [[ "${CURRENT_CONTEXT}" != "${CONTEXT}" ]]; then
  echo "ERROR: Wrong cluster context."
  echo "  Expected: ${CONTEXT}"
  echo "  Got:      ${CURRENT_CONTEXT}"
  echo "  Fix:      kubectl config use-context ${CONTEXT}"
  exit 1
fi
echo "Cluster context: ${CURRENT_CONTEXT} [OK]"

# Create evidence directory
mkdir -p "${EVIDENCE_BASE}"
echo "Evidence directory created: ${EVIDENCE_BASE}"
echo ""

# ---------------------------------------------------------------------------
# Step 1 — Cluster state snapshot
# CSF: ID.AM-01 | CIS: 1.1 | NIST: CM-2
# ---------------------------------------------------------------------------

echo "[1/7] Capturing cluster state..."

kubectl get nodes -o wide > "${EVIDENCE_BASE}/01-nodes.txt" 2>&1
kubectl get nodes -o json > "${EVIDENCE_BASE}/01-nodes.json" 2>&1
kubectl version --output=yaml > "${EVIDENCE_BASE}/01-cluster-version.yaml" 2>&1
kubectl get namespaces -o wide > "${EVIDENCE_BASE}/01-namespaces.txt" 2>&1

echo "  nodes.txt         -> $(wc -l < "${EVIDENCE_BASE}/01-nodes.txt") lines"
echo "  namespaces.txt    -> $(wc -l < "${EVIDENCE_BASE}/01-namespaces.txt") lines"
echo "  cluster-version.yaml saved"

# ---------------------------------------------------------------------------
# Step 2 — Target namespace snapshot (anthra)
# CSF: ID.AM-01 | CIS: 1.1 | NIST: CM-2
# ---------------------------------------------------------------------------

echo "[2/7] Capturing anthra namespace state..."

kubectl get all -n "${NAMESPACE}" -o wide > "${EVIDENCE_BASE}/02-anthra-all.txt" 2>&1
kubectl get pods -n "${NAMESPACE}" -o json > "${EVIDENCE_BASE}/02-anthra-pods.json" 2>&1
kubectl get deployments -n "${NAMESPACE}" -o json > "${EVIDENCE_BASE}/02-anthra-deployments.json" 2>&1
kubectl get services -n "${NAMESPACE}" -o json > "${EVIDENCE_BASE}/02-anthra-services.json" 2>&1
kubectl get serviceaccounts -n "${NAMESPACE}" -o json > "${EVIDENCE_BASE}/02-anthra-serviceaccounts.json" 2>&1

# Extract securityContext for each deployment
for deploy in portfolio-anthra-portfolio-app-api portfolio-anthra-portfolio-app-ui portfolio-anthra-portfolio-app-chroma; do
  outfile="${EVIDENCE_BASE}/02-secctx-${deploy}.txt"
  {
    echo "=== securityContext: ${deploy} ==="
    kubectl get deployment "${deploy}" -n "${NAMESPACE}" \
      -o jsonpath='{.spec.template.spec.securityContext}' 2>/dev/null | python3 -m json.tool || echo "(not found or empty)"
    echo ""
    echo "=== container securityContext: ${deploy} ==="
    kubectl get deployment "${deploy}" -n "${NAMESPACE}" \
      -o jsonpath='{.spec.template.spec.containers[0].securityContext}' 2>/dev/null | python3 -m json.tool || echo "(not found or empty)"
  } > "${outfile}" 2>&1
done

# Service account token automount status
kubectl get pods -n "${NAMESPACE}" \
  -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.automountServiceAccountToken}{"\n"}{end}' \
  > "${EVIDENCE_BASE}/02-automount-tokens.txt" 2>&1

echo "  anthra-all.txt saved"
echo "  securityContext files saved for 3 deployments"
echo "  automount-tokens.txt saved"

# ---------------------------------------------------------------------------
# Step 3 — Security stack health
# CSF: DE.CM-03 | CIS: 6.8 | NIST: SI-4
# ---------------------------------------------------------------------------

echo "[3/7] Capturing security stack health..."

{
  echo "=== Falco ==="
  kubectl get pods -n falco -o wide 2>&1 || echo "(namespace not found)"
  echo ""
  echo "=== Kyverno ==="
  kubectl get pods -n kyverno -o wide 2>&1 || echo "(namespace not found)"
  echo ""
  echo "=== Fluent Bit (logging) ==="
  kubectl get pods -n logging -o wide 2>&1 || echo "(namespace not found)"
  echo ""
  echo "=== Prometheus + Grafana (monitoring) ==="
  kubectl get pods -n monitoring -o wide 2>&1 || echo "(namespace not found)"
} > "${EVIDENCE_BASE}/03-security-stack-health.txt"

# Grab last 50 Falco log lines for baseline reference
kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=50 \
  > "${EVIDENCE_BASE}/03-falco-logs.txt" 2>&1 || \
kubectl logs -n falco -l app=falco --tail=50 \
  > "${EVIDENCE_BASE}/03-falco-logs.txt" 2>&1 || \
echo "(could not retrieve Falco logs)" > "${EVIDENCE_BASE}/03-falco-logs.txt"

echo "  security-stack-health.txt saved"
echo "  falco-logs.txt saved"

# ---------------------------------------------------------------------------
# Step 4 — Kyverno policy inventory
# CSF: PR.PS-01 | CIS: 4.6 | NIST: CM-6
# ---------------------------------------------------------------------------

echo "[4/7] Capturing Kyverno policy configuration..."

kubectl get clusterpolicies -o wide > "${EVIDENCE_BASE}/04-kyverno-clusterpolicies.txt" 2>&1 || \
  echo "(no clusterpolicies found)" > "${EVIDENCE_BASE}/04-kyverno-clusterpolicies.txt"

kubectl get clusterpolicies -o json > "${EVIDENCE_BASE}/04-kyverno-clusterpolicies.json" 2>&1 || \
  echo "{}" > "${EVIDENCE_BASE}/04-kyverno-clusterpolicies.json"

kubectl get policies -A -o wide > "${EVIDENCE_BASE}/04-kyverno-policies.txt" 2>&1 || \
  echo "(no namespace-scoped policies found)" > "${EVIDENCE_BASE}/04-kyverno-policies.txt"

# Extract enforcement modes
{
  echo "=== Kyverno ClusterPolicy Enforcement Modes ==="
  kubectl get clusterpolicies -o \
    jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.validationFailureAction}{"\n"}{end}' \
    2>/dev/null || echo "(no clusterpolicies)"
} > "${EVIDENCE_BASE}/04-kyverno-enforcement-modes.txt"

echo "  kyverno-clusterpolicies.txt saved"
echo "  kyverno-enforcement-modes.txt saved"

# ---------------------------------------------------------------------------
# Step 5 — RBAC snapshot
# CSF: PR.AA-05 | CIS: 12.2 | NIST: AC-6
# ---------------------------------------------------------------------------

echo "[5/7] Capturing RBAC configuration..."

kubectl get clusterroles -o wide > "${EVIDENCE_BASE}/05-clusterroles.txt" 2>&1
kubectl get clusterrolebindings -o wide > "${EVIDENCE_BASE}/05-clusterrolebindings.txt" 2>&1
kubectl get rolebindings -n "${NAMESPACE}" -o wide > "${EVIDENCE_BASE}/05-anthra-rolebindings.txt" 2>&1
kubectl get clusterrolebindings -o json > "${EVIDENCE_BASE}/05-clusterrolebindings.json" 2>&1

# Extract cluster-admin bindings specifically
{
  echo "=== Subjects bound to cluster-admin ==="
  kubectl get clusterrolebindings -o json | \
    python3 -c "
import json, sys
data = json.load(sys.stdin)
for item in data['items']:
    if item.get('roleRef', {}).get('name') == 'cluster-admin':
        for sub in item.get('subjects', []):
            print(f\"{item['metadata']['name']}: {sub.get('kind','?')} / {sub.get('name','?')} in ns={sub.get('namespace','cluster-scope')}\")
" 2>/dev/null || echo "(python3 extraction failed)"
} > "${EVIDENCE_BASE}/05-cluster-admin-bindings.txt"

# Extract wildcard roles (non-system)
{
  echo "=== ClusterRoles with wildcard verbs or resources (non-system) ==="
  kubectl get clusterroles -o json | \
    python3 -c "
import json, sys
data = json.load(sys.stdin)
found = 0
for item in data['items']:
    name = item['metadata']['name']
    if name.startswith('system:'):
        continue
    for rule in item.get('rules', []):
        if '*' in rule.get('verbs', []) or '*' in rule.get('resources', []):
            print(f\"{name}: verbs={rule.get('verbs',[])} resources={rule.get('resources',[])} apiGroups={rule.get('apiGroups','')}\")
            found += 1
if found == 0:
    print('(none found — expected baseline state)')
" 2>/dev/null || echo "(python3 extraction failed)"
} > "${EVIDENCE_BASE}/05-wildcard-roles.txt"

echo "  clusterroles.txt saved"
echo "  clusterrolebindings.txt saved"
echo "  cluster-admin-bindings.txt saved"
echo "  wildcard-roles.txt saved"

# ---------------------------------------------------------------------------
# Step 6 — NetworkPolicy snapshot
# CSF: PR.PS-01 | CIS: 12.3 | NIST: SC-7
# ---------------------------------------------------------------------------

echo "[6/7] Capturing NetworkPolicy configuration..."

kubectl get networkpolicies -n "${NAMESPACE}" -o wide > "${EVIDENCE_BASE}/06-networkpolicies.txt" 2>&1
kubectl get networkpolicies -n "${NAMESPACE}" -o yaml > "${EVIDENCE_BASE}/06-networkpolicies.yaml" 2>&1
kubectl get networkpolicies -A -o wide > "${EVIDENCE_BASE}/06-networkpolicies-all-ns.txt" 2>&1

echo "  networkpolicies.txt saved (anthra)"
echo "  networkpolicies-all-ns.txt saved (cluster-wide)"

# ---------------------------------------------------------------------------
# Step 7 — Image versions
# CSF: ID.AM-01 | CIS: 7.5 | NIST: CM-2
# ---------------------------------------------------------------------------

echo "[7/7] Capturing running image versions..."

{
  echo "=== Images running in anthra namespace ==="
  kubectl get pods -n "${NAMESPACE}" \
    -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{range .spec.containers[*]}  image: {.image}{"\n"}{end}{end}' \
    2>/dev/null
  echo ""
  echo "=== Images running in security stack namespaces ==="
  for ns in falco kyverno logging monitoring; do
    echo "--- ${ns} ---"
    kubectl get pods -n "${ns}" \
      -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{range .spec.containers[*]}  image: {.image}{"\n"}{end}{end}' \
      2>/dev/null || echo "(namespace ${ns} not accessible)"
    echo ""
  done
} > "${EVIDENCE_BASE}/07-image-versions.txt"

echo "  image-versions.txt saved"

# ---------------------------------------------------------------------------
# Baseline capture complete
# ---------------------------------------------------------------------------

echo ""
echo "=== Baseline capture complete ==="
echo ""
echo "Evidence saved to:"
echo "  ${EVIDENCE_BASE}/"
echo ""
echo "Files captured:"
ls -1 "${EVIDENCE_BASE}/"
echo ""
echo "Next steps:"
echo "  1. Walk through checklist.md — run each command manually"
echo "  2. Fill out baseline-report-template.md with your findings"
echo "  3. Keep this evidence directory — it is your before-state for all scenarios"
