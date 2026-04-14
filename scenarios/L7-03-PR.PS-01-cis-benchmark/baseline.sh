#!/usr/bin/env bash
#
# CSF: PROTECT / PR.PS-01 — Configuration management practices applied to IT assets
# CIS v8: 4.1 — Establish and Maintain a Secure Configuration Process
# NIST 800-53: CM-6 — Configuration Settings, CM-7 — Least Functionality
#
# L7-03 PR.PS-01 — Baseline: Run CIS benchmark audit and capture results
#
# This IS the detection. The baseline reveals benchmark failures that have
# existed since deployment. Run this to establish the ground truth before
# any remediation work begins.
#
# Tools required:
#   kube-bench at /usr/local/bin/kube-bench
#   kubescape at /home/jimmie/bin/kubescape
#
# Usage: bash baseline.sh
# Expected: kube-bench FAIL count > 0, kubescape score < 100%

set -euo pipefail

NAMESPACE="anthra"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
BASELINE_DIR="/tmp/L7-03-baseline-${TIMESTAMP}"
KUBE_BENCH="/usr/local/bin/kube-bench"
KUBESCAPE="${HOME}/bin/kubescape"

mkdir -p "${BASELINE_DIR}"

echo "=== L7-03 PR.PS-01 Baseline: CIS Benchmark Audit ==="
echo "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "Namespace: ${NAMESPACE}"
echo "Output directory: ${BASELINE_DIR}"
echo ""

# --- Verify tools are available ---
if [[ ! -x "${KUBE_BENCH}" ]]; then
  echo "ERROR: kube-bench not found at ${KUBE_BENCH}"
  echo "       Install: https://github.com/aquasecurity/kube-bench/releases"
  exit 1
fi

if [[ ! -x "${KUBESCAPE}" ]]; then
  echo "ERROR: kubescape not found at ${KUBESCAPE}"
  echo "       Install: curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash"
  exit 1
fi

echo "kube-bench: ${KUBE_BENCH}"
echo "kubescape:  ${KUBESCAPE}"
echo ""

# --- kube-bench: node-level CIS benchmark ---
echo "=== Phase 1: kube-bench (CIS Kubernetes Benchmark) ==="
echo "Running node benchmark against k3s cluster..."
echo "This may take 30-60 seconds."
echo ""

${KUBE_BENCH} run --targets node 2>/dev/null \
  | tee "${BASELINE_DIR}/kube-bench-output.txt"

echo ""
echo "--- kube-bench Result Counts ---"

KB_PASS=$(grep -cE "^\[PASS\]" "${BASELINE_DIR}/kube-bench-output.txt" 2>/dev/null || echo 0)
KB_FAIL=$(grep -cE "^\[FAIL\]" "${BASELINE_DIR}/kube-bench-output.txt" 2>/dev/null || echo 0)
KB_WARN=$(grep -cE "^\[WARN\]" "${BASELINE_DIR}/kube-bench-output.txt" 2>/dev/null || echo 0)
KB_INFO=$(grep -cE "^\[INFO\]" "${BASELINE_DIR}/kube-bench-output.txt" 2>/dev/null || echo 0)

echo "  PASS: ${KB_PASS}"
echo "  FAIL: ${KB_FAIL}"
echo "  WARN: ${KB_WARN}"
echo "  INFO: ${KB_INFO}"

# Save counts to a summary file for compare in verify.sh
{
  echo "kube-bench-pass=${KB_PASS}"
  echo "kube-bench-fail=${KB_FAIL}"
  echo "kube-bench-warn=${KB_WARN}"
  echo "kube-bench-info=${KB_INFO}"
  echo "timestamp=${TIMESTAMP}"
} > "${BASELINE_DIR}/counts.txt"

echo ""
echo "kube-bench output saved to: ${BASELINE_DIR}/kube-bench-output.txt"

# --- kubescape: workload and policy posture ---
echo ""
echo "=== Phase 2: kubescape (Workload Security Posture) ==="
echo "Running kubescape scan against cluster and namespace ${NAMESPACE}..."
echo "This may take 60-90 seconds on first run (downloads framework definitions)."
echo ""

${KUBESCAPE} scan \
  --format json \
  --output "${BASELINE_DIR}/kubescape-output.json" \
  namespace "${NAMESPACE}" \
  2>/dev/null || true

echo ""
echo "--- kubescape Summary (last 25 lines of pretty output) ---"
${KUBESCAPE} scan \
  --format pretty \
  namespace "${NAMESPACE}" \
  2>/dev/null \
  | tail -25 \
  | tee "${BASELINE_DIR}/kubescape-summary.txt" || true

echo ""
echo "kubescape JSON saved to: ${BASELINE_DIR}/kubescape-output.json"
echo "kubescape summary saved to: ${BASELINE_DIR}/kubescape-summary.txt"

# --- Namespace PSS labels check ---
echo ""
echo "=== Phase 3: Namespace PSS Labels (CM-7 Least Functionality) ==="
echo "Checking Pod Security Standards enforcement on namespace ${NAMESPACE}..."
echo ""

kubectl get namespace "${NAMESPACE}" \
  -o jsonpath='{range .metadata.labels}{.key}={.value}{"\n"}{end}' \
  2>/dev/null | grep -E "pod-security|pss" || echo "  No PSS labels found on namespace ${NAMESPACE}"

echo ""
echo "Namespace labels:"
kubectl get namespace "${NAMESPACE}" --show-labels 2>/dev/null || true

# --- NetworkPolicy check ---
echo ""
echo "=== Phase 4: NetworkPolicy Coverage (CM-7 Network Segmentation) ==="
echo "Checking NetworkPolicies in namespace ${NAMESPACE}..."
echo ""

NP_COUNT=$(kubectl get networkpolicy -n "${NAMESPACE}" --no-headers 2>/dev/null | wc -l | tr -d ' ')
if [[ "${NP_COUNT}" -eq 0 ]]; then
  echo "  FINDING: No NetworkPolicies found in namespace ${NAMESPACE}"
  echo "  All pod-to-pod traffic is unrestricted within the namespace"
else
  echo "  NetworkPolicies found: ${NP_COUNT}"
  kubectl get networkpolicy -n "${NAMESPACE}" 2>/dev/null
fi

# --- Resource limits check ---
echo ""
echo "=== Phase 5: Resource Limits Check (CM-7) ==="
echo "Checking deployments for resource limit configuration..."
echo ""

for DEPLOY in portfolio-anthra-portfolio-app-api portfolio-anthra-portfolio-app-ui portfolio-anthra-portfolio-app-chroma; do
  echo "Deployment: ${DEPLOY}"
  LIMITS=$(kubectl get deployment "${DEPLOY}" -n "${NAMESPACE}" \
    -o jsonpath='{.spec.template.spec.containers[0].resources.limits}' \
    2>/dev/null || echo "NOT FOUND")
  if [[ "${LIMITS}" == "{}" || "${LIMITS}" == "null" || "${LIMITS}" == "" ]]; then
    echo "  FINDING: No resource limits set"
  else
    echo "  Limits: ${LIMITS}"
  fi
done

# --- securityContext check ---
echo ""
echo "=== Phase 6: Security Context Check (CIS 5.2 Pod Security Standards) ==="
echo "Checking pods for security context configuration..."
echo ""

for DEPLOY in portfolio-anthra-portfolio-app-api portfolio-anthra-portfolio-app-ui portfolio-anthra-portfolio-app-chroma; do
  echo "Deployment: ${DEPLOY}"
  RUN_AS_NON_ROOT=$(kubectl get deployment "${DEPLOY}" -n "${NAMESPACE}" \
    -o jsonpath='{.spec.template.spec.securityContext.runAsNonRoot}' \
    2>/dev/null || echo "not set")
  READONLY_FS=$(kubectl get deployment "${DEPLOY}" -n "${NAMESPACE}" \
    -o jsonpath='{.spec.template.spec.containers[0].securityContext.readOnlyRootFilesystem}' \
    2>/dev/null || echo "not set")
  ALLOW_PRIV=$(kubectl get deployment "${DEPLOY}" -n "${NAMESPACE}" \
    -o jsonpath='{.spec.template.spec.containers[0].securityContext.allowPrivilegeEscalation}' \
    2>/dev/null || echo "not set")
  echo "  runAsNonRoot:           ${RUN_AS_NON_ROOT:-not set}"
  echo "  readOnlyRootFilesystem: ${READONLY_FS:-not set}"
  echo "  allowPrivilegeEscalation: ${ALLOW_PRIV:-not set}"
done

# --- Final summary ---
echo ""
echo "=== Baseline Complete ==="
echo ""
echo "Audit Summary:"
echo "  kube-bench PASS: ${KB_PASS}"
echo "  kube-bench FAIL: ${KB_FAIL}  <-- these are your findings"
echo "  kube-bench WARN: ${KB_WARN}  <-- these need human review"
echo "  NetworkPolicies: ${NP_COUNT}"
echo ""
echo "All output saved to: ${BASELINE_DIR}/"
echo ""
echo "NEXT STEP: Read detect.md to understand what you just found."
echo "           Then run fix.sh to address the top 5 findings."
echo "           Then run verify.sh to confirm improvement."
