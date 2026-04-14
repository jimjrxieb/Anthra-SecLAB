#!/usr/bin/env bash
#
# CSF: PROTECT / PR.PS-01 — Configuration management practices applied to IT assets
# CIS v8: 4.1 — Establish and Maintain a Secure Configuration Process
# NIST 800-53: CM-6 — Configuration Settings, CM-7 — Least Functionality
#
# L7-03 PR.PS-01 — Verify: Re-run audit and compare FAIL counts before vs after
#
# This script:
#   1. Re-runs kube-bench and kubescape
#   2. Compares FAIL counts against the baseline captured in baseline.sh
#   3. Verifies the five specific fixes applied in fix.sh
#   4. Reports the delta (improvement)
#
# Usage: bash verify.sh
# Prerequisite: baseline.sh must have been run first (reads /tmp/L7-03-baseline-*/counts.txt)

set -euo pipefail

NAMESPACE="anthra"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
VERIFY_DIR="/tmp/L7-03-verify-${TIMESTAMP}"
KUBE_BENCH="/usr/local/bin/kube-bench"
KUBESCAPE="${HOME}/bin/kubescape"
DEPLOYMENTS=(
  "portfolio-anthra-portfolio-app-api"
  "portfolio-anthra-portfolio-app-ui"
  "portfolio-anthra-portfolio-app-chroma"
)

mkdir -p "${VERIFY_DIR}"

PASS_COUNT=0
FAIL_COUNT=0

check_pass() {
  echo "  PASS  $*"
  PASS_COUNT=$(( PASS_COUNT + 1 ))
}

check_fail() {
  echo "  FAIL  $*"
  FAIL_COUNT=$(( FAIL_COUNT + 1 ))
}

echo "=== L7-03 PR.PS-01 Verify: Post-Fix Audit ==="
echo "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "Namespace: ${NAMESPACE}"
echo "Output directory: ${VERIFY_DIR}"
echo ""

# --- Load baseline counts for comparison ---
BASELINE_COUNTS=$(ls /tmp/L7-03-baseline-*/counts.txt 2>/dev/null | sort | tail -1 || echo "")

if [[ -n "${BASELINE_COUNTS}" ]]; then
  echo "--- Baseline reference: ${BASELINE_COUNTS} ---"
  BASELINE_FAIL=$(grep "^kube-bench-fail=" "${BASELINE_COUNTS}" | cut -d= -f2 || echo "unknown")
  BASELINE_WARN=$(grep "^kube-bench-warn=" "${BASELINE_COUNTS}" | cut -d= -f2 || echo "unknown")
  echo "  Baseline kube-bench FAIL: ${BASELINE_FAIL}"
  echo "  Baseline kube-bench WARN: ${BASELINE_WARN}"
else
  echo "NOTE: No baseline counts file found at /tmp/L7-03-baseline-*/counts.txt"
  echo "      Run baseline.sh before fix.sh for before/after comparison."
  BASELINE_FAIL="unknown"
  BASELINE_WARN="unknown"
fi

echo ""

# --- Re-run kube-bench ---
echo "=== Phase 1: kube-bench Re-scan ==="
echo "Running node benchmark (30-60 seconds)..."
echo ""

if [[ -x "${KUBE_BENCH}" ]]; then
  ${KUBE_BENCH} run --targets node 2>/dev/null \
    | tee "${VERIFY_DIR}/kube-bench-output.txt"

  echo ""
  echo "--- kube-bench Result Counts (post-fix) ---"
  KB_PASS=$(grep -cE "^\[PASS\]" "${VERIFY_DIR}/kube-bench-output.txt" 2>/dev/null || echo 0)
  KB_FAIL=$(grep -cE "^\[FAIL\]" "${VERIFY_DIR}/kube-bench-output.txt" 2>/dev/null || echo 0)
  KB_WARN=$(grep -cE "^\[WARN\]" "${VERIFY_DIR}/kube-bench-output.txt" 2>/dev/null || echo 0)

  echo "  PASS: ${KB_PASS}"
  echo "  FAIL: ${KB_FAIL}"
  echo "  WARN: ${KB_WARN}"

  echo ""
  echo "--- Delta vs Baseline ---"
  if [[ "${BASELINE_FAIL}" != "unknown" ]]; then
    DELTA=$(( BASELINE_FAIL - KB_FAIL ))
    if [[ ${DELTA} -gt 0 ]]; then
      echo "  FAIL count reduced by ${DELTA} (was ${BASELINE_FAIL}, now ${KB_FAIL})"
    elif [[ ${DELTA} -eq 0 ]]; then
      echo "  FAIL count unchanged (${KB_FAIL}) — node-level findings require cluster admin"
    else
      echo "  FAIL count increased by $(( -DELTA )) — investigate new findings"
    fi
  else
    echo "  No baseline for comparison. Current FAIL count: ${KB_FAIL}"
  fi
else
  echo "SKIP: kube-bench not found at ${KUBE_BENCH}"
fi

# --- Re-run kubescape ---
echo ""
echo "=== Phase 2: kubescape Re-scan ==="
echo "Running kubescape on namespace ${NAMESPACE}..."
echo ""

if [[ -x "${KUBESCAPE}" ]]; then
  ${KUBESCAPE} scan \
    --format pretty \
    namespace "${NAMESPACE}" \
    2>/dev/null \
    | tail -25 \
    | tee "${VERIFY_DIR}/kubescape-summary.txt" || true
  echo ""
  echo "kubescape summary saved to: ${VERIFY_DIR}/kubescape-summary.txt"
else
  echo "SKIP: kubescape not found at ${KUBESCAPE}"
fi

# --- Verify Fix 1: securityContext ---
echo ""
echo "=== Verification: Fix 1 — Security Context ==="
echo ""

for DEPLOY in "${DEPLOYMENTS[@]}"; do
  if ! kubectl get deployment "${DEPLOY}" -n "${NAMESPACE}" &>/dev/null; then
    echo "  SKIP: ${DEPLOY} not found"
    continue
  fi

  ALLOW_PRIV=$(kubectl get deployment "${DEPLOY}" -n "${NAMESPACE}" \
    -o jsonpath='{.spec.template.spec.containers[0].securityContext.allowPrivilegeEscalation}' \
    2>/dev/null || echo "")
  READONLY_FS=$(kubectl get deployment "${DEPLOY}" -n "${NAMESPACE}" \
    -o jsonpath='{.spec.template.spec.containers[0].securityContext.readOnlyRootFilesystem}' \
    2>/dev/null || echo "")
  RUN_NON_ROOT=$(kubectl get deployment "${DEPLOY}" -n "${NAMESPACE}" \
    -o jsonpath='{.spec.template.spec.securityContext.runAsNonRoot}' \
    2>/dev/null || echo "")

  echo "  Deployment: ${DEPLOY}"

  if [[ "${ALLOW_PRIV}" == "false" ]]; then
    check_pass "allowPrivilegeEscalation=false (CIS 5.2.5)"
  else
    check_fail "allowPrivilegeEscalation=${ALLOW_PRIV:-not set} — should be false (CIS 5.2.5)"
  fi

  if [[ "${READONLY_FS}" == "true" ]]; then
    check_pass "readOnlyRootFilesystem=true (CIS 5.2.4)"
  else
    check_fail "readOnlyRootFilesystem=${READONLY_FS:-not set} — should be true (CIS 5.2.4)"
  fi

  if [[ "${RUN_NON_ROOT}" == "true" ]]; then
    check_pass "runAsNonRoot=true (CIS 5.2.6)"
  else
    check_fail "runAsNonRoot=${RUN_NON_ROOT:-not set} — should be true (CIS 5.2.6)"
  fi

  echo ""
done

# --- Verify Fix 2: NetworkPolicy ---
echo "=== Verification: Fix 2 — NetworkPolicy ==="
echo ""

NP_COUNT=$(kubectl get networkpolicy -n "${NAMESPACE}" --no-headers 2>/dev/null | wc -l | tr -d ' ')

if [[ "${NP_COUNT}" -gt 0 ]]; then
  check_pass "${NP_COUNT} NetworkPolicy/ies exist in namespace ${NAMESPACE} (CIS 5.3.2)"
  kubectl get networkpolicy -n "${NAMESPACE}" 2>/dev/null
else
  check_fail "No NetworkPolicies in namespace ${NAMESPACE} (CIS 5.3.2)"
fi

echo ""

# --- Verify Fix 3: Resource limits ---
echo "=== Verification: Fix 3 — Resource Limits ==="
echo ""

for DEPLOY in "${DEPLOYMENTS[@]}"; do
  if ! kubectl get deployment "${DEPLOY}" -n "${NAMESPACE}" &>/dev/null; then
    echo "  SKIP: ${DEPLOY} not found"
    continue
  fi

  CPU_LIMIT=$(kubectl get deployment "${DEPLOY}" -n "${NAMESPACE}" \
    -o jsonpath='{.spec.template.spec.containers[0].resources.limits.cpu}' \
    2>/dev/null || echo "")
  MEM_LIMIT=$(kubectl get deployment "${DEPLOY}" -n "${NAMESPACE}" \
    -o jsonpath='{.spec.template.spec.containers[0].resources.limits.memory}' \
    2>/dev/null || echo "")

  if [[ -n "${CPU_LIMIT}" && -n "${MEM_LIMIT}" ]]; then
    check_pass "${DEPLOY} — cpu=${CPU_LIMIT}, memory=${MEM_LIMIT} (CIS 5.7.4)"
  else
    check_fail "${DEPLOY} — resource limits missing: cpu=${CPU_LIMIT:-unset}, memory=${MEM_LIMIT:-unset} (CIS 5.7.4)"
    echo "        NOTE: Add to POA&M — requires workload profiling to set correct values"
  fi
done

echo ""

# --- Verify Fix 4: PSS labels ---
echo "=== Verification: Fix 4 — PSS Labels ==="
echo ""

PSS_ENFORCE=$(kubectl get namespace "${NAMESPACE}" \
  -o jsonpath='{.metadata.labels.pod-security\.kubernetes\.io/enforce}' \
  2>/dev/null || echo "")

if [[ -n "${PSS_ENFORCE}" ]]; then
  check_pass "PSS enforce label present: ${PSS_ENFORCE} (CIS 5.2.1)"
else
  check_fail "No PSS enforce label on namespace ${NAMESPACE} (CIS 5.2.1)"
fi

echo ""

# --- Verify Fix 5: automountServiceAccountToken ---
echo "=== Verification: Fix 5 — Service Account Token Auto-Mount ==="
echo ""

for DEPLOY in "${DEPLOYMENTS[@]}"; do
  if ! kubectl get deployment "${DEPLOY}" -n "${NAMESPACE}" &>/dev/null; then
    echo "  SKIP: ${DEPLOY} not found"
    continue
  fi

  AUTO_MOUNT=$(kubectl get deployment "${DEPLOY}" -n "${NAMESPACE}" \
    -o jsonpath='{.spec.template.spec.automountServiceAccountToken}' \
    2>/dev/null || echo "")

  if [[ "${AUTO_MOUNT}" == "false" ]]; then
    check_pass "${DEPLOY} — automountServiceAccountToken=false (CIS 5.1.6)"
  else
    check_fail "${DEPLOY} — automountServiceAccountToken=${AUTO_MOUNT:-not set} (CIS 5.1.6)"
  fi
done

# --- Final summary ---
echo ""
echo "=== Verification Summary ==="
echo ""
echo "  Specific fix checks:"
echo "    PASS: ${PASS_COUNT}"
echo "    FAIL: ${FAIL_COUNT}"
echo ""

if [[ "${BASELINE_FAIL}" != "unknown" ]]; then
  echo "  kube-bench FAIL count:"
  echo "    Before: ${BASELINE_FAIL}"
  echo "    After:  ${KB_FAIL:-unknown}"
fi

echo ""

if [[ "${FAIL_COUNT}" -eq 0 ]]; then
  echo "RESULT: ALL SPECIFIC CHECKS PASSED"
  echo ""
  echo "The five targeted findings have been remediated."
  echo "Remaining kube-bench failures are node-level (kubelet config)."
  echo "Document those in the POA&M. See remediate.md for kubelet guidance."
  echo ""
  echo "NEXT STEP: Fill in report-template.md with the evidence and timeline."
else
  echo "RESULT: ${FAIL_COUNT} CHECK(S) STILL FAILING"
  echo ""
  echo "Review the FAIL lines above and re-run fix.sh for any items not yet addressed."
  echo "Check if rollouts completed: kubectl get pods -n ${NAMESPACE}"
fi

echo ""
echo "Verify output saved to: ${VERIFY_DIR}/"
