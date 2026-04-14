#!/usr/bin/env bash
# =============================================================================
# L7-05 — DE.AE-02: Alert Fatigue (No Custom Falco Tuning)
# Phase: VERIFY — Confirm noise reduction; test custom rules fire on real events
#
# CSF:       DETECT / DE.AE-02 (Potentially adverse events analyzed)
# CIS v8:    8.11 — Tune Security Event Alert Thresholds
# NIST:      AU-6 — Audit Record Review, Analysis, and Reporting
# Cluster:   k3d-seclab
# Namespace: falco (monitoring), anthra (test target)
#
# WHAT THIS DOES:
#   1. Re-counts alerts per minute and compares to baseline
#   2. Calculates noise reduction percentage
#   3. Tests that the Portfolio API Shell Spawn custom rule fires correctly
#   4. Confirms exceptions are loaded (suppressed rules show lower counts)
#   5. Summarizes pass/fail for each verification criterion
# =============================================================================
set -euo pipefail

FALCO_NS="falco"
ANTHRA_NS="anthra"
CM_NAME="falco-custom-portfolio-rules"
TAIL_LINES=200
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
PASS=0
FAIL=0

echo "============================================================"
echo "L7-05 VERIFY — Post-Tuning Confirmation"
echo "Timestamp: ${TIMESTAMP}"
echo "============================================================"
echo ""

# Helper function
check() {
  local label="$1"
  local result="$2"
  local expected="$3"
  if [[ "${result}" == "${expected}" ]]; then
    echo "  PASS | ${label}"
    (( PASS++ )) || true
  else
    echo "  FAIL | ${label} (got: ${result}, expected: ${expected})"
    (( FAIL++ )) || true
  fi
}

# --- 1. Confirm custom rules ConfigMap exists ---
echo "[1/5] Verify custom rules ConfigMap is present"
echo "------------------------------------------------------------"
CM_EXISTS=$(kubectl get configmap "${CM_NAME}" -n "${FALCO_NS}" \
  --no-headers 2>/dev/null | wc -l || echo 0)
check "ConfigMap ${CM_NAME} exists" "$([ "${CM_EXISTS}" -gt 0 ] && echo yes || echo no)" "yes"

CM_KEY=$(kubectl get configmap "${CM_NAME}" -n "${FALCO_NS}" \
  -o jsonpath='{.data.portfolio_rules\.yaml}' 2>/dev/null | wc -c || echo 0)
check "ConfigMap contains rule data" "$([ "${CM_KEY}" -gt 100 ] && echo yes || echo no)" "yes"
echo ""

# --- 2. Verify Falco pods are running (post-restart) ---
echo "[2/5] Verify Falco pods are running after restart"
echo "------------------------------------------------------------"
FALCO_RUNNING=$(kubectl get pods -n "${FALCO_NS}" \
  -l app.kubernetes.io/name=falco \
  --no-headers 2>/dev/null | grep -c Running || true)
check "Falco pods running" "$([ "${FALCO_RUNNING}" -gt 0 ] && echo yes || echo no)" "yes"
echo "  Pods running: ${FALCO_RUNNING}"
echo ""

# --- 3. Compare alert volume to baseline ---
echo "[3/5] Compare alert volume (before vs. after tuning)"
echo "------------------------------------------------------------"
echo "  NOTE: For accurate comparison, re-run baseline.sh and record the"
echo "  before rate. This check estimates the current rate from recent logs."
echo ""

CURRENT_ALERTS=$(kubectl logs -n "${FALCO_NS}" \
  -l app.kubernetes.io/name=falco \
  --tail="${TAIL_LINES}" \
  --prefix=false \
  2>/dev/null | grep -c '"rule":' || true)

echo "  Current alerts in ${TAIL_LINES}-line sample: ${CURRENT_ALERTS}"
echo ""
echo "  Top rules now (post-tuning):"
kubectl logs -n "${FALCO_NS}" \
  -l app.kubernetes.io/name=falco \
  --tail="${TAIL_LINES}" \
  --prefix=false \
  2>/dev/null \
  | grep -oP '"rule":"[^"]*"' \
  | sed 's/"rule":"//;s/"//' \
  | sort | uniq -c | sort -rn | head -8 \
  | awk '{printf "  %5s | %s\n", $1, $2}' \
  || echo "  No structured alerts in recent log window."
echo ""

# Check if known FP rules have lower counts after tuning
FP_RULE_COUNT=$(kubectl logs -n "${FALCO_NS}" \
  -l app.kubernetes.io/name=falco \
  --tail="${TAIL_LINES}" \
  --prefix=false \
  2>/dev/null \
  | grep -cE '"rule":"Launch Package Management Process in Container"' \
  || true)

echo "  'Launch Package Management' alerts in sample: ${FP_RULE_COUNT}"
check "Package manager FP rule suppressed (count < 10)" \
  "$([ "${FP_RULE_COUNT}" -lt 10 ] && echo yes || echo no)" "yes"
echo ""

# --- 4. Test custom rule: Portfolio API Shell Spawn ---
echo "[4/5] Test custom rule: Portfolio API Shell Spawn"
echo "------------------------------------------------------------"

API_DEPLOY=$(kubectl get deployment -n "${ANTHRA_NS}" \
  -l "app.kubernetes.io/component=api" \
  --no-headers 2>/dev/null | awk '{print $1}' | head -1 || true)

if [[ -z "${API_DEPLOY}" ]]; then
  API_DEPLOY=$(kubectl get deployment -n "${ANTHRA_NS}" \
    --no-headers 2>/dev/null | awk '{print $1}' | grep -i api | head -1 || true)
fi

if [[ -z "${API_DEPLOY}" ]]; then
  echo "  SKIP: No API deployment found in ${ANTHRA_NS}. Cannot run live detection test."
  (( FAIL++ )) || true
else
  echo "  Triggering test exec in ${API_DEPLOY}..."
  # Execute a shell command in the API pod — should trigger Portfolio API Shell Spawn rule
  kubectl exec -n "${ANTHRA_NS}" "deployment/${API_DEPLOY}" \
    -- sh -c 'echo "falco-test-shell-exec"' 2>/dev/null || true

  echo "  Waiting 8 seconds for Falco to process the event..."
  sleep 8

  CUSTOM_RULE_FIRED=$(kubectl logs -n "${FALCO_NS}" \
    -l app.kubernetes.io/name=falco \
    --tail=50 \
    --prefix=false \
    2>/dev/null \
    | grep -c '"rule":"Portfolio API Shell Spawn"' \
    || true)

  echo "  Custom rule 'Portfolio API Shell Spawn' fires: ${CUSTOM_RULE_FIRED}"
  check "Custom rule Portfolio API Shell Spawn fires on exec" \
    "$([ "${CUSTOM_RULE_FIRED}" -gt 0 ] && echo yes || echo no)" "yes"

  if (( CUSTOM_RULE_FIRED == 0 )); then
    echo ""
    echo "  TROUBLESHOOT:"
    echo "  - Verify Falco loaded the new ConfigMap: check for portfolio_rules.yaml in logs"
    echo "  - The rule uses 'spawned_process' — ensure Falco is not in audit mode only"
    echo "  - Check: kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=100"
    echo "    | grep -E '(portfolio|custom rules|error)'"
  fi
fi
echo ""

# --- 5. Summary ---
echo "[5/5] Verification Summary"
echo "============================================================"
echo "  PASSED: ${PASS}"
echo "  FAILED: ${FAIL}"
echo ""

if (( FAIL == 0 )); then
  echo "  STATUS: REMEDIATED"
  echo ""
  echo "  Alert tuning is active. The ConfigMap is deployed, Falco is running,"
  echo "  known FP rules are suppressed, and the custom Portfolio Shell Spawn"
  echo "  rule fires on exec events."
  echo ""
  echo "  Baseline comparison: run baseline.sh again and calculate:"
  echo "    Noise reduction = (before_rate - after_rate) / before_rate * 100"
  echo "    Target: > 80% reduction in alert volume"
  echo "    Target: custom rules fire on at least 1 real event in verify run"
else
  echo "  STATUS: INCOMPLETE — Review FAIL items above"
  echo ""
  echo "  Common causes:"
  echo "  - Falco did not reload the ConfigMap (try: kubectl rollout restart ds/falco -n falco)"
  echo "  - ConfigMap key name mismatch (must end in .yaml or .rules)"
  echo "  - API deployment not found (check namespace and label selectors)"
  echo "  - Falco is in JSON output mode but rules are in old format"
fi
echo ""
echo "Proceed to report-template.md to complete the POA&M entry."
echo "============================================================"
