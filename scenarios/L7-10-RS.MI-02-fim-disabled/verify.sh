#!/usr/bin/env bash
#
# CSF: RESPOND / RS.MI-02 — Incidents are eradicated
# CIS v8: 3.14 — Log Sensitive Data Access
# NIST 800-53: SI-7 — Software, Firmware, and Information Integrity
#
# L7-10 RS.MI-02 — Verify: Confirm Falco FIM rule fires on /tmp write
#
# Test sequence:
#   1. Write a test file to /tmp in the API pod
#   2. Wait for Falco to process the syscall event
#   3. Check Falco logs for the expected WARNING alert
#   4. Clean up the test file
#   5. Report PASS or FAIL with troubleshooting guidance
#
# Usage: bash verify.sh
# Expected: Falco emits a WARNING for the test write — PASS

set -euo pipefail

NAMESPACE="anthra"
FALCO_NAMESPACE="falco"
LABEL_SELECTOR="app.kubernetes.io/component=api"
TEST_FILE="/tmp/falco-fim-verify-$(date +%s).txt"
WAIT_SECONDS=10

echo "=== L7-10 RS.MI-02 Verify: Confirming Falco FIM rule is active ==="
echo "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "Test file: ${TEST_FILE}"
echo ""

PASS=0
FAIL=0

# ── Locate the API pod ───────────────────────────────────────────────────────

API_POD=$(kubectl get pods -n "${NAMESPACE}" \
  -l "${LABEL_SELECTOR}" \
  --field-selector=status.phase=Running \
  -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)

if [[ -z "${API_POD}" ]]; then
  echo "ERROR: No running API pod found in namespace '${NAMESPACE}'"
  echo "       Check: kubectl get pods -n ${NAMESPACE}"
  exit 1
fi

echo "API pod: ${API_POD}"

# ── Locate Falco pod ─────────────────────────────────────────────────────────

FALCO_POD=$(kubectl get pods -n "${FALCO_NAMESPACE}" \
  -l "app.kubernetes.io/name=falco" \
  --field-selector=status.phase=Running \
  -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)

if [[ -z "${FALCO_POD}" ]]; then
  echo "ERROR: No running Falco pod found in namespace '${FALCO_NAMESPACE}'"
  echo "       Check: kubectl get pods -n ${FALCO_NAMESPACE}"
  exit 1
fi

echo "Falco pod: ${FALCO_POD}"
echo ""

# ── Step 1: Verify custom rule ConfigMap exists ──────────────────────────────

echo "--- Check 1: Custom rule ConfigMap exists ---"
if kubectl get configmap falco-fim-anthra-rules -n "${FALCO_NAMESPACE}" &>/dev/null; then
  printf "  PASS  ConfigMap 'falco-fim-anthra-rules' exists in ${FALCO_NAMESPACE}\n"
  PASS=$(( PASS + 1 ))
else
  printf "  FAIL  ConfigMap 'falco-fim-anthra-rules' not found — run fix.sh first\n"
  FAIL=$(( FAIL + 1 ))
fi
echo ""

# ── Step 2: Write a test file to /tmp ────────────────────────────────────────

echo "--- Check 2: Write test file to /tmp ---"
echo "Writing: ${TEST_FILE}"

kubectl exec -n "${NAMESPACE}" "${API_POD}" -- \
  /bin/sh -c "echo 'falco-fim-verify-test' > ${TEST_FILE} && echo 'Write succeeded'" \
  2>/dev/null

# Confirm the file exists
FILE_EXISTS=$(kubectl exec -n "${NAMESPACE}" "${API_POD}" -- \
  /bin/sh -c "[ -f ${TEST_FILE} ] && echo 'yes' || echo 'no'" 2>/dev/null || echo "no")

if [[ "${FILE_EXISTS}" == "yes" ]]; then
  printf "  PASS  Test file written successfully to /tmp in API pod\n"
  PASS=$(( PASS + 1 ))
else
  printf "  FAIL  Test file write failed — /tmp may not be writable\n"
  FAIL=$(( FAIL + 1 ))
fi
echo ""

# ── Step 3: Wait for Falco to process the syscall event ──────────────────────

echo "--- Waiting ${WAIT_SECONDS}s for Falco to process the write event ---"
echo "(Falco processes syscall events in near-real-time; brief wait for log flush)"
sleep "${WAIT_SECONDS}"
echo ""

# ── Step 4: Check Falco logs for the expected alert ──────────────────────────

echo "--- Check 3: Falco alert fired for /tmp write ---"

# Search Falco logs for the rule output from our test write
FALCO_ALERT=$(kubectl logs -n "${FALCO_NAMESPACE}" "${FALCO_POD}" \
  --tail=200 --since=60s 2>/dev/null \
  | grep -i "Write to Temp in Portfolio API\|falco-fim-verify\|${NAMESPACE}.*api.*tmp\|tmp.*anthra" \
  | head -5 || true)

if [[ -n "${FALCO_ALERT}" ]]; then
  printf "  PASS  Falco alert found:\n"
  echo "${FALCO_ALERT}" | while IFS= read -r line; do
    printf "        %s\n" "${line}"
  done
  PASS=$(( PASS + 1 ))
else
  printf "  FAIL  No Falco alert found for the test write\n"
  printf "        The rule may not be loaded or the ConfigMap is not mounted\n"
  FAIL=$(( FAIL + 1 ))
fi
echo ""

# ── Step 5: Clean up the test file ───────────────────────────────────────────

echo "--- Cleanup: removing test file from /tmp ---"
kubectl exec -n "${NAMESPACE}" "${API_POD}" -- \
  /bin/sh -c "rm -f ${TEST_FILE} && echo 'Test file removed'" \
  2>/dev/null || echo "WARNING: Could not remove test file (may have already been cleaned)"

# Confirm cleanup
STILL_EXISTS=$(kubectl exec -n "${NAMESPACE}" "${API_POD}" -- \
  /bin/sh -c "[ -f ${TEST_FILE} ] && echo 'yes' || echo 'no'" 2>/dev/null || echo "no")

if [[ "${STILL_EXISTS}" == "no" ]]; then
  printf "  PASS  Test file cleaned up\n"
  PASS=$(( PASS + 1 ))
else
  printf "  WARNING  Test file still present — manual cleanup may be needed\n"
  printf "           kubectl exec -n %s %s -- rm -f %s\n" \
    "${NAMESPACE}" "${API_POD}" "${TEST_FILE}"
fi
echo ""

# ── Summary ──────────────────────────────────────────────────────────────────

echo "--- Summary ---"
echo "  PASS: ${PASS}"
echo "  FAIL: ${FAIL}"
echo ""

if [[ "${FAIL}" -eq 0 ]]; then
  echo "RESULT: ALL CHECKS PASSED"
  echo ""
  echo "The Falco FIM rule is active and firing on /tmp writes in the"
  echo "Portfolio API container (anthra namespace)."
  echo ""
  echo "FIM coverage gap has been closed. RS.MI-02 detection layer is operational."
  echo ""
  echo "NEXT STEP: Fill in report-template.md with the evidence and timeline."
else
  echo "RESULT: ${FAIL} CHECK(S) FAILED"
  echo ""

  # Targeted troubleshooting
  echo "--- Troubleshooting ---"
  echo ""
  echo "1. Confirm the custom rule ConfigMap exists and has correct content:"
  echo "   kubectl get configmap falco-fim-anthra-rules -n ${FALCO_NAMESPACE} -o yaml"
  echo ""
  echo "2. Confirm Falco is loading the custom rule file:"
  echo "   kubectl logs -n ${FALCO_NAMESPACE} ${FALCO_POD} --tail=100 | grep -i 'fim-anthra\|custom\|rule'"
  echo ""
  echo "3. Check if the ConfigMap is mounted into the Falco pod:"
  echo "   kubectl describe pod ${FALCO_POD} -n ${FALCO_NAMESPACE} | grep -A 10 'Mounts'"
  echo ""
  echo "4. If the ConfigMap is not mounted, the Helm values need to be updated:"
  echo "   See fix.sh comments for the extraVolumes / extraVolumeMounts configuration"
  echo ""
  echo "5. After mounting, restart Falco:"
  echo "   kubectl rollout restart daemonset/falco -n ${FALCO_NAMESPACE}"
  echo "   kubectl rollout status daemonset/falco -n ${FALCO_NAMESPACE}"
  echo ""
  echo "6. Re-run this script after confirming the rule is loaded."

  exit 1
fi
