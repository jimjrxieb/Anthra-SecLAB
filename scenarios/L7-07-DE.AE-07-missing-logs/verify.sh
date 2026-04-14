#!/usr/bin/env bash
# =============================================================================
# L7-07 — DE.AE-07: Log Source Stopped (Fluent Bit Node Gap)
# Phase: VERIFY — Confirm all nodes have Fluent Bit pods; log flow consistent
#
# CSF:       DETECT / DE.AE-07 (Threat intel and contextual info integrated)
# CIS v8:    8.2 — Collect Audit Logs
# NIST:      AU-2 — Event Logging
# Cluster:   k3d-seclab
# Namespace: logging (Fluent Bit DaemonSet)
#
# WHAT THIS DOES:
#   1. Confirms all cluster nodes have exactly one Running Fluent Bit pod
#   2. Verifies no nodes are cordoned
#   3. Spot-checks log flow from each Fluent Bit pod
#   4. Confirms anthra namespace logs are flowing from all nodes
#
# PASS criteria:
#   - Fluent Bit pod count == node count
#   - All Fluent Bit pods are Running
#   - No nodes are cordoned
#   - Each Fluent Bit pod has recent log activity
# =============================================================================
set -euo pipefail

LOGGING_NS="logging"
ANTHRA_NS="anthra"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

PASS_COUNT=0
FAIL_COUNT=0

echo "============================================================"
echo "L7-07 VERIFY — Fluent Bit Coverage and Log Flow"
echo "Timestamp: ${TIMESTAMP}"
echo "============================================================"
echo ""

# --- Check 1: Node count vs Fluent Bit pod count ---
echo "[CHECK 1] Fluent Bit pod count vs node count"
echo "------------------------------------------------------------"
NODE_COUNT=$(kubectl get nodes --no-headers 2>/dev/null | wc -l | tr -d ' ')
FB_COUNT=$(kubectl get pods -n "${LOGGING_NS}" \
  -l app.kubernetes.io/name=fluent-bit \
  --no-headers 2>/dev/null | wc -l | tr -d ' ')
FB_RUNNING=$(kubectl get pods -n "${LOGGING_NS}" \
  -l app.kubernetes.io/name=fluent-bit \
  --no-headers 2>/dev/null | grep "Running" | wc -l | tr -d ' ')

echo "  Total nodes:         ${NODE_COUNT}"
echo "  Fluent Bit pods:     ${FB_COUNT}"
echo "  Fluent Bit Running:  ${FB_RUNNING}"

if [[ "${FB_RUNNING}" -eq "${NODE_COUNT}" ]]; then
  echo "  PASS: All nodes have a Running Fluent Bit pod."
  PASS_COUNT=$(( PASS_COUNT + 1 ))
elif [[ "${FB_COUNT}" -eq "${NODE_COUNT}" && "${FB_RUNNING}" -lt "${NODE_COUNT}" ]]; then
  echo "  PARTIAL: All pods exist but not all are Running."
  echo "           Wait for pods to become Ready and re-run verify.sh."
  FAIL_COUNT=$(( FAIL_COUNT + 1 ))
else
  echo "  FAIL: ${FB_RUNNING} Running pods for ${NODE_COUNT} nodes."
  echo "        Run: kubectl get pods -n ${LOGGING_NS} -o wide"
  FAIL_COUNT=$(( FAIL_COUNT + 1 ))
fi
echo ""

# --- Check 2: Pod-to-node mapping ---
echo "[CHECK 2] Pod-to-node mapping (each node must appear exactly once)"
echo "------------------------------------------------------------"
echo "  Node list:"
kubectl get nodes --no-headers 2>/dev/null | awk '{printf "  - %-40s %s\n", $1, $2}'
echo ""
echo "  Fluent Bit pod placement:"
kubectl get pods -n "${LOGGING_NS}" \
  -l app.kubernetes.io/name=fluent-bit \
  -o wide --no-headers 2>/dev/null \
  | awk '{printf "  Pod: %-55s Node: %-30s Status: %s\n", $1, $7, $3}' \
  || echo "  (no pods found)"

# Check for any node NOT in the pod list
NODES=$(kubectl get nodes --no-headers 2>/dev/null | awk '{print $1}')
COVERED_NODES=$(kubectl get pods -n "${LOGGING_NS}" \
  -l app.kubernetes.io/name=fluent-bit \
  -o wide --no-headers 2>/dev/null | awk '{print $7}')

UNCOVERED=0
for NODE in ${NODES}; do
  if ! echo "${COVERED_NODES}" | grep -q "^${NODE}$"; then
    echo "  UNCOVERED NODE: ${NODE} — no Fluent Bit pod scheduled here"
    UNCOVERED=$(( UNCOVERED + 1 ))
  fi
done

if [[ "${UNCOVERED}" -eq 0 ]]; then
  echo "  PASS: All nodes are covered."
  PASS_COUNT=$(( PASS_COUNT + 1 ))
else
  echo "  FAIL: ${UNCOVERED} node(s) have no Fluent Bit pod."
  FAIL_COUNT=$(( FAIL_COUNT + 1 ))
fi
echo ""

# --- Check 3: No cordoned nodes ---
echo "[CHECK 3] Node schedulability (no cordoned nodes)"
echo "------------------------------------------------------------"
CORDONED=$(kubectl get nodes --no-headers 2>/dev/null \
  | grep "SchedulingDisabled" | awk '{print $1}' || true)

if [[ -z "${CORDONED}" ]]; then
  echo "  PASS: No cordoned nodes. DaemonSet can schedule on all nodes."
  PASS_COUNT=$(( PASS_COUNT + 1 ))
else
  echo "  FAIL: The following nodes are cordoned:"
  echo "${CORDONED}" | awk '{print "  - "$1}'
  echo "  Fluent Bit cannot schedule on cordoned nodes."
  echo "  Uncordon with: kubectl uncordon <node-name>"
  FAIL_COUNT=$(( FAIL_COUNT + 1 ))
fi
echo ""

# --- Check 4: Log flow spot check per pod ---
echo "[CHECK 4] Log flow check (recent activity per Fluent Bit pod)"
echo "------------------------------------------------------------"
FB_ACTIVE=0
FB_TOTAL=0

for FB_POD in $(kubectl get pods -n "${LOGGING_NS}" \
  -l app.kubernetes.io/name=fluent-bit \
  --no-headers 2>/dev/null | grep "Running" | awk '{print $1}'); do
  FB_TOTAL=$(( FB_TOTAL + 1 ))

  LAST_LINE=$(kubectl logs -n "${LOGGING_NS}" "${FB_POD}" \
    --tail=1 2>/dev/null | tr -d '\n' || echo "")

  if [[ -n "${LAST_LINE}" ]]; then
    FB_ACTIVE=$(( FB_ACTIVE + 1 ))
    echo "  ${FB_POD}: active (last line: ${LAST_LINE:0:80})"
  else
    echo "  ${FB_POD}: NO LOG OUTPUT — pod may not be collecting"
  fi
done

if [[ "${FB_ACTIVE}" -eq "${FB_TOTAL}" && "${FB_TOTAL}" -gt 0 ]]; then
  echo "  PASS: All ${FB_TOTAL} Fluent Bit pods have recent log activity."
  PASS_COUNT=$(( PASS_COUNT + 1 ))
elif [[ "${FB_TOTAL}" -eq 0 ]]; then
  echo "  FAIL: No Running Fluent Bit pods to check."
  FAIL_COUNT=$(( FAIL_COUNT + 1 ))
else
  echo "  PARTIAL: ${FB_ACTIVE} of ${FB_TOTAL} pods have log activity."
  FAIL_COUNT=$(( FAIL_COUNT + 1 ))
fi
echo ""

# --- Check 5: Anthra namespace logs flowing ---
echo "[CHECK 5] Anthra namespace log flow confirmation"
echo "------------------------------------------------------------"
ANTHRA_LOG_FOUND=0
for POD in $(kubectl get pods -n "${ANTHRA_NS}" --no-headers 2>/dev/null \
  | awk '{print $1}' | head -3); do
  LINE=$(kubectl logs -n "${ANTHRA_NS}" "${POD}" \
    --tail=1 --timestamps=true 2>/dev/null || echo "")
  if [[ -n "${LINE}" ]]; then
    ANTHRA_LOG_FOUND=$(( ANTHRA_LOG_FOUND + 1 ))
    echo "  ${POD}: ${LINE:0:100}"
  else
    echo "  ${POD}: no recent logs"
  fi
done

if [[ "${ANTHRA_LOG_FOUND}" -gt 0 ]]; then
  echo "  PASS: anthra namespace logs are flowing."
  PASS_COUNT=$(( PASS_COUNT + 1 ))
else
  echo "  WARN: No anthra logs found. May indicate collection is not working."
  echo "        Check anthra pods are running: kubectl get pods -n anthra"
  FAIL_COUNT=$(( FAIL_COUNT + 1 ))
fi
echo ""

# --- Summary ---
echo "============================================================"
echo "VERIFY SUMMARY — ${TIMESTAMP}"
echo ""
echo "  Checks passed: ${PASS_COUNT}"
echo "  Checks failed: ${FAIL_COUNT}"
echo ""

if [[ "${FAIL_COUNT}" -eq 0 ]]; then
  echo "  RESULT: PASS"
  echo "  All nodes have Fluent Bit coverage. Log collection is complete."
  echo "  AU-2 gap has been closed."
  echo ""
  echo "  Record this output as verification evidence for the POA&M."
  echo "  Complete remediate.md to document the gap event."
else
  echo "  RESULT: FAIL"
  echo "  ${FAIL_COUNT} check(s) did not pass."
  echo "  Review the failures above."
  echo "  If nodes are still cordoned, run fix.sh."
fi
echo ""
echo "  Compare against baseline.sh output to confirm full coverage restored."
echo "============================================================"
