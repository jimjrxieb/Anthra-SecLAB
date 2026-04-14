#!/usr/bin/env bash
# =============================================================================
# L7-07 — DE.AE-07: Log Source Stopped (Fluent Bit Node Gap)
# Phase: FIX — Restore Fluent Bit coverage on the affected node
#
# CSF:       DETECT / DE.AE-07 (Threat intel and contextual info integrated)
# CIS v8:    8.2 — Collect Audit Logs
# NIST:      AU-2 — Event Logging
# Cluster:   k3d-seclab
# Namespace: logging (Fluent Bit DaemonSet)
#
# WHAT THIS DOES:
#   1. Reads the cordoned node name from /tmp/l7-07-cordoned-node.txt
#      (written by break.sh when EXTENDED_BREAK=true)
#   2. Uncordons the node so the DaemonSet can reschedule
#   3. Waits for the Fluent Bit pod to become Ready on that node
#   4. Confirms log flow has resumed from the previously silent node
#
# RANK: D — Restoring a logging agent is operational, not a policy change.
#       Auto-fix with logging. The gap documentation (AU-2 record) is the
#       human-required step — that happens in remediate.md.
# =============================================================================
set -euo pipefail

LOGGING_NS="logging"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo "============================================================"
echo "L7-07 FIX — Restore Fluent Bit Node Coverage"
echo "Timestamp: ${TIMESTAMP}"
echo "============================================================"
echo ""

# --- Determine which node to uncordon ---
CORDONED_NODE=""

if [[ -f /tmp/l7-07-cordoned-node.txt ]]; then
  CORDONED_NODE=$(cat /tmp/l7-07-cordoned-node.txt | tr -d '[:space:]')
  echo "  Found cordoned node from break.sh: ${CORDONED_NODE}"
else
  echo "  /tmp/l7-07-cordoned-node.txt not found."
  echo "  Looking for cordoned nodes in the cluster..."
  CORDONED_NODE=$(kubectl get nodes --no-headers 2>/dev/null \
    | grep "SchedulingDisabled" | awk '{print $1}' | head -1 || true)

  if [[ -n "${CORDONED_NODE}" ]]; then
    echo "  Found cordoned node: ${CORDONED_NODE}"
  else
    echo "  No cordoned nodes found."
    echo ""
    echo "  If break.sh was run WITHOUT EXTENDED_BREAK=true, the DaemonSet"
    echo "  may have already restarted the pod automatically."
    echo ""
    echo "  Checking current Fluent Bit pod count..."
    NODE_COUNT=$(kubectl get nodes --no-headers 2>/dev/null | wc -l | tr -d ' ')
    FB_COUNT=$(kubectl get pods -n "${LOGGING_NS}" \
      -l app.kubernetes.io/name=fluent-bit \
      --no-headers 2>/dev/null | wc -l | tr -d ' ')
    echo "  Nodes: ${NODE_COUNT} | Fluent Bit pods: ${FB_COUNT}"

    if [[ "${FB_COUNT}" -ge "${NODE_COUNT}" ]]; then
      echo ""
      echo "  Pod count matches node count — gap may already be closed."
      echo "  Run verify.sh to confirm."
      exit 0
    else
      echo ""
      echo "  Still a mismatch. A node may have a Fluent Bit scheduling issue."
      echo "  Check: kubectl get pods -n ${LOGGING_NS} -o wide"
      exit 1
    fi
  fi
fi

echo ""

# --- Pre-fix state ---
echo "  Pre-fix state:"
kubectl get nodes --no-headers 2>/dev/null \
  | awk '{printf "  Node: %-40s Status: %s\n", $1, $2}'
echo ""
kubectl get pods -n "${LOGGING_NS}" \
  -l app.kubernetes.io/name=fluent-bit \
  -o wide --no-headers 2>/dev/null \
  | awk '{printf "  Pod: %-55s Node: %-30s Status: %s\n", $1, $7, $3}' \
  || echo "  (no pods found)"
echo ""

# --- Uncordon the node ---
echo "  Uncordoning node: ${CORDONED_NODE} ..."
kubectl uncordon "${CORDONED_NODE}"
echo "  Node uncordoned. DaemonSet will now reschedule Fluent Bit."
echo ""

# --- Clean up the temp file ---
rm -f /tmp/l7-07-cordoned-node.txt
echo "  Cleared /tmp/l7-07-cordoned-node.txt"
echo ""

# --- Wait for Fluent Bit pod to become Ready on the uncordoned node ---
echo "  Waiting for Fluent Bit pod to schedule on ${CORDONED_NODE}..."
echo "  (watching for up to 90 seconds)"
echo ""

WAIT_SECONDS=90
INTERVAL=5
ELAPSED=0

while [[ "${ELAPSED}" -lt "${WAIT_SECONDS}" ]]; do
  FB_ON_NODE=$(kubectl get pods -n "${LOGGING_NS}" \
    -l app.kubernetes.io/name=fluent-bit \
    --no-headers -o wide 2>/dev/null \
    | awk -v node="${CORDONED_NODE}" '$7 == node {print $1}' | head -1 || true)

  if [[ -n "${FB_ON_NODE}" ]]; then
    POD_STATUS=$(kubectl get pod -n "${LOGGING_NS}" "${FB_ON_NODE}" \
      --no-headers 2>/dev/null | awk '{print $3}' || true)
    echo "  [${ELAPSED}s] Pod ${FB_ON_NODE} found on node — status: ${POD_STATUS}"

    if [[ "${POD_STATUS}" == "Running" ]]; then
      echo ""
      echo "  Fluent Bit is Running on ${CORDONED_NODE}."
      break
    fi
  else
    echo "  [${ELAPSED}s] Waiting for pod to schedule on ${CORDONED_NODE}..."
  fi

  sleep "${INTERVAL}"
  ELAPSED=$(( ELAPSED + INTERVAL ))
done

if [[ "${ELAPSED}" -ge "${WAIT_SECONDS}" ]]; then
  echo ""
  echo "  WARNING: Fluent Bit did not become Ready within ${WAIT_SECONDS}s."
  echo "  Check manually: kubectl get pods -n ${LOGGING_NS} -o wide"
fi

echo ""

# --- Post-fix state ---
echo "  Post-fix state:"
NODE_COUNT=$(kubectl get nodes --no-headers 2>/dev/null | wc -l | tr -d ' ')
FB_COUNT=$(kubectl get pods -n "${LOGGING_NS}" \
  -l app.kubernetes.io/name=fluent-bit \
  --no-headers 2>/dev/null | wc -l | tr -d ' ')

echo "  Nodes:            ${NODE_COUNT}"
echo "  Fluent Bit pods:  ${FB_COUNT}"
echo ""

kubectl get pods -n "${LOGGING_NS}" \
  -l app.kubernetes.io/name=fluent-bit \
  -o wide --no-headers 2>/dev/null \
  | awk '{printf "  Pod: %-55s Node: %-30s Status: %s\n", $1, $7, $3}'
echo ""

if [[ "${FB_COUNT}" -ge "${NODE_COUNT}" ]]; then
  echo "  STATUS: Pod count matches node count."
  echo "          All nodes have Fluent Bit coverage."
else
  echo "  STATUS: STILL MISMATCHED — ${FB_COUNT} pods for ${NODE_COUNT} nodes."
  echo "          Run: kubectl describe daemonset -n ${LOGGING_NS}"
fi

echo ""
echo "  NEXT STEP: Run verify.sh to confirm log flow has resumed."
echo "  THEN: Complete remediate.md to document the gap for AU-2."
echo ""
echo "============================================================"
echo "FIX COMPLETE — ${TIMESTAMP}"
echo "============================================================"
