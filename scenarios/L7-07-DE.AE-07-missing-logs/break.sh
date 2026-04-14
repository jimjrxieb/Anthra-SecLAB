#!/usr/bin/env bash
# =============================================================================
# L7-07 — DE.AE-07: Log Source Stopped (Fluent Bit Node Gap)
# Phase: BREAK — Delete one Fluent Bit pod to create a partial logging gap
#
# CSF:       DETECT / DE.AE-07 (Threat intel and contextual info integrated)
# CIS v8:    8.2 — Collect Audit Logs
# NIST:      AU-2 — Event Logging
# Cluster:   k3d-seclab
# Namespace: logging (Fluent Bit DaemonSet)
#
# WHAT THIS DOES:
#   Deletes the first Fluent Bit pod found in the logging namespace.
#   The DaemonSet will restart it, but there is a gap window (10-60 seconds)
#   during which the node has no log collector running.
#
#   For a LONGER gap: the script can cordon the node first so the DaemonSet
#   cannot reschedule the pod. This simulates a node that drops out of
#   rotation — all pods on that node become unmonitored until uncordoned.
#
# LEARNING OBJECTIVE:
#   One missing Fluent Bit pod = one node's logs go to /dev/null.
#   In a 3-node cluster, that is 33% of log coverage gone — silently.
# =============================================================================
set -euo pipefail

LOGGING_NS="logging"
ANTHRA_NS="anthra"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Set EXTENDED_BREAK=true to cordon the node for a longer-lasting gap
EXTENDED_BREAK="${EXTENDED_BREAK:-false}"

echo "============================================================"
echo "L7-07 BREAK — Fluent Bit Node Gap"
echo "Timestamp:      ${TIMESTAMP}"
echo "Extended break: ${EXTENDED_BREAK}"
echo "============================================================"
echo ""

# --- Find the first Fluent Bit pod ---
FB_POD=$(kubectl get pods -n "${LOGGING_NS}" \
  -l app.kubernetes.io/name=fluent-bit \
  --no-headers 2>/dev/null \
  | awk '{print $1}' \
  | head -1 || true)

if [[ -z "${FB_POD}" ]]; then
  echo "ERROR: No Fluent Bit pods found in namespace '${LOGGING_NS}'."
  echo ""
  echo "  Check the DaemonSet label:"
  echo "  kubectl get daemonset -n ${LOGGING_NS} --show-labels"
  echo ""
  echo "  If the label is different, update the -l selector in this script."
  exit 1
fi

# --- Find which node this pod runs on ---
FB_NODE=$(kubectl get pod -n "${LOGGING_NS}" "${FB_POD}" \
  -o jsonpath='{.spec.nodeName}' 2>/dev/null || true)

echo "  Target pod:  ${FB_POD}"
echo "  Target node: ${FB_NODE}"
echo ""

# --- Show which anthra pods are on this node (will be unmonitored) ---
echo "  Pods on ${FB_NODE} that will be UNMONITORED during the gap:"
AFFECTED=$(kubectl get pods -n "${ANTHRA_NS}" \
  --field-selector "spec.nodeName=${FB_NODE}" \
  --no-headers 2>/dev/null \
  | awk '{print "  - "$1}' || true)
if [[ -n "${AFFECTED}" ]]; then
  echo "${AFFECTED}"
else
  echo "  (no anthra pods currently scheduled on this node)"
  echo "  Note: all pods on this node lose logging coverage, not just anthra"
fi
echo ""

# --- Optional: cordon the node to extend the gap ---
if [[ "${EXTENDED_BREAK}" == "true" ]]; then
  echo "  EXTENDED BREAK: cordoning node ${FB_NODE}"
  echo "  The DaemonSet cannot reschedule on a cordoned node."
  echo "  The gap will persist until the node is uncordoned (fix.sh)."
  echo ""
  kubectl cordon "${FB_NODE}"
  echo "  Node ${FB_NODE} cordoned."
  echo ""
  # Record the cordoned node for fix.sh to uncordon
  echo "${FB_NODE}" > /tmp/l7-07-cordoned-node.txt
  echo "  Cordoned node saved to /tmp/l7-07-cordoned-node.txt"
  echo ""
fi

# --- Record the gap start time ---
GAP_START=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
echo "${GAP_START}" > /tmp/l7-07-gap-start.txt
echo "  Gap start time: ${GAP_START}"
echo "  (saved to /tmp/l7-07-gap-start.txt)"
echo ""

# --- Delete the pod ---
echo "  Deleting pod: ${FB_POD} ..."
kubectl delete pod -n "${LOGGING_NS}" "${FB_POD}"
echo ""
echo "  Pod deleted. Log gap is OPEN on node: ${FB_NODE}"
echo ""

# --- Show immediate DaemonSet state ---
echo "  DaemonSet state immediately after deletion:"
kubectl get daemonset -n "${LOGGING_NS}" \
  -l app.kubernetes.io/name=fluent-bit \
  --no-headers 2>/dev/null \
  | awk '{printf "  Desired: %s | Current: %s | Ready: %s | Available: %s\n", $2, $3, $4, $5}'
echo ""

if [[ "${EXTENDED_BREAK}" == "true" ]]; then
  echo "============================================================"
  echo "EXTENDED BREAK ACTIVE"
  echo ""
  echo "  Node ${FB_NODE} is cordoned."
  echo "  Fluent Bit cannot restart on this node."
  echo "  All pods on this node are logging to nothing."
  echo ""
  echo "  To verify the gap is active, run:"
  echo "    kubectl get pods -n ${LOGGING_NS} -o wide"
  echo "    (you should see one fewer pod than nodes)"
  echo ""
  echo "  When ready to close the gap, run fix.sh."
  echo "  fix.sh will uncordon the node and restore coverage."
else
  echo "============================================================"
  echo "BRIEF BREAK ACTIVE (DaemonSet will restart the pod shortly)"
  echo ""
  echo "  The gap window is now open. During this 10-60 second window,"
  echo "  node ${FB_NODE} has zero log collection."
  echo ""
  echo "  Watch the gap close:"
  echo "    kubectl get pods -n ${LOGGING_NS} -w"
  echo ""
  echo "  For a longer gap, re-run with: EXTENDED_BREAK=true bash break.sh"
fi
echo ""
echo "  Proceed to detect.md to practice identifying the gap."
echo "============================================================"
