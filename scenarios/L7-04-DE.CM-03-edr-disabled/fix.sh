#!/usr/bin/env bash
#
# CSF: DETECT / DE.CM-03 — Computing hardware, software, services monitored
# CIS v8: 13.7 — Deploy Host-Based Intrusion Detection Solution
# NIST 800-53: SI-4 — Information System Monitoring
#
# L7-04 DE.CM-03 — Fix: Remove bad nodeSelector, restore Falco scheduling
# Removes the {seclab-break: evict} nodeSelector injected by break.sh.
# Kubernetes will immediately reschedule Falco onto all nodes.
# Record the completion time as the end of the monitoring gap for GRC.
#
# IMPORTANT: Document the gap start/end times in report-template.md before closing.
#
# Usage: bash fix.sh

set -euo pipefail

FALCO_NS="falco"

echo "=== L7-04 DE.CM-03 Fix ==="
echo "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo ""

# Verify the DaemonSet exists
if ! kubectl get daemonset falco -n "${FALCO_NS}" &>/dev/null; then
  echo "ERROR: Falco DaemonSet not found in namespace '${FALCO_NS}'"
  exit 1
fi

# Confirm the bad nodeSelector is present before attempting removal
CURRENT_NS=$(kubectl get daemonset falco -n "${FALCO_NS}" \
  -o jsonpath='{.spec.template.spec.nodeSelector}' 2>/dev/null || echo "")

echo "Current nodeSelector: ${CURRENT_NS:-"(empty)"}"

if echo "${CURRENT_NS}" | grep -q "seclab-break"; then
  echo "Bad nodeSelector confirmed. Removing..."
else
  echo "WARNING: 'seclab-break' key not found in nodeSelector."
  echo "         The DaemonSet may already be fixed, or the break was not applied."
  echo "         Current nodeSelector: ${CURRENT_NS:-"(none)"}"
  echo ""
  echo "Proceeding with removal attempt anyway..."
fi

echo ""

# Remove the bad nodeSelector key
kubectl patch daemonset falco -n "${FALCO_NS}" \
  --type=json \
  -p '[{"op":"remove","path":"/spec/template/spec/nodeSelector/seclab-break"}]' 2>/dev/null || {
  echo "Note: JSON patch 'remove' returned non-zero. This may mean the key was already absent."
  echo "Attempting merge patch to clear nodeSelector entirely..."
  kubectl patch daemonset falco -n "${FALCO_NS}" \
    --type=merge \
    -p '{"spec":{"template":{"spec":{"nodeSelector":null}}}}'
}

FIX_TIME="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "Patch applied at: ${FIX_TIME}"
echo "Kubernetes will now reschedule Falco onto all available nodes."
echo ""

# Get expected pod count from node count
NODE_COUNT=$(kubectl get nodes --no-headers 2>/dev/null | wc -l | tr -d ' ')
echo "Expected Falco pod count: ${NODE_COUNT} (one per node)"
echo ""

# Wait for pods to be scheduled and reach Running state
echo "Waiting for Falco pods to reach Running state..."
WAIT_SECONDS=0
MAX_WAIT=120
while true; do
  PODS_RUNNING=$(kubectl get pods -n "${FALCO_NS}" -l app.kubernetes.io/name=falco \
    --field-selector=status.phase=Running --no-headers 2>/dev/null | wc -l | tr -d ' ')

  if [[ "${PODS_RUNNING}" -ge "${NODE_COUNT}" ]]; then
    echo "All ${PODS_RUNNING} Falco pods are Running."
    break
  fi

  if [[ "${WAIT_SECONDS}" -ge "${MAX_WAIT}" ]]; then
    echo "WARNING: Only ${PODS_RUNNING}/${NODE_COUNT} pods running after ${MAX_WAIT}s"
    echo "         Check pod status manually: kubectl get pods -n ${FALCO_NS}"
    break
  fi

  printf "  %ds elapsed — %s/%s pods running...\n" "${WAIT_SECONDS}" "${PODS_RUNNING}" "${NODE_COUNT}"
  sleep 5
  WAIT_SECONDS=$((WAIT_SECONDS + 5))
done

echo ""
echo "--- Final State ---"
echo "DaemonSet:"
kubectl get daemonset falco -n "${FALCO_NS}" \
  -o custom-columns='NAME:.metadata.name,DESIRED:.status.desiredNumberScheduled,READY:.status.numberReady,AVAILABLE:.status.numberAvailable'

echo ""
echo "Pods:"
kubectl get pods -n "${FALCO_NS}" -o wide --no-headers 2>/dev/null | \
  awk '{printf "  %-50s  %-10s  %-8s  %s\n", $1, $3, $4, $7}'

echo ""
echo "Verified nodeSelector after fix:"
kubectl get daemonset falco -n "${FALCO_NS}" \
  -o jsonpath='{.spec.template.spec.nodeSelector}' 2>/dev/null && echo " (empty = correct)"

echo ""
echo "=========================================="
echo "  RUNTIME DETECTION RESTORED"
echo "  Gap end time: ${FIX_TIME}"
echo "  Record this in report-template.md"
echo "=========================================="
echo ""
echo "NEXT STEP: Run verify.sh to confirm Falco is generating events."
echo "           Then complete report-template.md with gap start and end times."
