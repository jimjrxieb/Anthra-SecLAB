#!/usr/bin/env bash
#
# CSF: DETECT / DE.CM-03 — Computing hardware, software, services monitored
# CIS v8: 13.7 — Deploy Host-Based Intrusion Detection Solution
# NIST 800-53: SI-4 — Information System Monitoring
#
# L7-04 DE.CM-03 — Break: Evict all Falco pods by injecting impossible nodeSelector
# Patches the Falco DaemonSet spec with a nodeSelector that no node satisfies.
# Kubernetes evicts all existing Falco pods and cannot schedule replacements.
# Result: zero runtime detection coverage across all cluster nodes.
#
# IMPORTANT: Run baseline.sh first. Run fix.sh when done.
# This script REMOVES runtime threat detection. Do not leave broken.
#
# Usage: bash break.sh

set -euo pipefail

FALCO_NS="falco"
BREAK_KEY="seclab-break"
BREAK_VALUE="evict"

echo "=== L7-04 DE.CM-03 Break ==="
echo "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo ""
echo "WARNING: This script will evict ALL Falco pods."
echo "         Runtime threat detection will be OFFLINE until fix.sh is run."
echo "         The monitoring gap begins at the moment the last pod terminates."
echo ""

# Confirm Falco DaemonSet exists
if ! kubectl get daemonset falco -n "${FALCO_NS}" &>/dev/null; then
  echo "ERROR: Falco DaemonSet not found in namespace '${FALCO_NS}'"
  echo "       Verify Falco is installed: kubectl get ds -n ${FALCO_NS}"
  exit 1
fi

# Capture pod count before break
PODS_BEFORE=$(kubectl get pods -n "${FALCO_NS}" -l app.kubernetes.io/name=falco \
  --field-selector=status.phase=Running --no-headers 2>/dev/null | wc -l | tr -d ' ')
echo "Falco pods running before break: ${PODS_BEFORE}"

# Record break start time for gap measurement
BREAK_START="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "Break start time (gap begins): ${BREAK_START}"
echo ""

# Inject the impossible nodeSelector
# DaemonSets have no replicas field — this is the correct way to "scale to 0"
echo "Patching Falco DaemonSet nodeSelector..."
kubectl patch daemonset falco -n "${FALCO_NS}" \
  --type=json \
  -p '[{"op":"add","path":"/spec/template/spec/nodeSelector","value":{"'"${BREAK_KEY}"'":"'"${BREAK_VALUE}"'"}}]'

echo "Patch applied: nodeSelector = { ${BREAK_KEY}: \"${BREAK_VALUE}\" }"
echo "No node in this cluster carries that label. All pods will be evicted."
echo ""

# Wait for pods to terminate
echo "Waiting for Falco pods to terminate..."
WAIT_SECONDS=0
MAX_WAIT=60
while true; do
  PODS_NOW=$(kubectl get pods -n "${FALCO_NS}" -l app.kubernetes.io/name=falco \
    --no-headers 2>/dev/null | grep -v Terminating | wc -l | tr -d ' ')
  if [[ "${PODS_NOW}" -eq 0 ]]; then
    echo "All Falco pods terminated."
    break
  fi
  if [[ "${WAIT_SECONDS}" -ge "${MAX_WAIT}" ]]; then
    echo "WARNING: Pods still present after ${MAX_WAIT}s — check manually:"
    kubectl get pods -n "${FALCO_NS}" -l app.kubernetes.io/name=falco
    break
  fi
  printf "  %ds elapsed — %s pod(s) still running...\n" "${WAIT_SECONDS}" "${PODS_NOW}"
  sleep 5
  WAIT_SECONDS=$((WAIT_SECONDS + 5))
done

echo ""
echo "--- Current State ---"
echo "DaemonSet:"
kubectl get daemonset falco -n "${FALCO_NS}" \
  -o custom-columns='NAME:.metadata.name,DESIRED:.status.desiredNumberScheduled,READY:.status.numberReady,AVAILABLE:.status.numberAvailable'

echo ""
echo "Pods in falco namespace:"
kubectl get pods -n "${FALCO_NS}" 2>/dev/null || echo "  (none)"

echo ""
echo "=========================================="
echo "  RUNTIME DETECTION IS NOW OFFLINE"
echo "  Gap start: ${BREAK_START}"
echo "  Syscall monitoring: ZERO COVERAGE"
echo "  Shell spawn detection: DISABLED"
echo "  Privilege escalation detection: DISABLED"
echo "  Crypto mining detection: DISABLED"
echo "=========================================="
echo ""
echo "NEXT STEP: Go to detect.md and work through the detection exercise."
echo "           Then run fix.sh to restore Falco and end the monitoring gap."
