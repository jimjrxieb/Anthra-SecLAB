#!/usr/bin/env bash
#
# CSF: DETECT / DE.CM-03 — Computing hardware, software, services monitored
# CIS v8: 13.7 — Deploy Host-Based Intrusion Detection Solution
# NIST 800-53: SI-4 — Information System Monitoring
#
# L7-04 DE.CM-03 — Baseline: Capture Falco runtime monitoring status
# Verifies Falco DaemonSet is healthy: one pod per node, Falcosidekick running,
# and records the current alert event count from Falco logs.
# Run this BEFORE break.sh to establish the detection-capable ground truth.
#
# Usage: bash baseline.sh
# Expected: falco pods = node count, falcosidekick = 2/2 Running, events visible

set -euo pipefail

FALCO_NS="falco"
OUTFILE="/tmp/L7-04-baseline-$(date +%Y%m%d-%H%M%S).txt"

echo "=== L7-04 DE.CM-03 Baseline ==="
echo "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "Namespace:  ${FALCO_NS}"
echo ""

# --- Node count ---
NODE_COUNT=$(kubectl get nodes --no-headers 2>/dev/null | wc -l | tr -d ' ')
echo "--- Cluster Nodes ---"
kubectl get nodes -o wide --no-headers 2>/dev/null | awk '{printf "  %-40s  %-12s  %s\n", $1, $2, $5}'
echo "Total nodes: ${NODE_COUNT}"
echo ""

# --- Falco DaemonSet status ---
echo "--- Falco DaemonSet ---"
DS_DESIRED=$(kubectl get daemonset falco -n "${FALCO_NS}" \
  -o jsonpath='{.status.desiredNumberScheduled}' 2>/dev/null || echo "0")
DS_READY=$(kubectl get daemonset falco -n "${FALCO_NS}" \
  -o jsonpath='{.status.numberReady}' 2>/dev/null || echo "0")
DS_AVAILABLE=$(kubectl get daemonset falco -n "${FALCO_NS}" \
  -o jsonpath='{.status.numberAvailable}' 2>/dev/null || echo "0")

printf "  Desired:    %s\n" "${DS_DESIRED}"
printf "  Ready:      %s\n" "${DS_READY}"
printf "  Available:  %s\n" "${DS_AVAILABLE}"

if [[ "${DS_READY}" == "${NODE_COUNT}" ]]; then
  echo "  Status:     HEALTHY — one Falco pod per node"
else
  echo "  Status:     WARNING — pod count (${DS_READY}) does not match node count (${NODE_COUNT})"
fi
echo ""

# --- Falco pod listing ---
echo "--- Falco Pods ---"
kubectl get pods -n "${FALCO_NS}" -l app.kubernetes.io/name=falco \
  -o wide --no-headers 2>/dev/null | \
  awk '{printf "  %-50s  %-10s  %-8s  %s\n", $1, $3, $4, $7}' || \
  echo "  WARNING: Could not list Falco pods"
echo ""

# --- Falcosidekick pod listing ---
echo "--- Falcosidekick Pods ---"
SIDEKICK_READY=$(kubectl get pods -n "${FALCO_NS}" -l app.kubernetes.io/name=falcosidekick \
  --field-selector=status.phase=Running --no-headers 2>/dev/null | wc -l | tr -d ' ')
kubectl get pods -n "${FALCO_NS}" -l app.kubernetes.io/name=falcosidekick \
  -o wide --no-headers 2>/dev/null | \
  awk '{printf "  %-50s  %-10s  %-8s  %s\n", $1, $3, $4, $7}' || \
  echo "  WARNING: Could not list Falcosidekick pods"
echo "  Running Falcosidekick pods: ${SIDEKICK_READY}"
echo ""

# --- Current nodeSelector on DaemonSet (should be empty or cluster-default) ---
echo "--- DaemonSet nodeSelector ---"
NS_VALUE=$(kubectl get daemonset falco -n "${FALCO_NS}" \
  -o jsonpath='{.spec.template.spec.nodeSelector}' 2>/dev/null || echo "{}")
if [[ -z "${NS_VALUE}" || "${NS_VALUE}" == "{}" || "${NS_VALUE}" == "null" ]]; then
  echo "  nodeSelector: (none) — DaemonSet will schedule on all nodes"
else
  echo "  nodeSelector: ${NS_VALUE}"
  echo "  WARNING: A nodeSelector is set. Verify this is intentional."
fi
echo ""

# --- Sample recent Falco events (last 10 lines from first pod) ---
echo "--- Recent Falco Events (last 10 lines) ---"
FALCO_POD=$(kubectl get pods -n "${FALCO_NS}" -l app.kubernetes.io/name=falco \
  --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)

if [[ -n "${FALCO_POD}" ]]; then
  echo "  Source pod: ${FALCO_POD}"
  kubectl logs -n "${FALCO_NS}" "${FALCO_POD}" --tail=10 2>/dev/null | \
    sed 's/^/  /' || echo "  WARNING: Could not retrieve Falco logs"
else
  echo "  WARNING: No running Falco pod found — cannot capture event sample"
fi
echo ""

# --- Save summary to file ---
{
  echo "=== L7-04 Baseline: $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
  echo "Node count:           ${NODE_COUNT}"
  echo "DS desired:           ${DS_DESIRED}"
  echo "DS ready:             ${DS_READY}"
  echo "DS available:         ${DS_AVAILABLE}"
  echo "Sidekick running:     ${SIDEKICK_READY}"
  echo "nodeSelector:         ${NS_VALUE:-none}"
  echo "Falco pod sampled:    ${FALCO_POD:-none}"
} > "${OUTFILE}"

echo "Baseline saved to: ${OUTFILE}"
echo "=== Baseline complete ==="
echo ""
echo "NEXT STEP: Run break.sh to evict all Falco pods and start the monitoring gap."
