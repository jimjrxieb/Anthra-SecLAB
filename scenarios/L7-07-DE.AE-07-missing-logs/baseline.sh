#!/usr/bin/env bash
# =============================================================================
# L7-07 — DE.AE-07: Log Source Stopped (Fluent Bit Node Gap)
# Phase: BASELINE — Map Fluent Bit pods to nodes, confirm log flow per node
#
# CSF:       DETECT / DE.AE-07 (Threat intel and contextual info integrated)
# CIS v8:    8.2 — Collect Audit Logs
# NIST:      AU-2 — Event Logging
# Cluster:   k3d-seclab
# Namespace: logging (Fluent Bit), anthra (target)
#
# WHAT THIS DOES:
#   Establishes the healthy baseline state: each cluster node has exactly one
#   Fluent Bit pod. Records pod names, host nodes, and confirms log flow
#   is active from each pod. This baseline is your AU-2 evidence of
#   complete log collection before the break is applied.
#
# SAVE THIS OUTPUT. You will compare it against verify.sh output to
# confirm all nodes are covered after remediation.
# =============================================================================
set -euo pipefail

LOGGING_NS="logging"
ANTHRA_NS="anthra"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo "============================================================"
echo "L7-07 BASELINE — Fluent Bit Coverage Baseline"
echo "Timestamp: ${TIMESTAMP}"
echo "Cluster:   k3d-seclab"
echo "============================================================"
echo ""

# --- 1. Node inventory ---
echo "[1/5] Cluster node inventory"
echo "------------------------------------------------------------"
NODE_COUNT=$(kubectl get nodes --no-headers 2>/dev/null | wc -l | tr -d ' ')
echo "  Total nodes: ${NODE_COUNT}"
echo ""
kubectl get nodes -o wide --no-headers 2>/dev/null \
  | awk '{printf "  %-40s STATUS: %-10s ROLES: %s\n", $1, $2, $3}' \
  || echo "  (could not list nodes)"
echo ""

# --- 2. Fluent Bit DaemonSet status ---
echo "[2/5] Fluent Bit DaemonSet health"
echo "------------------------------------------------------------"
kubectl get daemonset -n "${LOGGING_NS}" \
  -l app.kubernetes.io/name=fluent-bit \
  -o wide 2>/dev/null \
  || kubectl get daemonset -n "${LOGGING_NS}" \
       --no-headers 2>/dev/null \
  || echo "  WARNING: No Fluent Bit DaemonSet found in ${LOGGING_NS} namespace."
echo ""

FB_DESIRED=$(kubectl get daemonset -n "${LOGGING_NS}" \
  -l app.kubernetes.io/name=fluent-bit \
  --no-headers 2>/dev/null | awk '{print $2}' | head -1 || echo "0")
echo "  Expected: ${NODE_COUNT} pod(s) (one per node)"
echo "  Desired:  ${FB_DESIRED} pod(s)"

if [[ "${FB_DESIRED}" == "${NODE_COUNT}" ]]; then
  echo "  STATUS: DaemonSet coverage matches node count. HEALTHY."
else
  echo "  STATUS: MISMATCH — investigate before proceeding."
fi
echo ""

# --- 3. Pod-to-node mapping ---
echo "[3/5] Fluent Bit pod-to-node mapping"
echo "------------------------------------------------------------"
echo "  Each node MUST have exactly one Fluent Bit pod for complete AU-2 coverage."
echo ""
kubectl get pods -n "${LOGGING_NS}" \
  -l app.kubernetes.io/name=fluent-bit \
  -o wide --no-headers 2>/dev/null \
  | awk '{printf "  POD: %-55s NODE: %-30s STATUS: %s\n", $1, $7, $3}' \
  || echo "  (no Fluent Bit pods found)"
echo ""

# --- 4. Log flow spot check (one line per pod) ---
echo "[4/5] Log flow spot check (most recent log line per pod)"
echo "------------------------------------------------------------"
for FB_POD in $(kubectl get pods -n "${LOGGING_NS}" \
  -l app.kubernetes.io/name=fluent-bit \
  --no-headers 2>/dev/null | awk '{print $1}'); do
  echo "  Pod: ${FB_POD}"
  LAST_LINE=$(kubectl logs -n "${LOGGING_NS}" "${FB_POD}" \
    --tail=1 2>/dev/null || echo "(no logs)")
  echo "    Last log: ${LAST_LINE:0:120}"
  echo ""
done

# --- 5. Anthra namespace pod-to-node distribution ---
echo "[5/5] Anthra pods by node (shows what would be unmonitored during a node gap)"
echo "------------------------------------------------------------"
kubectl get pods -n "${ANTHRA_NS}" \
  -o wide --no-headers 2>/dev/null \
  | awk '{printf "  %-45s NODE: %-30s STATUS: %s\n", $1, $7, $3}' \
  || echo "  (no pods in anthra namespace)"
echo ""

echo "============================================================"
echo "BASELINE COMPLETE — ${TIMESTAMP}"
echo ""
echo "  RECORD THESE VALUES for the POA&M:"
echo "  Total nodes:             ${NODE_COUNT}"
echo "  Fluent Bit pods desired: ${FB_DESIRED}"
echo "  Coverage status:         [COMPLETE / MISMATCH — fill in from step 3]"
echo ""
echo "  Run break.sh to simulate a Fluent Bit pod failure on one node."
echo "  Run verify.sh after fix.sh to confirm full coverage is restored."
echo "============================================================"
