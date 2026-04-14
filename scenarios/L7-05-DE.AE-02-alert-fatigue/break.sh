#!/usr/bin/env bash
# =============================================================================
# L7-05 — DE.AE-02: Alert Fatigue (No Custom Falco Tuning)
# Phase: BREAK — Generate alert flood from legitimate Portfolio operations
#
# CSF:       DETECT / DE.AE-02 (Potentially adverse events analyzed)
# CIS v8:    8.11 — Tune Security Event Alert Thresholds
# NIST:      AU-6 — Audit Record Review, Analysis, and Reporting
# Cluster:   k3d-seclab
# Namespace: anthra (target), falco (monitoring)
#
# WHAT THIS DOES:
#   Executes 20 iterations of legitimate commands inside the Portfolio API pod.
#   Each invocation (ls, cat /etc/os-release, curl healthcheck) triggers one or
#   more default Falco rules. The break is not a misconfiguration — it is the
#   default state. This script makes that default state visible by concentrating
#   50+ alerts into a 30-second window. Watch Falco logs during execution.
#
# NOTE: No actual attack occurs. All commands are read-only and harmless.
#       The point is to show the analyst what "normal operations" look like
#       in the Falco alert stream when no tuning has been applied.
# =============================================================================
set -euo pipefail

ANTHRA_NS="anthra"
FALCO_NS="falco"
ITERATIONS=20

# Resolve the API deployment name (handles varying release names)
API_DEPLOY=$(kubectl get deployment -n "${ANTHRA_NS}" \
  -l "app.kubernetes.io/component=api" \
  --no-headers 2>/dev/null | awk '{print $1}' | head -1 || true)

if [[ -z "${API_DEPLOY}" ]]; then
  # Fallback: look for any deployment with "api" in the name
  API_DEPLOY=$(kubectl get deployment -n "${ANTHRA_NS}" \
    --no-headers 2>/dev/null | awk '{print $1}' | grep -i api | head -1 || true)
fi

if [[ -z "${API_DEPLOY}" ]]; then
  echo "ERROR: No API deployment found in namespace ${ANTHRA_NS}."
  echo "       Verify the anthra namespace is deployed and healthy."
  echo "       Run: kubectl get deployments -n ${ANTHRA_NS}"
  exit 1
fi

echo "============================================================"
echo "L7-05 BREAK — Alert Flood Generator"
echo "Target namespace:  ${ANTHRA_NS}"
echo "Target deployment: ${API_DEPLOY}"
echo "Iterations:        ${ITERATIONS}"
echo "============================================================"
echo ""
echo "This script runs legitimate commands inside the Portfolio API pod."
echo "Each command triggers default Falco rules. No attack, just noise."
echo ""
echo "MONITOR in a separate terminal:"
echo "  kubectl logs -n ${FALCO_NS} -l app.kubernetes.io/name=falco -f"
echo ""
echo "Starting in 3 seconds..."
sleep 3

# --- Alert flood: ls (triggers Read sensitive file / filesystem activity) ---
echo "[1/3] Running ls /tmp (triggers filesystem activity rules)..."
for i in $(seq 1 "${ITERATIONS}"); do
  kubectl exec -n "${ANTHRA_NS}" "deployment/${API_DEPLOY}" \
    -- ls /tmp 2>/dev/null &
done
wait
echo "      ${ITERATIONS} ls commands dispatched."
echo ""

# --- Alert flood: cat /etc/os-release (triggers sensitive file read) ---
echo "[2/3] Reading /etc/os-release (triggers sensitive file read rules)..."
for i in $(seq 1 "${ITERATIONS}"); do
  kubectl exec -n "${ANTHRA_NS}" "deployment/${API_DEPLOY}" \
    -- cat /etc/os-release 2>/dev/null &
done
wait
echo "      ${ITERATIONS} /etc/os-release reads dispatched."
echo ""

# --- Alert flood: curl healthcheck (triggers network activity rules) ---
echo "[3/3] Curling localhost health endpoint (triggers outbound connection rules)..."
for i in $(seq 1 "${ITERATIONS}"); do
  kubectl exec -n "${ANTHRA_NS}" "deployment/${API_DEPLOY}" \
    -- sh -c 'curl -s http://localhost:8000/health 2>/dev/null || true' &
done
wait
echo "      ${ITERATIONS} health check curls dispatched."
echo ""

# --- Show immediate Falco alert count ---
echo "------------------------------------------------------------"
echo "Waiting 5 seconds for Falco to process events..."
sleep 5

echo ""
echo "Recent Falco alerts (last 60 lines, rule names only):"
kubectl logs -n "${FALCO_NS}" \
  -l app.kubernetes.io/name=falco \
  --tail=60 \
  --prefix=false \
  2>/dev/null \
  | grep -oP '"rule":"[^"]*"' \
  | sed 's/"rule":"//;s/"//' \
  | sort \
  | uniq -c \
  | sort -rn \
  | head -10 \
  | awk '{printf "  %5s alerts | %s\n", $1, $2}' \
  || echo "  No structured alerts found. Falco may use a different output format."

echo ""
echo "============================================================"
echo "BREAK COMPLETE"
echo ""
echo "Observation: $(( ITERATIONS * 3 ))+ commands just ran. They were all harmless."
echo "             But they look identical to an attacker doing recon."
echo "             Without tuning, the analyst cannot tell the difference."
echo ""
echo "This is alert fatigue. Proceed to detect.md."
echo "============================================================"
