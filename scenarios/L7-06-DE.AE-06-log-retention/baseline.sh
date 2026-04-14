#!/usr/bin/env bash
# =============================================================================
# L7-06 — DE.AE-06: Log Retention Too Short
# Phase: BASELINE — Capture current retention config and oldest log entry
#
# CSF:       DETECT / DE.AE-06 (Info on adverse events provided to authorized staff)
# CIS v8:    8.10 — Retain Audit Logs
# NIST:      AU-11 — Audit Record Retention
# Cluster:   k3d-seclab
# Namespace: logging (Fluent Bit), anthra (target)
#
# WHAT THIS DOES:
#   Records the current state of log retention before the break is applied.
#   Captures: Fluent Bit config, Loki retention config (if deployed), kubelet
#   log rotation settings, and the oldest available log timestamp from the
#   anthra namespace. This is your AU-11 before-state evidence.
#
# SAVE THIS OUTPUT. You will compare it against verify.sh output to
# demonstrate remediation for the POA&M.
# =============================================================================
set -euo pipefail

LOGGING_NS="logging"
ANTHRA_NS="anthra"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo "============================================================"
echo "L7-06 BASELINE — Log Retention State Capture"
echo "Timestamp: ${TIMESTAMP}"
echo "Cluster:   k3d-seclab"
echo "============================================================"
echo ""

# --- 1. Fluent Bit DaemonSet status ---
echo "[1/6] Fluent Bit DaemonSet status"
echo "------------------------------------------------------------"
FB_DESIRED=$(kubectl get daemonset -n "${LOGGING_NS}" \
  -l app.kubernetes.io/name=fluent-bit \
  --no-headers 2>/dev/null | awk '{print $2}' | head -1 || echo "unknown")
FB_READY=$(kubectl get daemonset -n "${LOGGING_NS}" \
  -l app.kubernetes.io/name=fluent-bit \
  --no-headers 2>/dev/null | awk '{print $4}' | head -1 || echo "unknown")
echo "  Desired pods: ${FB_DESIRED}"
echo "  Ready pods:   ${FB_READY}"
echo ""

# --- 2. Fluent Bit ConfigMap — look for buffer and output config ---
echo "[2/6] Fluent Bit buffer and output configuration"
echo "------------------------------------------------------------"
FB_CM=$(kubectl get configmap -n "${LOGGING_NS}" \
  --no-headers 2>/dev/null | grep -i fluent | awk '{print $1}' | head -1 || true)

if [[ -n "${FB_CM}" ]]; then
  echo "  ConfigMap: ${FB_CM}"
  echo ""
  echo "  Mem_Buf_Limit setting:"
  kubectl get configmap -n "${LOGGING_NS}" "${FB_CM}" -o jsonpath='{.data}' \
    2>/dev/null | grep -i "mem_buf_limit" || echo "  (not set — using default 5MB)"
  echo ""
  echo "  Output destinations:"
  kubectl get configmap -n "${LOGGING_NS}" "${FB_CM}" -o jsonpath='{.data}' \
    2>/dev/null | grep -i -E "\[OUTPUT\]|name\s+loki|name\s+forward|name\s+es" \
    | head -10 || echo "  (could not parse — check configmap directly)"
else
  echo "  WARNING: No Fluent Bit ConfigMap found in ${LOGGING_NS} namespace."
  echo "  Run: kubectl get configmaps -n ${LOGGING_NS}"
fi
echo ""

# --- 3. Loki retention config (if Loki is deployed) ---
echo "[3/6] Loki retention configuration (if deployed)"
echo "------------------------------------------------------------"
LOKI_NS=$(kubectl get pods --all-namespaces \
  --no-headers 2>/dev/null | grep -i loki | awk '{print $1}' | head -1 || true)

if [[ -n "${LOKI_NS}" ]]; then
  echo "  Loki namespace: ${LOKI_NS}"
  LOKI_CM=$(kubectl get configmap -n "${LOKI_NS}" \
    --no-headers 2>/dev/null | grep -i loki | awk '{print $1}' | head -1 || true)

  if [[ -n "${LOKI_CM}" ]]; then
    echo "  Loki ConfigMap: ${LOKI_CM}"
    echo ""
    echo "  Retention settings:"
    kubectl get configmap -n "${LOKI_NS}" "${LOKI_CM}" \
      -o jsonpath='{.data}' 2>/dev/null \
      | grep -i -E "retention_period|retention_deletes_enabled|chunk_retain_period" \
      || echo "  (retention settings not found in ConfigMap data)"
  else
    echo "  Loki ConfigMap not found. Check: kubectl get configmaps -n ${LOKI_NS}"
  fi
else
  echo "  Loki not detected in any namespace."
  echo "  Log retention is determined by:"
  echo "  - kubelet container log rotation (see step 4)"
  echo "  - Fluent Bit Mem_Buf_Limit (see step 2)"
  echo "  Without central storage, logs older than kubelet rotation window are gone."
fi
echo ""

# --- 4. Kubelet log rotation settings ---
echo "[4/6] Kubelet container log rotation settings"
echo "------------------------------------------------------------"
echo "  Default kubelet behavior (k3s/k3d unless overridden):"
echo "  - containerLogMaxSize:  10Mi per container log file"
echo "  - containerLogMaxFiles: 5 files per container"
echo "  - Max retention:        50Mi per container = hours to days depending on volume"
echo ""
echo "  Node log storage check:"
NODE=$(kubectl get nodes --no-headers 2>/dev/null | awk '{print $1}' | head -1 || true)
if [[ -n "${NODE}" ]]; then
  kubectl describe node "${NODE}" 2>/dev/null \
    | grep -i -E "containerLogMax|log" | head -5 \
    || echo "  (no log rotation overrides found — using defaults)"
fi
echo ""

# --- 5. Oldest available log from anthra namespace ---
echo "[5/6] Oldest available log timestamp from anthra namespace"
echo "------------------------------------------------------------"
echo "  Checking each pod in anthra for oldest log line..."
echo ""

for POD in $(kubectl get pods -n "${ANTHRA_NS}" --no-headers 2>/dev/null \
  | awk '{print $1}' | head -5); do
  OLDEST=$(kubectl logs -n "${ANTHRA_NS}" "${POD}" \
    --timestamps=true 2>/dev/null | head -1 | awk '{print $1}' || true)
  if [[ -n "${OLDEST}" ]]; then
    echo "  ${POD}: oldest log at ${OLDEST}"
  else
    echo "  ${POD}: no logs available"
  fi
done
echo ""

# --- 6. Summary ---
echo "[6/6] Retention baseline summary"
echo "============================================================"
echo "  Baseline captured at: ${TIMESTAMP}"
echo ""
echo "  AU-11 retention requirements:"
echo "  - FedRAMP Moderate minimum: 90 days"
echo "  - PCI-DSS minimum:         365 days"
echo "  - HIPAA (PHI logs):        6 years"
echo "  - CIS v8 8.10 minimum:     90 days"
echo ""
echo "  RECORD THESE VALUES for the POA&M:"
echo "  Current retention setting: [fill from steps 2-3 above]"
echo "  Oldest log available from: [fill from step 5 above]"
echo "  Gap vs 90-day requirement: [calculate: 90 days - current retention]"
echo ""
echo "  Run break.sh to simulate the retention failure condition."
echo "  Run verify.sh after fix.sh to confirm remediation."
echo "============================================================"
