#!/usr/bin/env bash
# =============================================================================
# L7-05 — DE.AE-02: Alert Fatigue (No Custom Falco Tuning)
# Phase: BASELINE — Measure current Falco alert volume and noise profile
#
# CSF:       DETECT / DE.AE-02 (Potentially adverse events analyzed)
# CIS v8:    8.11 — Tune Security Event Alert Thresholds
# NIST:      AU-6 — Audit Record Review, Analysis, and Reporting
# Cluster:   k3d-seclab
# Namespace: falco
# =============================================================================
set -euo pipefail

FALCO_NS="falco"
ANTHRA_NS="anthra"
TAIL_LINES=200
TOP_RULES=10
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo "============================================================"
echo "L7-05 BASELINE — Falco Alert Volume Measurement"
echo "Timestamp: ${TIMESTAMP}"
echo "============================================================"
echo ""

# --- 1. Verify Falco is running ---
echo "[1/5] Falco pod status"
echo "------------------------------------------------------------"
kubectl get pods -n "${FALCO_NS}" -l app.kubernetes.io/name=falco \
  --no-headers 2>/dev/null | awk '{printf "  %-50s %s/%s\n", $1, $3, $4}' \
  || echo "  WARNING: No Falco pods found in namespace ${FALCO_NS}"
echo ""

# --- 2. Count alerts by rule name (last N lines) ---
echo "[2/5] Top ${TOP_RULES} noisiest rules (last ${TAIL_LINES} log lines)"
echo "------------------------------------------------------------"
echo "  Count | Rule Name"
echo "  ------|--------------------------------------------------"
kubectl logs -n "${FALCO_NS}" \
  -l app.kubernetes.io/name=falco \
  --tail="${TAIL_LINES}" \
  --prefix=false \
  2>/dev/null \
  | grep -oP '"rule":"[^"]*"' \
  | sed 's/"rule":"//;s/"//' \
  | sort \
  | uniq -c \
  | sort -rn \
  | head -"${TOP_RULES}" \
  | awk '{printf "  %5s | %s\n", $1, $2}' \
  || echo "  No structured Falco output found. Check Falco is producing JSON output."
echo ""

# --- 3. Estimate alerts per minute ---
echo "[3/5] Alert rate estimation"
echo "------------------------------------------------------------"
TOTAL_ALERTS=$(kubectl logs -n "${FALCO_NS}" \
  -l app.kubernetes.io/name=falco \
  --tail="${TAIL_LINES}" \
  --prefix=false \
  2>/dev/null \
  | grep -c '"rule":' || true)

# Falco timestamps in JSON: "output_fields":{"evt.time":...}
# Grab first and last timestamp from the tail window to estimate rate
FIRST_TS=$(kubectl logs -n "${FALCO_NS}" \
  -l app.kubernetes.io/name=falco \
  --tail="${TAIL_LINES}" \
  --prefix=false \
  2>/dev/null \
  | grep -oP '\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}' \
  | head -1 || true)

LAST_TS=$(kubectl logs -n "${FALCO_NS}" \
  -l app.kubernetes.io/name=falco \
  --tail="${TAIL_LINES}" \
  --prefix=false \
  2>/dev/null \
  | grep -oP '\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}' \
  | tail -1 || true)

echo "  Total alerts in sample:  ${TOTAL_ALERTS}"
echo "  Sample window start:     ${FIRST_TS:-unknown}"
echo "  Sample window end:       ${LAST_TS:-unknown}"

if [[ -n "${FIRST_TS}" && -n "${LAST_TS}" && "${FIRST_TS}" != "${LAST_TS}" ]]; then
  START_EPOCH=$(date -d "${FIRST_TS}" +%s 2>/dev/null || echo 0)
  END_EPOCH=$(date -d "${LAST_TS}" +%s 2>/dev/null || echo 0)
  ELAPSED=$(( END_EPOCH - START_EPOCH ))
  if (( ELAPSED > 0 )); then
    RATE=$(echo "scale=1; ${TOTAL_ALERTS} * 60 / ${ELAPSED}" | bc)
    echo "  Elapsed seconds:         ${ELAPSED}"
    echo "  Estimated rate:          ${RATE} alerts/minute"
    HOURLY=$(echo "scale=0; ${TOTAL_ALERTS} * 3600 / ${ELAPSED}" | bc)
    echo "  Projected hourly rate:   ${HOURLY} alerts/hour"
  fi
else
  echo "  Rate calculation: insufficient timestamp data in sample window"
  echo "  Increase TAIL_LINES or wait for more Falco output to accumulate"
fi
echo ""

# --- 4. Check for custom rules ConfigMap ---
echo "[4/5] Custom rules check"
echo "------------------------------------------------------------"
CUSTOM_CM=$(kubectl get configmap -n "${FALCO_NS}" \
  -l "app.kubernetes.io/component=custom-rules" \
  --no-headers 2>/dev/null | wc -l || echo 0)

if (( CUSTOM_CM == 0 )); then
  echo "  FINDING: No custom Falco rules ConfigMap detected."
  echo "  Falco is operating entirely on default community rules."
  echo "  No exceptions exist for known-good Portfolio processes."
  echo "  This is the root cause of the false positive flood."
else
  echo "  Custom rules ConfigMaps found: ${CUSTOM_CM}"
  kubectl get configmap -n "${FALCO_NS}" \
    -l "app.kubernetes.io/component=custom-rules" \
    --no-headers 2>/dev/null \
    | awk '{printf "  - %s\n", $1}'
fi
echo ""

# --- 5. Snapshot for comparison ---
echo "[5/5] Baseline snapshot (save for post-fix comparison)"
echo "------------------------------------------------------------"
echo "  Baseline timestamp:    ${TIMESTAMP}"
echo "  Alerts in sample:      ${TOTAL_ALERTS}"
echo "  Custom rules present:  $([ "${CUSTOM_CM}" -gt 0 ] && echo yes || echo NO)"
echo ""
echo "  ACTION: Record these numbers. verify.sh will compare against them."
echo "  Expected after fix: alert rate drops 80-90%, custom rules fire on real events."
echo ""
echo "============================================================"
echo "BASELINE COMPLETE — Proceed to break.sh"
echo "============================================================"
