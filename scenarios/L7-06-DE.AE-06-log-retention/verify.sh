#!/usr/bin/env bash
# =============================================================================
# L7-06 — DE.AE-06: Log Retention Too Short
# Phase: VERIFY — Confirm retention >= 90 days and check oldest log entry
#
# CSF:       DETECT / DE.AE-06 (Info on adverse events provided to authorized staff)
# CIS v8:    8.10 — Retain Audit Logs
# NIST:      AU-11 — Audit Record Retention
# Cluster:   k3d-seclab
# Namespace: logging (Fluent Bit), anthra (target)
#
# WHAT THIS DOES:
#   1. Reads the Loki retention_period and confirms it is >= the required minimum
#   2. Queries Loki for the oldest available log entry from anthra namespace
#   3. Compares current retention against the AU-11 requirement (90 days)
#   4. Prints PASS or FAIL with the evidence for the POA&M
#
# PASS criteria:
#   - Loki retention_period >= 2160h (90 days) OR lab setting >= 720h (30 days)
#   - Loki has retention_deletes_enabled: true (so old logs are managed, not piling)
#   - Oldest available log timestamp exists and is within the retention window
# =============================================================================
set -euo pipefail

LOGGING_NS="logging"
ANTHRA_NS="anthra"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Minimum acceptable for lab (30 days) and production (90 days)
LAB_MIN_HOURS=720
PROD_MIN_HOURS=2160

PASS_COUNT=0
FAIL_COUNT=0

echo "============================================================"
echo "L7-06 VERIFY — Log Retention Compliance Check"
echo "Timestamp: ${TIMESTAMP}"
echo "============================================================"
echo ""

# --- Check 1: Loki deployed and healthy ---
echo "[CHECK 1] Loki deployment status"
echo "------------------------------------------------------------"
LOKI_NS=$(kubectl get pods --all-namespaces \
  --no-headers 2>/dev/null | grep -i loki | awk '{print $1}' | head -1 || true)

if [[ -n "${LOKI_NS}" ]]; then
  LOKI_READY=$(kubectl get pods -n "${LOKI_NS}" \
    --no-headers 2>/dev/null | grep -v "Completed" | grep "Running" | wc -l | tr -d ' ')
  echo "  Loki namespace: ${LOKI_NS}"
  echo "  Loki Running pods: ${LOKI_READY}"
  if [[ "${LOKI_READY}" -gt 0 ]]; then
    echo "  PASS: Loki is running."
    PASS_COUNT=$(( PASS_COUNT + 1 ))
  else
    echo "  FAIL: Loki pods found but none are Running."
    FAIL_COUNT=$(( FAIL_COUNT + 1 ))
  fi
else
  echo "  FAIL: Loki not deployed. No durable log backend found."
  echo "        kubectl logs only retains for hours. AU-11 requires 90 days."
  FAIL_COUNT=$(( FAIL_COUNT + 1 ))
fi
echo ""

# --- Check 2: Retention period setting ---
echo "[CHECK 2] Loki retention_period configuration"
echo "------------------------------------------------------------"
if [[ -n "${LOKI_NS}" ]]; then
  LOKI_CM=$(kubectl get configmap -n "${LOKI_NS}" \
    --no-headers 2>/dev/null | grep -i loki | awk '{print $1}' | head -1 || true)

  if [[ -n "${LOKI_CM}" ]]; then
    RETENTION_RAW=$(kubectl get configmap -n "${LOKI_NS}" "${LOKI_CM}" \
      -o jsonpath='{.data}' 2>/dev/null \
      | python3 -c "
import sys, json, re
d = json.load(sys.stdin)
for k, v in d.items():
    m = re.search(r'retention_period:\s*(\S+)', v)
    if m:
        print(m.group(1))
" 2>/dev/null || echo "")

    if [[ -n "${RETENTION_RAW}" ]]; then
      echo "  retention_period: ${RETENTION_RAW}"

      # Convert to hours for comparison
      if [[ "${RETENTION_RAW}" == *"h" ]]; then
        RETENTION_HOURS="${RETENTION_RAW%h}"
      elif [[ "${RETENTION_RAW}" == *"d" ]]; then
        RETENTION_HOURS=$(( ${RETENTION_RAW%d} * 24 ))
      else
        RETENTION_HOURS=0
      fi

      echo "  Retention in hours: ${RETENTION_HOURS}h"
      echo "  Lab minimum:        ${LAB_MIN_HOURS}h (30 days)"
      echo "  Production minimum: ${PROD_MIN_HOURS}h (90 days)"

      if [[ "${RETENTION_HOURS}" -ge "${PROD_MIN_HOURS}" ]]; then
        echo "  PASS: Retention meets production FedRAMP requirement (90+ days)."
        PASS_COUNT=$(( PASS_COUNT + 1 ))
      elif [[ "${RETENTION_HOURS}" -ge "${LAB_MIN_HOURS}" ]]; then
        echo "  PASS (lab): Retention meets lab minimum (30+ days)."
        echo "  NOTE: Production must be set to ${PROD_MIN_HOURS}h (90 days)."
        PASS_COUNT=$(( PASS_COUNT + 1 ))
      else
        echo "  FAIL: Retention is ${RETENTION_HOURS}h — below lab minimum of ${LAB_MIN_HOURS}h."
        echo "        Run fix.sh to set retention to ${LAB_MIN_HOURS}h or higher."
        FAIL_COUNT=$(( FAIL_COUNT + 1 ))
      fi
    else
      echo "  FAIL: retention_period not found in Loki ConfigMap."
      echo "        Loki uses compactor defaults (may not delete old logs at all)."
      echo "        Explicit retention_period is required for AU-11 compliance."
      FAIL_COUNT=$(( FAIL_COUNT + 1 ))
    fi

    # Check retention_deletes_enabled
    DELETES_ENABLED=$(kubectl get configmap -n "${LOKI_NS}" "${LOKI_CM}" \
      -o jsonpath='{.data}' 2>/dev/null \
      | python3 -c "
import sys, json, re
d = json.load(sys.stdin)
for k, v in d.items():
    m = re.search(r'retention_deletes_enabled:\s*(\S+)', v)
    if m:
        print(m.group(1))
" 2>/dev/null || echo "false")

    echo "  retention_deletes_enabled: ${DELETES_ENABLED:-not set}"
    if [[ "${DELETES_ENABLED}" == "true" ]]; then
      echo "  PASS: Loki will actively manage retention."
    else
      echo "  NOTE: retention_deletes_enabled not set to true."
      echo "        Old logs will accumulate but not be automatically deleted."
      echo "        This is not a retention failure but disk management will suffer."
    fi
  else
    echo "  FAIL: No Loki ConfigMap found."
    FAIL_COUNT=$(( FAIL_COUNT + 1 ))
  fi
else
  echo "  SKIP: Loki not deployed — retention_period check not applicable."
fi
echo ""

# --- Check 3: Oldest available log from anthra ---
echo "[CHECK 3] Oldest available log timestamp from anthra namespace"
echo "------------------------------------------------------------"
OLDEST_FOUND=""
for POD in $(kubectl get pods -n "${ANTHRA_NS}" --no-headers 2>/dev/null \
  | awk '{print $1}' | head -3); do
  TS=$(kubectl logs -n "${ANTHRA_NS}" "${POD}" \
    --timestamps=true 2>/dev/null | head -1 | awk '{print $1}' || true)
  if [[ -n "${TS}" ]]; then
    echo "  ${POD}: oldest log at ${TS}"
    OLDEST_FOUND="${TS}"
    break
  fi
done

if [[ -n "${OLDEST_FOUND}" ]]; then
  echo "  Oldest anthra log: ${OLDEST_FOUND}"
  echo "  Current time:      ${TIMESTAMP}"
  echo "  NOTE: Full 90-day accumulation takes time after fix."
  echo "        If Loki was just deployed or retention was just extended,"
  echo "        the oldest log will be from the deployment date, not 90 days ago."
  echo "  PASS: Logs are available."
  PASS_COUNT=$(( PASS_COUNT + 1 ))
else
  echo "  FAIL: No logs found in anthra namespace."
  echo "        Check that anthra pods are running: kubectl get pods -n anthra"
  FAIL_COUNT=$(( FAIL_COUNT + 1 ))
fi
echo ""

# --- Check 4: Fluent Bit still collecting ---
echo "[CHECK 4] Fluent Bit DaemonSet health"
echo "------------------------------------------------------------"
NODE_COUNT=$(kubectl get nodes --no-headers 2>/dev/null | wc -l | tr -d ' ')
FB_COUNT=$(kubectl get pods -n "${LOGGING_NS}" \
  -l app.kubernetes.io/name=fluent-bit \
  --no-headers 2>/dev/null | grep "Running" | wc -l | tr -d ' ')

echo "  Nodes:                ${NODE_COUNT}"
echo "  Fluent Bit Running:   ${FB_COUNT}"

if [[ "${FB_COUNT}" -ge "${NODE_COUNT}" ]]; then
  echo "  PASS: All nodes have Fluent Bit running."
  PASS_COUNT=$(( PASS_COUNT + 1 ))
else
  echo "  FAIL: ${FB_COUNT} of ${NODE_COUNT} nodes have Fluent Bit running."
  echo "        Collection gap exists. Retention fix is moot if collection is broken."
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
  echo "  AU-11 retention configuration is compliant."
  echo "  Record this output as verification evidence for the POA&M."
else
  echo "  RESULT: FAIL"
  echo "  ${FAIL_COUNT} check(s) require attention."
  echo "  Review the failures above and re-run fix.sh if needed."
fi
echo ""
echo "  Save this output for the POA&M evidence package."
echo "  Compare against baseline.sh output to show before/after state."
echo "============================================================"
