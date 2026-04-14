#!/usr/bin/env bash
# =============================================================================
# L7-06 — DE.AE-06: Log Retention Too Short
# Phase: BREAK — Simulate short log retention condition
#
# CSF:       DETECT / DE.AE-06 (Info on adverse events provided to authorized staff)
# CIS v8:    8.10 — Retain Audit Logs
# NIST:      AU-11 — Audit Record Retention
# Cluster:   k3d-seclab
# Namespace: logging (Fluent Bit), anthra (target)
#
# WHAT THIS DOES:
#   Path A — Loki deployed: patches the Loki ConfigMap to set retention_period
#             to 24h, then restarts Loki. Logs older than 24h will be purged
#             on the next compaction cycle.
#
#   Path B — No Loki: documents the buffer-only condition and demonstrates
#             that Fluent Bit's Mem_Buf_Limit means logs vanish once the buffer
#             fills and there is no durable backend to receive them.
#
# LEARNING OBJECTIVE:
#   When an incident is reported 48h after the event, and retention is 24h,
#   the investigator finds nothing. The logging stack ran correctly. The logs
#   are just gone. That is the AU-11 failure.
# =============================================================================
set -euo pipefail

LOGGING_NS="logging"
ANTHRA_NS="anthra"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo "============================================================"
echo "L7-06 BREAK — Log Retention Failure Simulation"
echo "Timestamp: ${TIMESTAMP}"
echo "============================================================"
echo ""

# --- Detect whether Loki is deployed ---
LOKI_NS=$(kubectl get pods --all-namespaces \
  --no-headers 2>/dev/null | grep -i loki | awk '{print $1}' | head -1 || true)

if [[ -n "${LOKI_NS}" ]]; then
  echo "PATH A: Loki detected in namespace '${LOKI_NS}'"
  echo "        Patching retention_period to 24h."
  echo ""

  LOKI_CM=$(kubectl get configmap -n "${LOKI_NS}" \
    --no-headers 2>/dev/null | grep -i loki | awk '{print $1}' | head -1 || true)

  if [[ -z "${LOKI_CM}" ]]; then
    echo "ERROR: Loki ConfigMap not found in namespace ${LOKI_NS}."
    echo "       Run: kubectl get configmaps -n ${LOKI_NS}"
    exit 1
  fi

  echo "  Target ConfigMap: ${LOKI_CM} in ${LOKI_NS}"
  echo ""

  # --- Save original config before modifying ---
  echo "  Saving original ConfigMap to /tmp/loki-config-before-break.yaml ..."
  kubectl get configmap -n "${LOKI_NS}" "${LOKI_CM}" \
    -o yaml > /tmp/loki-config-before-break.yaml
  echo "  Saved. Restore with: kubectl apply -f /tmp/loki-config-before-break.yaml"
  echo ""

  # --- Get current config data ---
  LOKI_CONFIG=$(kubectl get configmap -n "${LOKI_NS}" "${LOKI_CM}" \
    -o jsonpath='{.data.loki\.yaml}' 2>/dev/null \
    || kubectl get configmap -n "${LOKI_NS}" "${LOKI_CM}" \
       -o jsonpath='{.data.config\.yaml}' 2>/dev/null \
    || true)

  if [[ -z "${LOKI_CONFIG}" ]]; then
    echo "  WARNING: Could not extract Loki config from ConfigMap."
    echo "  The ConfigMap may use a different key name."
    echo ""
    echo "  MANUAL BREAK STEPS:"
    echo "  1. kubectl edit configmap -n ${LOKI_NS} ${LOKI_CM}"
    echo "  2. Under limits_config, set:"
    echo "       retention_period: 24h"
    echo "       retention_deletes_enabled: true"
    echo "  3. kubectl rollout restart deployment -n ${LOKI_NS}"
    echo ""
    echo "  This manually applies the same 24h retention that break.sh automates."
    exit 0
  fi

  # --- Write patched config ---
  echo "  Setting retention_period: 24h ..."

  # Use a temp file to patch the YAML safely
  cat /tmp/loki-config-before-break.yaml | \
    python3 -c "
import sys, re

raw = sys.stdin.read()

# If retention_period already exists, replace its value
if 'retention_period' in raw:
    raw = re.sub(r'retention_period:\s*\S+', 'retention_period: 24h', raw)
else:
    # Insert under limits_config block or at end of data
    raw = raw.replace('limits_config:', 'limits_config:\n  retention_period: 24h\n  retention_deletes_enabled: true')

print(raw)
" > /tmp/loki-config-patched.yaml

  kubectl apply -f /tmp/loki-config-patched.yaml
  echo "  ConfigMap patched."
  echo ""

  # --- Restart Loki to pick up new config ---
  echo "  Restarting Loki to apply retention change..."
  kubectl rollout restart deployment -n "${LOKI_NS}" 2>/dev/null \
    || kubectl rollout restart statefulset -n "${LOKI_NS}" 2>/dev/null \
    || echo "  (could not restart — restart manually)"

  echo ""
  echo "  Waiting 15 seconds for Loki to restart..."
  sleep 15

  echo ""
  echo "  BREAK STATE:"
  echo "  - Loki retention_period set to: 24h"
  echo "  - Logs older than 24h will be purged at next compaction"
  echo "  - An investigation starting 48h after an event will find nothing"
  echo ""
  echo "  AU-11 requirement: 90 days minimum (FedRAMP Moderate)"
  echo "  Current setting:   24 hours"
  echo "  Gap:               89 days and 0 hours"

else
  echo "PATH B: Loki not detected. Demonstrating buffer-only retention failure."
  echo ""
  echo "  In this lab environment, Fluent Bit collects logs but the output"
  echo "  destination has limited or no long-term storage. This section"
  echo "  documents what 'buffer-only' means for AU-11 compliance."
  echo ""

  # --- Show current Fluent Bit output config ---
  FB_CM=$(kubectl get configmap -n "${LOGGING_NS}" \
    --no-headers 2>/dev/null | grep -i fluent | awk '{print $1}' | head -1 || true)

  if [[ -n "${FB_CM}" ]]; then
    echo "  Current Fluent Bit ConfigMap: ${FB_CM}"
    echo ""
    echo "  Output section (where logs go):"
    kubectl get configmap -n "${LOGGING_NS}" "${FB_CM}" \
      -o jsonpath='{.data}' 2>/dev/null \
      | python3 -c "
import sys, json
data = json.load(sys.stdin)
for k, v in data.items():
    if '[OUTPUT]' in v or 'output' in k.lower():
        print(v[:800])
" 2>/dev/null || echo "  (could not parse — check configmap)"
    echo ""
  fi

  echo "  FLUENT BIT RETENTION FACTS:"
  echo "  ----------------------------------------------------------------"
  echo "  Mem_Buf_Limit: memory buffer is cleared when the buffer fills."
  echo "    Default: 5MB per container log stream"
  echo "    At 10KB/min log rate: buffer fills in ~8 hours"
  echo "    When buffer fills: oldest records are dropped silently"
  echo ""
  echo "  File-based output (if configured):"
  echo "    kubelet rotates container logs at 10Mi or 5 files"
  echo "    At 1MB/hr: 10Mi lasts ~10 hours per container"
  echo "    Once rotated, logs are deleted — not archived"
  echo ""
  echo "  kubectl logs (node-side):"
  echo "    Backed by node filesystem (/var/log/containers/)"
  echo "    Rotated by kubelet — same limits as above"
  echo "    No backup. No archive. No 90-day retention."
  echo "  ----------------------------------------------------------------"
  echo ""
  echo "  WHAT THIS MEANS:"
  echo "  In a buffer-only environment, log retention is measured in hours."
  echo "  Any incident investigation that starts more than 8-24h after the"
  echo "  event will find no logs. AU-11 requires 90 days. This environment"
  echo "  cannot satisfy AU-11 without a durable log backend."
  echo ""
  echo "  The break is already in place. There is no restore step for this"
  echo "  path because the condition is the default state."
  echo ""
  echo "  Proceed to detect.md to simulate the investigation failure."
fi

echo ""
echo "============================================================"
echo "BREAK COMPLETE — ${TIMESTAMP}"
echo ""
echo "  The condition: logs older than 24h do not exist."
echo "  The scenario:  an incident is reported 48h after the event."
echo "  The outcome:   the investigator finds nothing."
echo ""
echo "  Proceed to detect.md."
echo "============================================================"
