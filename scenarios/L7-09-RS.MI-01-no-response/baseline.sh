#!/usr/bin/env bash
# =============================================================================
# L7-09 — RS.MI-01: Detection Without Response
# Phase: BASELINE — Document Falcosidekick config and current output channels
#
# CSF:       RESPOND / RS.MI-01 (Incidents are contained)
# CIS v8:    17.2 — Establish and Maintain Contact Information for Incidents
# NIST:      IR-4 — Incident Handling
# Cluster:   k3d-seclab
# Namespace: falco (Falco + Falcosidekick), anthra (target workload)
#
# WHAT THIS DOES:
#   Captures the current Falcosidekick configuration before the break.
#   Records which output channels are configured (if any), what the current
#   alert routing looks like, and whether the Falcosidekick UI is accessible.
#   This is the "before" state for the report-template.md comparison.
# =============================================================================
set -euo pipefail

FALCO_NS="falco"
ANTHRA_NS="anthra"

echo "============================================================"
echo "L7-09 BASELINE — Falcosidekick Configuration Audit"
echo "Namespace:  ${FALCO_NS}"
echo "Date:       $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "============================================================"
echo ""

# --- Step 1: Verify Falco and Falcosidekick are running ---
echo "[1/5] Checking Falco and Falcosidekick pod status..."
kubectl get pods -n "${FALCO_NS}" --no-headers 2>/dev/null || \
  echo "  WARNING: No pods found in ${FALCO_NS} namespace."
echo ""

FALCOSIDEKICK_POD=$(kubectl get pods -n "${FALCO_NS}" \
  -l "app.kubernetes.io/name=falcosidekick" \
  --no-headers 2>/dev/null | awk '{print $1}' | head -1 || true)

if [[ -z "${FALCOSIDEKICK_POD}" ]]; then
  echo "  WARNING: Falcosidekick pod not found."
  echo "           Falcosidekick may not be deployed. Check Falco Helm values."
  echo "           Run: helm get values falco -n ${FALCO_NS}"
  FALCOSIDEKICK_DEPLOYED=false
else
  echo "  Falcosidekick pod: ${FALCOSIDEKICK_POD}"
  FALCOSIDEKICK_DEPLOYED=true
fi
echo ""

# --- Step 2: Read Falcosidekick ConfigMap for output channels ---
echo "[2/5] Reading Falcosidekick configuration (ConfigMap)..."
CONFIGMAP=$(kubectl get configmap -n "${FALCO_NS}" \
  -l "app.kubernetes.io/name=falcosidekick" \
  --no-headers 2>/dev/null | awk '{print $1}' | head -1 || true)

if [[ -z "${CONFIGMAP}" ]]; then
  # Try well-known names
  for cm_name in falco-falcosidekick falcosidekick; do
    if kubectl get configmap "${cm_name}" -n "${FALCO_NS}" &>/dev/null; then
      CONFIGMAP="${cm_name}"
      break
    fi
  done
fi

if [[ -n "${CONFIGMAP}" ]]; then
  echo "  ConfigMap: ${CONFIGMAP}"
  echo ""
  kubectl get configmap "${CONFIGMAP}" -n "${FALCO_NS}" \
    -o jsonpath='{.data.config\.yaml}' 2>/dev/null || \
  kubectl get configmap "${CONFIGMAP}" -n "${FALCO_NS}" \
    -o jsonpath='{.data}' 2>/dev/null | python3 -c "import json,sys; d=json.load(sys.stdin); [print(k+': '+str(v)) for k,v in d.items()]" 2>/dev/null || \
  echo "  (Could not read ConfigMap data)"
else
  echo "  No Falcosidekick ConfigMap found."
fi
echo ""

# --- Step 3: Check Falcosidekick Helm values for output channels ---
echo "[3/5] Checking Helm values for output configuration..."
helm get values falco -n "${FALCO_NS}" 2>/dev/null | grep -A 5 -i "falcosidekick" | \
  grep -v "^--$" | head -40 || \
  echo "  (Helm release not found or helm not available)"
echo ""

# --- Step 4: Check for any configured webhook / Slack / SIEM outputs ---
echo "[4/5] Checking for configured alert outputs..."
echo ""
echo "  Checking Falcosidekick environment variables:"
if [[ "${FALCOSIDEKICK_DEPLOYED}" == "true" ]]; then
  kubectl exec -n "${FALCO_NS}" "${FALCOSIDEKICK_POD}" \
    -- env 2>/dev/null | grep -iE "(slack|webhook|pagerduty|alertmanager|splunk|siem|output)" | \
    grep -v "^PASSWORD\|SECRET\|TOKEN" | sort || \
    echo "  No output-related environment variables found."
fi
echo ""

# --- Step 5: Record current Falco alert volume ---
echo "[5/5] Sampling recent Falco alerts (last 20 lines)..."
FALCO_POD=$(kubectl get pods -n "${FALCO_NS}" \
  -l "app.kubernetes.io/name=falco" \
  --no-headers 2>/dev/null | awk '{print $1}' | head -1 || true)

if [[ -n "${FALCO_POD}" ]]; then
  kubectl logs -n "${FALCO_NS}" "${FALCO_POD}" \
    --tail=20 --prefix=false 2>/dev/null | \
    grep -i "output\|rule\|priority" | head -20 || \
    echo "  No recent Falco alert lines found."
else
  echo "  Falco pod not found. Check: kubectl get pods -n ${FALCO_NS}"
fi

echo ""
echo "============================================================"
echo "BASELINE COMPLETE"
echo ""
echo "Record the following for your report-template.md:"
echo "  - Which output channels are configured: [your observation above]"
echo "  - Is Falcosidekick reachable? [check kubectl port-forward below]"
echo "  - Are alerts going anywhere a human will see them? [Yes/No]"
echo ""
echo "Quick UI access (run in a separate terminal):"
echo "  kubectl port-forward -n ${FALCO_NS} svc/falco-falcosidekick-ui 2802:2802"
echo "  Then open: http://localhost:2802"
echo ""
echo "If the UI shows alerts but there are no notification outputs configured,"
echo "that is the finding: detection without response."
echo "Proceed to break.sh."
echo "============================================================"
