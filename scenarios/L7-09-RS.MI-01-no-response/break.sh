#!/usr/bin/env bash
# =============================================================================
# L7-09 — RS.MI-01: Detection Without Response
# Phase: BREAK — Exec into the API pod to trigger Falco's shell-in-container rule
#
# CSF:       RESPOND / RS.MI-01 (Incidents are contained)
# CIS v8:    17.2 — Establish and Maintain Contact Information for Incidents
# NIST:      IR-4 — Incident Handling
# Cluster:   k3d-seclab
# Namespace: anthra (target), falco (monitoring)
#
# WHAT THIS DOES:
#   Executes a shell command inside the Portfolio API pod. This triggers Falco's
#   "Terminal shell in container" rule — a HIGH priority rule that fires whenever
#   a shell is spawned inside a running container. The rule is correct: this action
#   is an indicator of compromise. An attacker who exec's into a container can
#   exfiltrate data, plant backdoors, or pivot to other workloads.
#
#   After triggering the alert, the script checks where it was routed. If
#   Falcosidekick has no outputs configured, the alert exists only in Falco's
#   stdout — visible only to someone actively tailing the logs. That is the finding.
#
# NOTE: The exec command is harmless (writes to /tmp, a writable ephemeral dir).
#       The point is to generate a real Falco alert, then trace where it went.
# =============================================================================
set -euo pipefail

ANTHRA_NS="anthra"
FALCO_NS="falco"
API_DEPLOY="portfolio-anthra-portfolio-app-api"

echo "============================================================"
echo "L7-09 BREAK — Trigger Falco Alert via Container Exec"
echo "Target namespace:  ${ANTHRA_NS}"
echo "Target deployment: ${API_DEPLOY}"
echo "Monitoring:        ${FALCO_NS}"
echo "============================================================"
echo ""

# Verify the deployment exists
if ! kubectl get deployment "${API_DEPLOY}" -n "${ANTHRA_NS}" &>/dev/null; then
  echo "ERROR: Deployment ${API_DEPLOY} not found in namespace ${ANTHRA_NS}."
  echo "       Run: kubectl get deployments -n ${ANTHRA_NS}"
  exit 1
fi

# Record the timestamp before the exec so we can search Falco logs afterward
TRIGGER_TIMESTAMP=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
TRIGGER_EPOCH=$(date +%s)

echo "Trigger timestamp: ${TRIGGER_TIMESTAMP}"
echo ""
echo "------------------------------------------------------------"
echo "STEP 1: Open a second terminal and watch Falco in real time:"
echo ""
echo "  FALCO_POD=\$(kubectl get pods -n ${FALCO_NS} \\"
echo "    -l app.kubernetes.io/name=falco --no-headers | awk '{print \$1}' | head -1)"
echo "  kubectl logs -n ${FALCO_NS} \$FALCO_POD -f"
echo ""
echo "This lets you see the alert fire in real time."
echo "Starting exec in 5 seconds..."
echo "------------------------------------------------------------"
sleep 5

# Perform the exec — writes to /tmp (attacker-like behavior, harmless in lab)
echo ""
echo "Executing shell command inside ${API_DEPLOY}..."
echo ""

kubectl exec -n "${ANTHRA_NS}" "deployment/${API_DEPLOY}" \
  -- /bin/sh -c "echo 'attacker-simulation: L7-09 break' > /tmp/evidence.txt && cat /tmp/evidence.txt" \
  2>/dev/null || {
    # If /bin/sh is not available, try bash or sh via alternate path
    kubectl exec -n "${ANTHRA_NS}" "deployment/${API_DEPLOY}" \
      -- sh -c "echo 'attacker-simulation: L7-09 break' > /tmp/evidence.txt" \
      2>/dev/null || true
  }

echo ""
echo "Exec completed. Waiting 3 seconds for Falco to process the event..."
sleep 3

# --- Check Falco logs for the alert ---
echo ""
echo "------------------------------------------------------------"
echo "STEP 2: Checking Falco logs for the triggered alert..."
echo "------------------------------------------------------------"
echo ""

FALCO_POD=$(kubectl get pods -n "${FALCO_NS}" \
  -l "app.kubernetes.io/name=falco" \
  --no-headers 2>/dev/null | awk '{print $1}' | head -1 || true)

if [[ -z "${FALCO_POD}" ]]; then
  echo "WARNING: Falco pod not found in ${FALCO_NS}."
  echo "         Cannot verify alert was generated."
else
  echo "Falco pod: ${FALCO_POD}"
  echo ""
  echo "Recent Falco log lines (last 30 lines):"
  kubectl logs -n "${FALCO_NS}" "${FALCO_POD}" \
    --tail=30 --prefix=false 2>/dev/null | \
    grep -iE "(shell|exec|terminal|spawn|evidence)" | head -10 || \
    echo "  (No matching lines found -- check full logs manually)"
  echo ""
  echo "Full recent output (last 15 lines):"
  kubectl logs -n "${FALCO_NS}" "${FALCO_POD}" \
    --tail=15 --prefix=false 2>/dev/null | head -15
fi

echo ""
echo "------------------------------------------------------------"
echo "STEP 3: Checking Falcosidekick for forwarded alerts..."
echo "------------------------------------------------------------"
echo ""

SIDEKICK_POD=$(kubectl get pods -n "${FALCO_NS}" \
  -l "app.kubernetes.io/name=falcosidekick" \
  --no-headers 2>/dev/null | awk '{print $1}' | head -1 || true)

if [[ -z "${SIDEKICK_POD}" ]]; then
  echo "WARNING: Falcosidekick pod not found."
  echo "         Falcosidekick may not be deployed."
else
  echo "Falcosidekick pod: ${SIDEKICK_POD}"
  echo ""
  echo "Falcosidekick logs (last 20 lines):"
  kubectl logs -n "${FALCO_NS}" "${SIDEKICK_POD}" \
    --tail=20 --prefix=false 2>/dev/null | head -20
  echo ""
  echo "Check the above for: 'outputs enabled', forwarding lines, or error messages."
  echo "If you see only '[info] Starting...' lines and no forwarding -- that is the finding."
fi

echo ""
echo "============================================================"
echo "BREAK COMPLETE"
echo ""
echo "The exec happened. Falco fired an alert (verify in logs above)."
echo ""
echo "The question now is: WHO WAS NOTIFIED?"
echo ""
echo "  - Did you receive a Slack message? [Yes/No]"
echo "  - Did a webhook fire? [Yes/No]"
echo "  - Is there a PagerDuty ticket? [Yes/No]"
echo "  - Is there a Splunk event? [Yes/No]"
echo ""
echo "If all answers are No: detection without response. That is the finding."
echo "Record the trigger timestamp: ${TRIGGER_TIMESTAMP}"
echo ""
echo "Proceed to detect.md for the L1 analyst workflow."
echo "============================================================"
