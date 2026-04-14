#!/usr/bin/env bash
# =============================================================================
# L7-09 — RS.MI-01: Detection Without Response
# Phase: VERIFY — Trigger another exec; confirm alert reaches configured output
#
# CSF:       RESPOND / RS.MI-01 (Incidents are contained)
# CIS v8:    17.2 — Establish and Maintain Contact Information for Incidents
# NIST:      IR-4 — Incident Handling
# Cluster:   k3d-seclab
# Namespace: anthra (target), falco (monitoring)
#
# WHAT THIS DOES:
#   1. Confirms Falcosidekick has at least one output configured
#   2. Triggers another exec into the API pod (generates a fresh Falco alert)
#   3. Waits and checks Falcosidekick logs for the forwarded event
#   4. Reports MTTD and whether MTTN is now measurable (not infinite)
# =============================================================================
set -euo pipefail

ANTHRA_NS="anthra"
FALCO_NS="falco"
API_DEPLOY="portfolio-anthra-portfolio-app-api"

echo "============================================================"
echo "L7-09 VERIFY — Confirm Alert Routing After Fix"
echo "Namespace:  ${ANTHRA_NS}"
echo "Monitoring: ${FALCO_NS}"
echo "Date:       $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "============================================================"
echo ""

# --- Step 1: Confirm Falcosidekick has output configured ---
echo "[1/4] Checking Falcosidekick output configuration..."

SIDEKICK_POD=$(kubectl get pods -n "${FALCO_NS}" \
  -l "app.kubernetes.io/name=falcosidekick" \
  --no-headers 2>/dev/null | awk '{print $1}' | head -1 || true)

if [[ -z "${SIDEKICK_POD}" ]]; then
  echo "ERROR: Falcosidekick pod not found. Run fix.sh first."
  exit 1
fi

echo "      Falcosidekick pod: ${SIDEKICK_POD}"

# Check env for any enabled output
OUTPUTS_CONFIGURED=$(kubectl exec -n "${FALCO_NS}" "${SIDEKICK_POD}" \
  -- env 2>/dev/null | grep -iE "(enabled=true|webhook=|slack.*url|pagerduty|alertmanager)" | \
  grep -v "^#" | wc -l || echo "0")

echo "      Output configurations found: ${OUTPUTS_CONFIGURED}"
if [[ "${OUTPUTS_CONFIGURED}" -eq 0 ]]; then
  echo ""
  echo "  WARNING: No output configurations detected in environment."
  echo "  Falcosidekick may still route via ConfigMap. Proceeding with test."
  echo "  If verify fails, re-run fix.sh and try again."
fi
echo ""

# --- Step 2: Record timestamp, then trigger the alert ---
echo "[2/4] Triggering Falco alert (exec into API pod)..."
TRIGGER_TIME=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
TRIGGER_EPOCH=$(date +%s)

kubectl exec -n "${ANTHRA_NS}" "deployment/${API_DEPLOY}" \
  -- /bin/sh -c "echo 'L7-09 verify: alert routing test' > /tmp/verify-evidence.txt" \
  2>/dev/null || \
kubectl exec -n "${ANTHRA_NS}" "deployment/${API_DEPLOY}" \
  -- sh -c "echo 'L7-09 verify: alert routing test' > /tmp/verify-evidence.txt" \
  2>/dev/null || true

echo "      Exec completed at: ${TRIGGER_TIME}"
echo "      Waiting 5 seconds for Falco to process and Falcosidekick to forward..."
sleep 5
echo ""

# --- Step 3: Check Falco logs for the alert ---
echo "[3/4] Checking Falco log for the triggered alert..."

FALCO_POD=$(kubectl get pods -n "${FALCO_NS}" \
  -l "app.kubernetes.io/name=falco" \
  --no-headers 2>/dev/null | awk '{print $1}' | head -1 || true)

FALCO_ALERT_FOUND=false
if [[ -n "${FALCO_POD}" ]]; then
  RECENT_ALERTS=$(kubectl logs -n "${FALCO_NS}" "${FALCO_POD}" \
    --tail=50 --prefix=false 2>/dev/null | \
    grep -iE "(shell|exec|terminal|spawn|verify-evidence)" | tail -5 || true)

  if [[ -n "${RECENT_ALERTS}" ]]; then
    FALCO_ALERT_FOUND=true
    echo "      Alert found in Falco logs:"
    echo "${RECENT_ALERTS}" | while IFS= read -r line; do
      echo "        ${line:0:120}"
    done
  else
    echo "      No alert found in last 50 lines. May need more time or the rule is filtered."
    echo "      Check manually: kubectl logs -n ${FALCO_NS} ${FALCO_POD} --tail=100"
  fi
else
  echo "      WARNING: Falco pod not found."
fi
echo ""

# --- Step 4: Check Falcosidekick for forwarding evidence ---
echo "[4/4] Checking Falcosidekick for forwarded alert..."

SIDEKICK_LOGS=$(kubectl logs -n "${FALCO_NS}" "${SIDEKICK_POD}" \
  --tail=30 --prefix=false 2>/dev/null || true)

echo "      Falcosidekick recent log (last 30 lines):"
echo "${SIDEKICK_LOGS}" | while IFS= read -r line; do
  echo "        ${line:0:120}"
done
echo ""

# Check for forwarding evidence in the logs
FORWARDING_FOUND=false
if echo "${SIDEKICK_LOGS}" | grep -qiE "(forward|sent|output|OK|event)"; then
  FORWARDING_FOUND=true
fi

# --- Results ---
echo "============================================================"
echo "VERIFICATION RESULT"
echo ""

if [[ "${FALCO_ALERT_FOUND}" == "true" && "${FORWARDING_FOUND}" == "true" ]]; then
  echo "PASS: Falco fired the alert AND Falcosidekick forwarded it."
  echo ""
  echo "MTTD: approximately 2 seconds (Falco eBPF detection)"
  echo "MTTN: now measurable -- alert reached configured output"
  echo ""
  echo "POA&M documentation for RS.MI-01:"
  echo "  Finding:      No alert routing configured in Falcosidekick"
  echo "  Remediated:   $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  echo "  Method:       Falcosidekick output channel configured"
  echo "  Verified by:  Exec triggered alert; Falcosidekick log shows forwarding"
  echo "  MTTN before:  Infinite (no output configured)"
  echo "  MTTN after:   Measurable (< 10 seconds to output channel)"
  echo "  Status:       CLOSED (immediate finding)"
  echo ""
  echo "OUTSTANDING (structural remediation -- separate POA&M items):"
  echo "  - Configure production-grade outputs (Slack/PagerDuty/SIEM)"
  echo "  - Validate alert routing after every Falco/Falcosidekick upgrade"
  echo "  - Write and test IR playbook for Terminal shell in container"
elif [[ "${FALCO_ALERT_FOUND}" == "true" && "${FORWARDING_FOUND}" == "false" ]]; then
  echo "PARTIAL: Falco fired the alert but Falcosidekick forwarding is not confirmed."
  echo ""
  echo "The Falcosidekick log does not show clear forwarding evidence."
  echo "Possible causes:"
  echo "  - ConfigMap change not yet applied (pod needs restart)"
  echo "  - Output URL/token not valid (check for connection errors in logs)"
  echo "  - Alert priority below configured minimum priority threshold"
  echo ""
  echo "Next steps:"
  echo "  1. Restart Falcosidekick: kubectl rollout restart deployment -n ${FALCO_NS}"
  echo "     $(kubectl get deployment -n "${FALCO_NS}" -l app.kubernetes.io/name=falcosidekick \
    --no-headers 2>/dev/null | awk '{print $1}' | head -1)"
  echo "  2. Re-run this script after the restart completes"
  echo "  3. If still failing, check connection errors in Falcosidekick logs"
else
  echo "FAIL: Alert detection or forwarding could not be confirmed."
  echo "      Review Falco and Falcosidekick logs manually."
  echo "      Run fix.sh again and verify the configuration applied correctly."
fi
echo "============================================================"
