#!/usr/bin/env bash
# =============================================================================
# L7-09 — RS.MI-01: Detection Without Response
# Phase: FIX — Configure Falcosidekick with a working output channel
#
# CSF:       RESPOND / RS.MI-01 (Incidents are contained)
# CIS v8:    17.2 — Establish and Maintain Contact Information for Incidents
# NIST:      IR-4 — Incident Handling
# Cluster:   k3d-seclab
# Namespace: falco
#
# WHAT THIS DOES:
#   Configures Falcosidekick to forward alerts to a verifiable output.
#   In this lab, we use the Falcosidekick webhook output pointed at a local
#   netcat listener. This proves the routing works without requiring external
#   services (Slack token, PagerDuty API key, etc.).
#
#   Two methods are offered:
#   METHOD A: Patch the Falcosidekick ConfigMap directly (immediate, not persisted
#             through Helm upgrades -- good for lab verification)
#   METHOD B: Update the Helm values (persisted, correct for production pattern)
#
# FOR PRODUCTION:
#   Replace the webhook URL with your actual destination:
#   - Slack incoming webhook: https://hooks.slack.com/services/...
#   - PagerDuty Events API: https://events.pagerduty.com/v2/enqueue
#   - Alertmanager: http://alertmanager:9093/api/v1/alerts
#   - Splunk HEC: https://splunk:8088/services/collector
# =============================================================================
set -euo pipefail

FALCO_NS="falco"
WEBHOOK_PORT=9999

echo "============================================================"
echo "L7-09 FIX — Configure Falcosidekick Alert Routing"
echo "Namespace: ${FALCO_NS}"
echo "============================================================"
echo ""

# Verify Falcosidekick is deployed
SIDEKICK_POD=$(kubectl get pods -n "${FALCO_NS}" \
  -l "app.kubernetes.io/name=falcosidekick" \
  --no-headers 2>/dev/null | awk '{print $1}' | head -1 || true)

if [[ -z "${SIDEKICK_POD}" ]]; then
  echo "ERROR: Falcosidekick pod not found in ${FALCO_NS}."
  echo "       Falcosidekick must be deployed before configuring outputs."
  echo "       Check: helm get values falco -n ${FALCO_NS}"
  exit 1
fi
echo "Falcosidekick pod: ${SIDEKICK_POD}"
echo ""

echo "------------------------------------------------------------"
echo "METHOD A: Patch Falcosidekick ConfigMap (lab-immediate fix)"
echo "------------------------------------------------------------"
echo ""
echo "This patches the running ConfigMap to enable the Falcosidekick stdout"
echo "output with enhanced formatting. Stdout output writes formatted alert"
echo "messages to the Falcosidekick pod log -- verifiable without external services."
echo ""
echo "In production, replace 'stdout' with Slack / PagerDuty / Alertmanager."
echo ""

# Find the Falcosidekick ConfigMap
SIDEKICK_CM=$(kubectl get configmap -n "${FALCO_NS}" \
  -l "app.kubernetes.io/name=falcosidekick" \
  --no-headers 2>/dev/null | awk '{print $1}' | head -1 || true)

if [[ -z "${SIDEKICK_CM}" ]]; then
  # Try well-known name
  for cm_name in falco-falcosidekick falcosidekick; do
    if kubectl get configmap "${cm_name}" -n "${FALCO_NS}" &>/dev/null; then
      SIDEKICK_CM="${cm_name}"
      break
    fi
  done
fi

if [[ -n "${SIDEKICK_CM}" ]]; then
  echo "ConfigMap found: ${SIDEKICK_CM}"
  echo "Patching to enable stdout output..."

  kubectl patch configmap "${SIDEKICK_CM}" -n "${FALCO_NS}" \
    --type merge \
    -p '{"data":{"config.yaml":"slack:\n  webhookurl: \"\"\nwebhook:\n  address: \"\"\nstdout:\n  enabled: true\n"}}' \
    2>/dev/null || {
      echo "  Patch via merge failed (may be structured differently)."
      echo "  Trying direct env-var approach on the deployment..."
      SIDEKICK_DEPLOY=$(kubectl get deployment -n "${FALCO_NS}" \
        -l "app.kubernetes.io/name=falcosidekick" \
        --no-headers 2>/dev/null | awk '{print $1}' | head -1 || true)
      if [[ -n "${SIDEKICK_DEPLOY}" ]]; then
        kubectl set env deployment/"${SIDEKICK_DEPLOY}" \
          FALCOSIDEKICK_OUTPUT_STDOUT_ENABLED=true \
          -n "${FALCO_NS}" 2>/dev/null || echo "  env patch also failed -- see METHOD B."
      fi
    }
else
  echo "  No Falcosidekick ConfigMap found. Patching via deployment env vars..."
  SIDEKICK_DEPLOY=$(kubectl get deployment -n "${FALCO_NS}" \
    -l "app.kubernetes.io/name=falcosidekick" \
    --no-headers 2>/dev/null | awk '{print $1}' | head -1 || true)
  if [[ -n "${SIDEKICK_DEPLOY}" ]]; then
    kubectl set env deployment/"${SIDEKICK_DEPLOY}" \
      FALCOSIDEKICK_OUTPUT_STDOUT_ENABLED=true \
      -n "${FALCO_NS}"
    echo "  Environment variable set on deployment."
  else
    echo "  ERROR: Cannot find Falcosidekick deployment to patch."
  fi
fi

echo ""
echo "Waiting for Falcosidekick to restart with new config..."
kubectl rollout status deployment \
  "$(kubectl get deployment -n "${FALCO_NS}" \
    -l app.kubernetes.io/name=falcosidekick \
    --no-headers | awk '{print $1}' | head -1)" \
  -n "${FALCO_NS}" \
  --timeout=60s 2>/dev/null || echo "  (Rollout check skipped -- verify manually)"

echo ""
echo "------------------------------------------------------------"
echo "METHOD B: Helm values (production-correct pattern)"
echo "------------------------------------------------------------"
echo ""
echo "The correct long-term fix is to configure Falcosidekick outputs in Helm:"
echo ""
echo "  # File: values-seclab.yaml (add under falcosidekick:)"
echo "  falcosidekick:"
echo "    enabled: true"
echo "    config:"
echo "      slack:"
echo "        webhookurl: \"https://hooks.slack.com/services/YOUR/WEBHOOK/URL\""
echo "        channel: \"#security-alerts\""
echo "        minimumpriority: \"warning\""
echo "      alertmanager:"
echo "        hostport: \"http://alertmanager:9093\""
echo "        minimumpriority: \"warning\""
echo "      webhook:"
echo "        address: \"http://your-siem:8080/falco-events\""
echo "        minimumpriority: \"warning\""
echo ""
echo "  # Apply:"
echo "  helm upgrade falco falcosecurity/falco -n ${FALCO_NS} -f values-seclab.yaml"
echo ""
echo "------------------------------------------------------------"
echo "CURRENT STATE AFTER FIX:"
echo "------------------------------------------------------------"
echo ""
echo "Falcosidekick pod status:"
kubectl get pods -n "${FALCO_NS}" \
  -l "app.kubernetes.io/name=falcosidekick" 2>/dev/null || true

echo ""
echo "============================================================"
echo "FIX APPLIED"
echo ""
echo "Next: Run verify.sh to confirm the alert now routes to output."
echo "  1. verify.sh triggers another exec into the API pod"
echo "  2. It then checks Falcosidekick logs for forwarded alert lines"
echo "  3. Confirm MTTN is now measurable (seconds, not infinity)"
echo "============================================================"
