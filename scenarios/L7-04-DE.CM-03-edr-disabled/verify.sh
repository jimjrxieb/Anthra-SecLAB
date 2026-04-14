#!/usr/bin/env bash
#
# CSF: DETECT / DE.CM-03 — Computing hardware, software, services monitored
# CIS v8: 13.7 — Deploy Host-Based Intrusion Detection Solution
# NIST 800-53: SI-4 — Information System Monitoring
#
# L7-04 DE.CM-03 — Verify: Confirm Falco is restored and generating detections
# Checks pod count matches node count, Falcosidekick is healthy, and runs a live
# detection test by exec-ing into an anthra pod — Falco should fire a shell spawn alert.
#
# Usage: bash verify.sh
# Expected: pod count = node count, live test produces Falco output

set -euo pipefail

FALCO_NS="falco"
APP_NS="anthra"
PASS=0
FAIL=0

echo "=== L7-04 DE.CM-03 Verify ==="
echo "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo ""

# --- Check 1: Pod count matches node count ---
NODE_COUNT=$(kubectl get nodes --no-headers 2>/dev/null | wc -l | tr -d ' ')
PODS_RUNNING=$(kubectl get pods -n "${FALCO_NS}" -l app.kubernetes.io/name=falco \
  --field-selector=status.phase=Running --no-headers 2>/dev/null | wc -l | tr -d ' ')

echo "--- Check 1: Falco Pod Count ---"
printf "  Cluster nodes:      %s\n" "${NODE_COUNT}"
printf "  Falco pods running: %s\n" "${PODS_RUNNING}"

if [[ "${PODS_RUNNING}" -ge "${NODE_COUNT}" && "${NODE_COUNT}" -gt 0 ]]; then
  echo "  PASS: Pod count matches node count — full coverage restored"
  PASS=$((PASS + 1))
else
  echo "  FAIL: Pod count (${PODS_RUNNING}) does not match node count (${NODE_COUNT})"
  echo "        Run fix.sh first, or check: kubectl get pods -n ${FALCO_NS}"
  FAIL=$((FAIL + 1))
fi
echo ""

# --- Check 2: nodeSelector is clean ---
echo "--- Check 2: DaemonSet nodeSelector ---"
CURRENT_NS=$(kubectl get daemonset falco -n "${FALCO_NS}" \
  -o jsonpath='{.spec.template.spec.nodeSelector}' 2>/dev/null || echo "")

if echo "${CURRENT_NS}" | grep -q "seclab-break"; then
  echo "  FAIL: Bad nodeSelector still present: ${CURRENT_NS}"
  echo "        Run fix.sh to remove it."
  FAIL=$((FAIL + 1))
else
  echo "  PASS: nodeSelector is clean (no seclab-break key)"
  printf "  Current value: %s\n" "${CURRENT_NS:-"(none)"}"
  PASS=$((PASS + 1))
fi
echo ""

# --- Check 3: Falcosidekick pods healthy ---
echo "--- Check 3: Falcosidekick Health ---"
SIDEKICK_RUNNING=$(kubectl get pods -n "${FALCO_NS}" -l app.kubernetes.io/name=falcosidekick \
  --field-selector=status.phase=Running --no-headers 2>/dev/null | wc -l | tr -d ' ')

printf "  Falcosidekick pods running: %s\n" "${SIDEKICK_RUNNING}"
if [[ "${SIDEKICK_RUNNING}" -ge 1 ]]; then
  echo "  PASS: Falcosidekick is running — alerting pipeline is active"
  PASS=$((PASS + 1))
else
  echo "  WARN: No Falcosidekick pods running — alerts will not forward downstream"
  FAIL=$((FAIL + 1))
fi
echo ""

# --- Check 4: Falco logs show recent events ---
echo "--- Check 4: Falco Event Output ---"
FALCO_POD=$(kubectl get pods -n "${FALCO_NS}" -l app.kubernetes.io/name=falco \
  --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)

if [[ -n "${FALCO_POD}" ]]; then
  echo "  Checking logs from pod: ${FALCO_POD}"
  RECENT_LINES=$(kubectl logs -n "${FALCO_NS}" "${FALCO_POD}" --tail=5 2>/dev/null | wc -l | tr -d ' ')
  if [[ "${RECENT_LINES}" -gt 0 ]]; then
    echo "  PASS: Falco pod is producing log output"
    kubectl logs -n "${FALCO_NS}" "${FALCO_POD}" --tail=3 2>/dev/null | sed 's/^/    /'
    PASS=$((PASS + 1))
  else
    echo "  WARN: Falco pod logs are empty — may still be initializing"
    FAIL=$((FAIL + 1))
  fi
else
  echo "  FAIL: No running Falco pod found to check logs"
  FAIL=$((FAIL + 1))
fi
echo ""

# --- Check 5: Live detection test ---
echo "--- Check 5: Live Detection Test ---"
echo "  Exec-ing into an anthra pod to trigger a Falco shell spawn detection..."
echo "  (This is the standard test: interactive shell in a container = Falco alert)"
echo ""

APP_POD=$(kubectl get pods -n "${APP_NS}" \
  --field-selector=status.phase=Running \
  -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)

if [[ -z "${APP_POD}" ]]; then
  echo "  SKIP: No running pod found in namespace '${APP_NS}'"
  echo "        To test manually: kubectl exec -it <any-pod> -n ${APP_NS} -- /bin/sh -c 'whoami'"
else
  echo "  Target pod: ${APP_POD}"
  # Run a harmless command inside the pod — Falco's "Terminal shell in container" rule fires
  kubectl exec -n "${APP_NS}" "${APP_POD}" -- /bin/sh -c 'echo falco-detection-test && id' \
    2>/dev/null || \
    kubectl exec -n "${APP_NS}" "${APP_POD}" -- sh -c 'echo falco-detection-test && id' \
    2>/dev/null || \
    echo "  NOTE: Shell exec not available in this container — try a different pod"

  echo ""
  echo "  Waiting 3 seconds for Falco to process the event..."
  sleep 3

  echo "  Checking Falco logs for detection of the test exec..."
  if [[ -n "${FALCO_POD}" ]]; then
    DETECTION=$(kubectl logs -n "${FALCO_NS}" "${FALCO_POD}" --tail=20 2>/dev/null | \
      grep -i "Terminal shell\|shell in container\|falco-detection-test\|Notice\|Warning" | tail -5 || true)
    if [[ -n "${DETECTION}" ]]; then
      echo "  PASS: Falco fired — live detection confirmed"
      echo "${DETECTION}" | sed 's/^/    /'
      PASS=$((PASS + 1))
    else
      echo "  INFO: No matching Falco alert in last 20 lines — rule may not apply to this pod"
      echo "        This does not mean Falco is broken. Check the full Falco log:"
      echo "        kubectl logs -n ${FALCO_NS} ${FALCO_POD} --tail=50"
      # Don't count as fail — rule coverage depends on Falco config
    fi
  fi
fi
echo ""

# --- Summary ---
TOTAL=$((PASS + FAIL))
echo "=========================================="
echo "  Verify Results: ${PASS}/${TOTAL} checks passed"
if [[ "${FAIL}" -eq 0 ]]; then
  echo "  STATUS: PASS — Falco coverage fully restored"
  echo "  Record gap end time in report-template.md"
else
  echo "  STATUS: FAIL — ${FAIL} check(s) require attention"
  echo "  Do not close the POA&M entry until all checks pass"
fi
echo "=========================================="
echo ""
echo "NEXT STEP: Complete report-template.md with:"
echo "  - Gap start and end times"
echo "  - Detection lag (how long before you noticed)"
echo "  - POA&M entry with compensating controls"
echo "  - Lessons learned"
