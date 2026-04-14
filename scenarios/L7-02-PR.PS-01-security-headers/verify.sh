#!/usr/bin/env bash
#
# CSF: PROTECT / PR.PS-01 — Configuration management practices established and applied
# CIS v8: 16.12 — Implement Code-Level Security Checks
# NIST 800-53: SI-10 — Information Input Validation, SC-8 — Transmission Confidentiality
#
# L7-02 PR.PS-01 — Verify: Confirm all security headers are present
#
# Checks each of the 7 security headers in the nginx response.
# PASS/FAIL per header. Confirms the page still returns HTTP 200.
#
# Usage: bash verify.sh
# Expected: 7 PASS for headers, 1 PASS for HTTP 200

set -euo pipefail

NAMESPACE="anthra"
LABEL_SELECTOR="app.kubernetes.io/component=ui"

echo "=== L7-02 PR.PS-01 Verify: Security header presence check ==="
echo "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo ""

# Locate the UI pod
UI_POD=$(kubectl get pods -n "${NAMESPACE}" \
  -l "${LABEL_SELECTOR}" \
  --field-selector=status.phase=Running \
  -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)

if [[ -z "${UI_POD}" ]]; then
  echo "ERROR: No running UI pod found in namespace '${NAMESPACE}'"
  echo "       Check: kubectl get pods -n ${NAMESPACE}"
  exit 1
fi

echo "UI pod: ${UI_POD}"
echo ""

# Capture full response headers from inside the pod
RESPONSE=$(kubectl exec -n "${NAMESPACE}" "${UI_POD}" -- \
  curl -sI http://localhost:8080/ 2>/dev/null || true)

if [[ -z "${RESPONSE}" ]]; then
  echo "ERROR: Got empty response from nginx. Pod may not be healthy."
  echo "       Check: kubectl logs -n ${NAMESPACE} ${UI_POD} --tail=20"
  exit 1
fi

# Track overall pass/fail
PASS=0
FAIL=0

check_header() {
  local PATTERN="$1"
  local HEADER_NAME="$2"
  local EXPECTED_PARTIAL="$3"   # substring to verify in the value (optional)

  local VALUE
  VALUE=$(echo "${RESPONSE}" | grep -i "^${PATTERN}:" | tr -d '\r' || true)

  if [[ -n "${VALUE}" ]]; then
    # If a partial match is required, verify the value contains it
    if [[ -n "${EXPECTED_PARTIAL}" ]] && ! echo "${VALUE}" | grep -qi "${EXPECTED_PARTIAL}"; then
      printf "  FAIL  %-35s  found but wrong value: %s\n" "${HEADER_NAME}" "${VALUE}"
      FAIL=$(( FAIL + 1 ))
    else
      printf "  PASS  %-35s  %s\n" "${HEADER_NAME}" "${VALUE}"
      PASS=$(( PASS + 1 ))
    fi
  else
    printf "  FAIL  %-35s  (not present in response)\n" "${HEADER_NAME}"
    FAIL=$(( FAIL + 1 ))
  fi
}

echo "--- Security Header Checks ---"
check_header "content-security-policy"   "Content-Security-Policy"   "default-src"
check_header "x-frame-options"           "X-Frame-Options"           "SAMEORIGIN"
check_header "x-content-type-options"   "X-Content-Type-Options"    "nosniff"
check_header "x-xss-protection"         "X-XSS-Protection"          "mode=block"
check_header "referrer-policy"           "Referrer-Policy"           "strict-origin"
check_header "permissions-policy"        "Permissions-Policy"        "geolocation"
check_header "strict-transport-security" "Strict-Transport-Security" "max-age"

echo ""
echo "--- Page Load Check (HTTP 200) ---"

HTTP_STATUS=$(kubectl exec -n "${NAMESPACE}" "${UI_POD}" -- \
  curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/ 2>/dev/null || echo "ERR")

if [[ "${HTTP_STATUS}" == "200" ]]; then
  printf "  PASS  %-35s  HTTP %s\n" "Page load (GET /)" "${HTTP_STATUS}"
  PASS=$(( PASS + 1 ))
else
  printf "  FAIL  %-35s  HTTP %s (expected 200)\n" "Page load (GET /)" "${HTTP_STATUS}"
  FAIL=$(( FAIL + 1 ))
fi

echo ""
echo "--- Summary ---"
echo "  PASS: ${PASS}"
echo "  FAIL: ${FAIL}"
echo "  Total checks: $(( PASS + FAIL )) (7 headers + 1 page load)"
echo ""

if [[ "${FAIL}" -eq 0 ]]; then
  echo "RESULT: ALL CHECKS PASSED"
  echo ""
  echo "All 7 security headers are present. The page is serving HTTP 200."
  echo "The finding is remediated."
  echo ""
  echo "NEXT STEP: Fill in report-template.md with the before/after evidence."
else
  echo "RESULT: ${FAIL} CHECK(S) FAILED"
  echo ""

  # Targeted troubleshooting
  HEADER_COUNT=$(echo "${RESPONSE}" | \
    grep -icE "(content-security-policy|x-frame-options|x-content-type-options|x-xss-protection|referrer-policy|permissions-policy|strict-transport-security)" \
    || echo 0)

  if [[ "${HEADER_COUNT}" -eq 0 ]]; then
    echo "--- Troubleshooting: No security headers found ---"
    echo ""
    echo "The nginx config does not have the add_header directives."
    echo ""
    echo "1. Check what is in the current config:"
    echo "   kubectl exec -n ${NAMESPACE} ${UI_POD} -- cat /etc/nginx/conf.d/default.conf"
    echo ""
    echo "2. If the config is stripped, run fix.sh to restore it:"
    echo "   bash fix.sh"
    echo ""
    echo "3. If fix.sh completed but you still see no headers, check whether nginx"
    echo "   reloaded correctly:"
    echo "   kubectl exec -n ${NAMESPACE} ${UI_POD} -- nginx -t"
    echo "   kubectl exec -n ${NAMESPACE} ${UI_POD} -- nginx -s reload"
    echo ""
    echo "4. If the deployment was rolled out (fix.sh revert step), the new pod"
    echo "   uses the image-baked config. Confirm the image is correct:"
    echo "   kubectl get deployment ${DEPLOYMENT:-portfolio-anthra-portfolio-app-ui} -n ${NAMESPACE} \\"
    echo "     -o jsonpath='{.spec.template.spec.containers[0].image}'"
  fi

  if [[ "${HTTP_STATUS}" != "200" ]]; then
    echo ""
    echo "--- Troubleshooting: Page not returning HTTP 200 ---"
    echo ""
    echo "The UI pod may have a startup or config error."
    echo ""
    echo "1. Check pod logs:"
    echo "   kubectl logs -n ${NAMESPACE} ${UI_POD} --tail=30"
    echo ""
    echo "2. Check pod events:"
    echo "   kubectl describe pod ${UI_POD} -n ${NAMESPACE} | tail -20"
    echo ""
    echo "3. Validate the nginx config:"
    echo "   kubectl exec -n ${NAMESPACE} ${UI_POD} -- nginx -t"
    echo ""
    echo "4. If the rollout broke the pod, restore from the deployment rollout:"
    echo "   kubectl rollout undo deployment/portfolio-anthra-portfolio-app-ui -n ${NAMESPACE}"
  fi

  exit 1
fi
