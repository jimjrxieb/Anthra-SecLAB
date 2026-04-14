#!/usr/bin/env bash
#
# CSF: PROTECT / PR.PS-01 — Configuration management practices established and applied
# CIS v8: 16.12 — Implement Code-Level Security Checks
# NIST 800-53: SI-10 — Information Input Validation, SC-8 — Transmission Confidentiality
#
# L7-02 PR.PS-01 — Baseline: Capture current security header state
# Records which security headers are present in the UI nginx response.
# Run this BEFORE break.sh to establish the ground truth.
#
# Usage: bash baseline.sh
# Expected (hardened): All 7 headers present in response
# Expected (broken):   No headers present

set -euo pipefail

NAMESPACE="anthra"
LABEL_SELECTOR="app.kubernetes.io/component=ui"
OUTFILE="/tmp/L7-02-baseline-$(date +%Y%m%d-%H%M%S).txt"

echo "=== L7-02 PR.PS-01 Baseline ==="
echo "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "Namespace: ${NAMESPACE}"
echo ""

# Locate the UI pod
UI_POD=$(kubectl get pods -n "${NAMESPACE}" \
  -l "${LABEL_SELECTOR}" \
  --field-selector=status.phase=Running \
  -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)

if [[ -z "${UI_POD}" ]]; then
  echo "ERROR: No running UI pod found in namespace '${NAMESPACE}' with label '${LABEL_SELECTOR}'"
  echo "       Check pod status: kubectl get pods -n ${NAMESPACE}"
  exit 1
fi

echo "UI pod: ${UI_POD}"
echo ""

# Capture raw response headers from inside the pod
# This bypasses any edge proxies or load balancers — tests the origin server directly
echo "--- Raw response headers from nginx (curl to localhost:8080) ---"
RAW_HEADERS=$(kubectl exec -n "${NAMESPACE}" "${UI_POD}" -- \
  curl -sI http://localhost:8080/ 2>/dev/null || true)

echo "${RAW_HEADERS}"
echo ""

# Save raw headers to file
{
  echo "=== L7-02 Baseline: $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
  echo "Pod: ${UI_POD}"
  echo ""
  echo "--- Raw Headers ---"
  echo "${RAW_HEADERS}"
  echo ""
} > "${OUTFILE}"

# Check each security header individually
echo "--- Security Header Status ---"
printf "%-45s  %s\n" "HEADER" "STATUS"
printf "%-45s  %s\n" "------" "------"

{
  echo "--- Security Header Status ---"
  printf "%-45s  %s\n" "HEADER" "STATUS"
} >> "${OUTFILE}"

check_header() {
  local HEADER_PATTERN="$1"
  local HEADER_NAME="$2"
  local VALUE
  VALUE=$(echo "${RAW_HEADERS}" | grep -i "${HEADER_PATTERN}" | head -1 || true)
  if [[ -n "${VALUE}" ]]; then
    printf "  PRESENT  %-45s  %s\n" "${HEADER_NAME}" "${VALUE}"
    printf "  PRESENT  %-45s  %s\n" "${HEADER_NAME}" "${VALUE}" >> "${OUTFILE}"
  else
    printf "  MISSING  %-45s  (not in response)\n" "${HEADER_NAME}"
    printf "  MISSING  %-45s  (not in response)\n" "${HEADER_NAME}" >> "${OUTFILE}"
  fi
}

check_header "content-security-policy"   "Content-Security-Policy"
check_header "x-frame-options"           "X-Frame-Options"
check_header "x-content-type-options"    "X-Content-Type-Options"
check_header "x-xss-protection"         "X-XSS-Protection"
check_header "referrer-policy"           "Referrer-Policy"
check_header "permissions-policy"        "Permissions-Policy"
check_header "strict-transport-security" "Strict-Transport-Security"

echo ""

# Count present vs missing
PRESENT=$(echo "${RAW_HEADERS}" | grep -icE "(content-security-policy|x-frame-options|x-content-type-options|x-xss-protection|referrer-policy|permissions-policy|strict-transport-security)" || echo 0)
echo "Headers present: ${PRESENT} of 7"

if [[ "${PRESENT}" -eq 7 ]]; then
  echo "STATE: HARDENED — all security headers present"
elif [[ "${PRESENT}" -eq 0 ]]; then
  echo "STATE: BROKEN — no security headers present (already stripped)"
else
  echo "STATE: PARTIAL — some headers present, some missing"
fi

echo ""

# Capture deployment info
echo "--- Deployment Info ---"
kubectl get deployment portfolio-anthra-portfolio-app-ui -n "${NAMESPACE}" \
  -o jsonpath='Name: {.metadata.name}{"\n"}Replicas: {.status.readyReplicas}/{.spec.replicas}{"\n"}Image: {.spec.template.spec.containers[0].image}{"\n"}' \
  2>/dev/null || echo "WARNING: Could not retrieve deployment info"

echo ""

# Show current nginx config
echo "--- Current nginx config (/etc/nginx/conf.d/default.conf) ---"
kubectl exec -n "${NAMESPACE}" "${UI_POD}" -- \
  cat /etc/nginx/conf.d/default.conf 2>/dev/null || echo "WARNING: Could not read nginx config"

echo ""
echo "Baseline saved to: ${OUTFILE}"
echo "=== Baseline complete ==="
echo ""
echo "NEXT STEP: Run break.sh to strip the security headers, then proceed to detect.md"
