#!/usr/bin/env bash
#
# CSF: PROTECT / PR.AA-05 — Access permissions managed
# CIS v8: 3.3 — Configure Data Access Control Lists
# NIST 800-53: AC-3 — Access Enforcement
#
# L7-01 PR.AA-05 — Baseline: Capture pre-break endpoint status
# Records HTTP response codes for all Portfolio API endpoints.
# Run this BEFORE break.sh to establish the ground truth.
#
# Usage: bash baseline.sh
# Expected: /docs=200, /redoc=200, /openapi.json=200, /health=200 (vulnerability pre-exists)

set -euo pipefail

NAMESPACE="anthra"
LABEL_SELECTOR="app.kubernetes.io/component=api"
OUTFILE="/tmp/L7-01-baseline-$(date +%Y%m%d-%H%M%S).txt"

echo "=== L7-01 PR.AA-05 Baseline ==="
echo "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "Namespace: ${NAMESPACE}"
echo ""

# Locate the API pod
API_POD=$(kubectl get pods -n "${NAMESPACE}" \
  -l "${LABEL_SELECTOR}" \
  --field-selector=status.phase=Running \
  -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)

if [[ -z "${API_POD}" ]]; then
  echo "ERROR: No running API pod found in namespace '${NAMESPACE}' with label '${LABEL_SELECTOR}'"
  echo "       Check pod status: kubectl get pods -n ${NAMESPACE}"
  exit 1
fi

echo "API pod: ${API_POD}"
echo ""

# Check each endpoint from inside the pod
# This bypasses any external network controls and tests the app directly
declare -A ENDPOINTS
ENDPOINTS["/docs"]="Swagger UI (documentation endpoint)"
ENDPOINTS["/redoc"]="ReDoc viewer (documentation endpoint)"
ENDPOINTS["/openapi.json"]="OpenAPI schema (full API surface)"
ENDPOINTS["/health"]="Health check (should always be accessible)"

echo "--- Endpoint Status ---"
printf "%-20s  %-6s  %s\n" "ENDPOINT" "STATUS" "DESCRIPTION"
printf "%-20s  %-6s  %s\n" "--------" "------" "-----------"

{
  echo "=== L7-01 Baseline: $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
  echo "Pod: ${API_POD}"
  printf "%-20s  %-6s  %s\n" "ENDPOINT" "STATUS" "DESCRIPTION"
} >> "${OUTFILE}"

for ENDPOINT in "/health" "/docs" "/redoc" "/openapi.json"; do
  DESC="${ENDPOINTS[${ENDPOINT}]}"
  STATUS=$(kubectl exec -n "${NAMESPACE}" "${API_POD}" -- \
    curl -s -o /dev/null -w "%{http_code}" \
    "http://localhost:8000${ENDPOINT}" 2>/dev/null || echo "ERR")

  printf "%-20s  %-6s  %s\n" "${ENDPOINT}" "${STATUS}" "${DESC}"
  printf "%-20s  %-6s  %s\n" "${ENDPOINT}" "${STATUS}" "${DESC}" >> "${OUTFILE}"
done

echo ""
echo "--- Deployment Info ---"
kubectl get deployment portfolio-anthra-portfolio-app-api -n "${NAMESPACE}" \
  -o jsonpath='Name: {.metadata.name}{"\n"}Replicas: {.status.readyReplicas}/{.spec.replicas}{"\n"}Image: {.spec.template.spec.containers[0].image}{"\n"}' \
  2>/dev/null || echo "WARNING: Could not retrieve deployment info"

echo ""
echo "--- Environment Variables (docs-related) ---"
kubectl exec -n "${NAMESPACE}" "${API_POD}" -- \
  sh -c 'env | grep -i docs || echo "No DOCS-related env vars set"' 2>/dev/null || true

echo ""
echo "Baseline saved to: ${OUTFILE}"
echo "=== Baseline complete ==="
echo ""
echo "NEXT STEP: Run break.sh to verify the vulnerability, then proceed to detect.md"
