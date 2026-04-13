#!/usr/bin/env bash
#
# CSF: PROTECT / PR.AA-05 — Access permissions managed
# CIS v8: 3.3 — Configure Data Access Control Lists
# NIST 800-53: AC-3 — Access Enforcement
#
# L7-01 PR.AA-05 — Verify: Confirm documentation endpoints are disabled
#
# Checks that /docs, /redoc, and /openapi.json return non-200,
# and that /health still returns 200 (service is healthy).
#
# Usage: bash verify.sh
# Expected: /docs=404, /redoc=404, /openapi.json=404, /health=200

set -euo pipefail

NAMESPACE="anthra"
LABEL_SELECTOR="app.kubernetes.io/component=api"

echo "=== L7-01 PR.AA-05 Verify: Checking documentation endpoint status ==="
echo "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo ""

# Locate the API pod
API_POD=$(kubectl get pods -n "${NAMESPACE}" \
  -l "${LABEL_SELECTOR}" \
  --field-selector=status.phase=Running \
  -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)

if [[ -z "${API_POD}" ]]; then
  echo "ERROR: No running API pod found in namespace '${NAMESPACE}'"
  echo "       Check: kubectl get pods -n ${NAMESPACE}"
  exit 1
fi

echo "API pod: ${API_POD}"
echo ""

# Track overall pass/fail
PASS=0
FAIL=0

check_endpoint() {
  local ENDPOINT="$1"
  local EXPECTED="$2"
  local DESCRIPTION="$3"

  local STATUS
  STATUS=$(kubectl exec -n "${NAMESPACE}" "${API_POD}" -- \
    curl -s -o /dev/null -w "%{http_code}" \
    "http://localhost:8000${ENDPOINT}" 2>/dev/null || echo "ERR")

  if [[ "${STATUS}" == "${EXPECTED}" ]]; then
    printf "  PASS  %-20s  got=%s  expected=%s  (%s)\n" \
      "${ENDPOINT}" "${STATUS}" "${EXPECTED}" "${DESCRIPTION}"
    PASS=$(( PASS + 1 ))
  else
    printf "  FAIL  %-20s  got=%s  expected=%s  (%s)\n" \
      "${ENDPOINT}" "${STATUS}" "${EXPECTED}" "${DESCRIPTION}"
    FAIL=$(( FAIL + 1 ))
  fi
}

echo "--- Documentation endpoints (expect non-200 after fix) ---"
check_endpoint "/docs"         "404" "Swagger UI — must be disabled"
check_endpoint "/redoc"        "404" "ReDoc viewer — must be disabled"
check_endpoint "/openapi.json" "404" "OpenAPI schema — must be disabled"

echo ""
echo "--- Health check (expect 200 — service must remain healthy) ---"
check_endpoint "/health" "200" "Health check — service must be up"

echo ""
echo "--- Summary ---"
echo "  PASS: ${PASS}"
echo "  FAIL: ${FAIL}"
echo ""

if [[ "${FAIL}" -eq 0 ]]; then
  echo "RESULT: ALL CHECKS PASSED"
  echo ""
  echo "Documentation endpoints are disabled. /health is responding."
  echo "The finding is remediated."
  echo ""
  echo "NEXT STEP: Fill in report-template.md with the evidence and timeline."
else
  echo "RESULT: ${FAIL} CHECK(S) FAILED"
  echo ""

  # Targeted troubleshooting guidance based on what failed
  DOCS_STATUS=$(kubectl exec -n "${NAMESPACE}" "${API_POD}" -- \
    curl -s -o /dev/null -w "%{http_code}" "http://localhost:8000/docs" 2>/dev/null || echo "ERR")

  HEALTH_STATUS=$(kubectl exec -n "${NAMESPACE}" "${API_POD}" -- \
    curl -s -o /dev/null -w "%{http_code}" "http://localhost:8000/health" 2>/dev/null || echo "ERR")

  if [[ "${DOCS_STATUS}" == "200" ]]; then
    echo "--- Troubleshooting: /docs still returning 200 ---"
    echo ""
    echo "1. Check that DISABLE_DOCS=true was set:"
    echo "   kubectl get deployment portfolio-anthra-portfolio-app-api -n ${NAMESPACE} \\"
    echo "     -o jsonpath='{.spec.template.spec.containers[0].env}'"
    echo ""
    echo "2. Check that the app code reads DISABLE_DOCS and passes docs_url=None:"
    echo "   kubectl exec -n ${NAMESPACE} ${API_POD} -- \\"
    echo "     sh -c 'grep -n \"DISABLE_DOCS\\|docs_url\" /app/main.py 2>/dev/null'"
    echo ""
    echo "3. If the app does not check DISABLE_DOCS, the env var fix has no effect."
    echo "   The permanent fix (code change) is required. See remediate.md."
    echo ""
    echo "4. Confirm the rollout completed with the new env var:"
    echo "   kubectl rollout history deployment/portfolio-anthra-portfolio-app-api -n ${NAMESPACE}"
  fi

  if [[ "${HEALTH_STATUS}" != "200" ]]; then
    echo "--- Troubleshooting: /health not returning 200 ---"
    echo ""
    echo "WARNING: The API service may be down or unhealthy."
    echo ""
    echo "1. Check pod status:"
    echo "   kubectl get pods -n ${NAMESPACE} -l app.kubernetes.io/component=api"
    echo ""
    echo "2. Check recent events:"
    echo "   kubectl describe pod ${API_POD} -n ${NAMESPACE} | tail -20"
    echo ""
    echo "3. Check pod logs for startup errors:"
    echo "   kubectl logs -n ${NAMESPACE} ${API_POD} --tail=50"
    echo ""
    echo "4. If the rollout caused a crash, roll back:"
    echo "   kubectl rollout undo deployment/portfolio-anthra-portfolio-app-api -n ${NAMESPACE}"
  fi

  exit 1
fi
