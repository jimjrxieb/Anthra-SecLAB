#!/usr/bin/env bash
#
# CSF: PROTECT / PR.AA-05 — Access permissions managed
# CIS v8: 3.3 — Configure Data Access Control Lists
# NIST 800-53: AC-3 — Access Enforcement
#
# L7-01 PR.AA-05 — Break: Verify documentation endpoint exposure
#
# REALISTIC NOTE: FastAPI enables /docs, /redoc, and /openapi.json by default.
# This "break" confirms the vulnerability pre-exists — no injection required.
# If the app was already hardened (DISABLE_DOCS=true), this script re-enables
# the defaults so the analyst can practice detection and remediation.
#
# Usage: bash break.sh
# Expected: /docs returns 200 (vulnerability confirmed or re-enabled)

set -euo pipefail

NAMESPACE="anthra"
LABEL_SELECTOR="app.kubernetes.io/component=api"
DEPLOYMENT="portfolio-anthra-portfolio-app-api"

echo "=== L7-01 PR.AA-05 Break: Verifying documentation endpoint exposure ==="
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

# Check current state of /docs
echo "--- Checking /docs endpoint ---"
DOCS_STATUS=$(kubectl exec -n "${NAMESPACE}" "${API_POD}" -- \
  curl -s -o /dev/null -w "%{http_code}" \
  "http://localhost:8000/docs" 2>/dev/null || echo "ERR")

echo "/docs HTTP status: ${DOCS_STATUS}"
echo ""

if [[ "${DOCS_STATUS}" == "200" ]]; then
  echo "CONFIRMED: Vulnerability pre-exists."
  echo "FastAPI enables documentation endpoints by default."
  echo "/docs is returning 200 without any authentication."
  echo ""
  echo "This is the expected starting state for this scenario."
  echo "No injection needed — the misconfiguration is already present."
else
  echo "NOTE: /docs is not returning 200 (got: ${DOCS_STATUS})."
  echo "The app may already have DISABLE_DOCS=true set."
  echo "Re-enabling documentation endpoints for the scenario..."
  echo ""

  # Re-enable docs by removing the DISABLE_DOCS env var if present
  kubectl set env deployment/"${DEPLOYMENT}" \
    -n "${NAMESPACE}" \
    DISABLE_DOCS- \
    2>/dev/null || true

  echo "Waiting for rollout..."
  kubectl rollout status deployment/"${DEPLOYMENT}" -n "${NAMESPACE}" --timeout=90s

  # Re-locate pod after rollout
  API_POD=$(kubectl get pods -n "${NAMESPACE}" \
    -l "${LABEL_SELECTOR}" \
    --field-selector=status.phase=Running \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)

  DOCS_STATUS=$(kubectl exec -n "${NAMESPACE}" "${API_POD}" -- \
    curl -s -o /dev/null -w "%{http_code}" \
    "http://localhost:8000/docs" 2>/dev/null || echo "ERR")

  echo "/docs HTTP status after re-enable: ${DOCS_STATUS}"
fi

echo ""
echo "=== Break complete ==="
echo ""
echo "--- Verify the exposure yourself ---"
echo "Run a port-forward to access /docs from your browser:"
echo ""
echo "  kubectl port-forward -n ${NAMESPACE} svc/portfolio-anthra-portfolio-app-api 8000:8000 &"
echo "  curl -s -o /dev/null -w '%{http_code}' http://localhost:8000/docs"
echo "  # Open http://localhost:8000/docs in your browser"
echo "  # You should see the full Swagger UI with all routes exposed"
echo ""
echo "  curl -s http://localhost:8000/openapi.json | python3 -m json.tool | head -60"
echo "  # This downloads the full API schema with no authentication"
echo ""
echo "NEXT STEP: Follow detect.md to practice discovery from the analyst perspective"
