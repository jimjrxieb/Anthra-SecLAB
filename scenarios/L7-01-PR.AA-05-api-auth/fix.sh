#!/usr/bin/env bash
#
# CSF: PROTECT / PR.AA-05 — Access permissions managed
# CIS v8: 3.3 — Configure Data Access Control Lists
# NIST 800-53: AC-3 — Access Enforcement
#
# L7-01 PR.AA-05 — Fix: Disable unauthenticated documentation endpoints
#
# This script sets DISABLE_DOCS=true on the API deployment.
# The application must be written to check this variable and set:
#   docs_url=None, redoc_url=None, openapi_url=None
# in the FastAPI constructor when DISABLE_DOCS=true.
#
# NOTE: This is a D-rank runtime fix (environment variable). The permanent
# fix is a code change. See remediate.md for the code-level solution.
#
# Usage: bash fix.sh
# Expected result: /docs returns 404, /health still returns 200

set -euo pipefail

NAMESPACE="anthra"
DEPLOYMENT="portfolio-anthra-portfolio-app-api"
LABEL_SELECTOR="app.kubernetes.io/component=api"

echo "=== L7-01 PR.AA-05 Fix: Disabling documentation endpoints ==="
echo "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "Deployment: ${DEPLOYMENT}"
echo "Namespace: ${NAMESPACE}"
echo ""

# Confirm the deployment exists before touching it
if ! kubectl get deployment "${DEPLOYMENT}" -n "${NAMESPACE}" &>/dev/null; then
  echo "ERROR: Deployment '${DEPLOYMENT}' not found in namespace '${NAMESPACE}'"
  echo "       Check: kubectl get deployment -n ${NAMESPACE}"
  exit 1
fi

# Capture current env state (for rollback reference)
echo "--- Current DOCS-related environment ---"
kubectl get deployment "${DEPLOYMENT}" -n "${NAMESPACE}" \
  -o jsonpath='{range .spec.template.spec.containers[0].env[*]}{.name}={.value}{"\n"}{end}' \
  2>/dev/null | grep -i docs || echo "No DOCS-related env vars currently set"
echo ""

# Set DISABLE_DOCS=true
# The FastAPI app must check this variable. See remediate.md for the code pattern.
echo "Setting DISABLE_DOCS=true on deployment..."
kubectl set env deployment/"${DEPLOYMENT}" \
  -n "${NAMESPACE}" \
  DISABLE_DOCS=true

echo ""
echo "Waiting for rollout to complete..."
kubectl rollout status deployment/"${DEPLOYMENT}" \
  -n "${NAMESPACE}" \
  --timeout=120s

echo ""
echo "--- Post-fix endpoint check ---"

# Locate the new pod
API_POD=$(kubectl get pods -n "${NAMESPACE}" \
  -l "${LABEL_SELECTOR}" \
  --field-selector=status.phase=Running \
  -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)

if [[ -z "${API_POD}" ]]; then
  echo "WARNING: Could not locate running API pod after rollout."
  echo "         Check: kubectl get pods -n ${NAMESPACE}"
  echo "         The deployment rollout may still be in progress."
  exit 1
fi

echo "New pod: ${API_POD}"
echo ""

for ENDPOINT in /health /docs /redoc /openapi.json; do
  STATUS=$(kubectl exec -n "${NAMESPACE}" "${API_POD}" -- \
    curl -s -o /dev/null -w "%{http_code}" \
    "http://localhost:8000${ENDPOINT}" 2>/dev/null || echo "ERR")
  printf "%-20s  %s\n" "${ENDPOINT}" "${STATUS}"
done

echo ""
echo "=== Fix applied ==="
echo ""
echo "--- IMPORTANT: Runtime vs Permanent Fix ---"
echo ""
echo "This fix uses an environment variable. It works immediately and is"
echo "reversible, but it depends on the application checking DISABLE_DOCS."
echo ""
echo "The permanent fix is a code change in the FastAPI constructor:"
echo ""
echo "  # In main.py — replace:"
echo "  app = FastAPI()"
echo ""
echo "  # With:"
echo "  app = FastAPI("
echo "      docs_url=None,"
echo "      redoc_url=None,"
echo "      openapi_url=None,"
echo "  )"
echo ""
echo "See remediate.md for full context, CIS/NIST justification, and code diff."
echo ""
echo "--- Rollback (if needed) ---"
echo "  kubectl set env deployment/${DEPLOYMENT} -n ${NAMESPACE} DISABLE_DOCS-"
echo "  kubectl rollout status deployment/${DEPLOYMENT} -n ${NAMESPACE}"
echo ""
echo "NEXT STEP: Run verify.sh to confirm the fix, then fill in report-template.md"
