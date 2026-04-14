#!/usr/bin/env bash
# =============================================================================
# L7-08 — ID.RA-01: Unpatched CVE in Container Image
# Phase: BREAK — Swap API image to an unpatched, vulnerable base image
#
# CSF:       IDENTIFY / ID.RA-01 (Vulnerabilities identified, validated, recorded)
# CIS v8:    7.4 — Perform Automated Application Patch Management
# NIST:      SI-2 — Flaw Remediation; RA-5 — Vulnerability Scanning
# Cluster:   k3d-seclab
# Namespace: anthra
#
# WHAT THIS DOES:
#   Patches the Portfolio API deployment to use python:3.9-slim — an unpinned,
#   unscanned base image with known CRITICAL CVEs in openssl, glibc, and pip.
#   This simulates an operator making an ad-hoc image change without running a
#   vulnerability scan in CI first.
#
# AVAILABILITY IMPACT:
#   The application may enter CrashLoopBackOff if the Python 3.9 runtime differs
#   from the application's build target. This is intentional and realistic.
#   A vulnerability that also causes an outage is a more serious finding, not a
#   lesser one. Document both the CVE and the availability impact in the POA&M.
#
# REVERTING: Run fix.sh to rollback. The original image is preserved in rollout
#            history and will be restored by kubectl rollout undo.
# =============================================================================
set -euo pipefail

ANTHRA_NS="anthra"
API_DEPLOY="portfolio-anthra-portfolio-app-api"
VULNERABLE_IMAGE="python:3.9-slim"

echo "============================================================"
echo "L7-08 BREAK — Swap API Image to Vulnerable Base"
echo "Namespace:  ${ANTHRA_NS}"
echo "Deployment: ${API_DEPLOY}"
echo "New image:  ${VULNERABLE_IMAGE}"
echo "============================================================"
echo ""

# Verify the deployment exists
if ! kubectl get deployment "${API_DEPLOY}" -n "${ANTHRA_NS}" &>/dev/null; then
  echo "ERROR: Deployment ${API_DEPLOY} not found in namespace ${ANTHRA_NS}."
  echo "       Run: kubectl get deployments -n ${ANTHRA_NS}"
  exit 1
fi

# Record the original image before breaking (for documentation)
ORIGINAL_IMAGE=$(kubectl get deployment "${API_DEPLOY}" -n "${ANTHRA_NS}" \
  -o jsonpath='{.spec.template.spec.containers[0].image}' 2>/dev/null || echo "unknown")

echo "Original image (will be preserved in rollout history):"
echo "  ${ORIGINAL_IMAGE}"
echo ""
echo "Swapping to vulnerable image: ${VULNERABLE_IMAGE}"
echo ""
echo "NOTE: The application may crash (CrashLoopBackOff) after this change."
echo "      That is a realistic outcome. A vulnerability can cause both a"
echo "      security risk and an availability incident simultaneously."
echo ""

# Apply the image change
kubectl set image deployment/"${API_DEPLOY}" \
  api="${VULNERABLE_IMAGE}" \
  -n "${ANTHRA_NS}"

echo ""
echo "Image change submitted. Waiting for rollout..."
echo "(Timeout: 90 seconds. If the pod crashes, rollout will show as failed.)"
echo ""

# Wait for rollout — do not fail if the app crashes, we want to observe
if kubectl rollout status deployment/"${API_DEPLOY}" \
    -n "${ANTHRA_NS}" \
    --timeout=90s 2>&1; then
  echo ""
  echo "Rollout completed. Pod is running — but may have CVEs."
  ROLLOUT_STATUS="running"
else
  echo ""
  echo "Rollout did not complete cleanly. The pod may be in CrashLoopBackOff."
  ROLLOUT_STATUS="degraded"
fi

echo ""
echo "------------------------------------------------------------"
echo "Current pod state:"
kubectl get pods -n "${ANTHRA_NS}" \
  -l "app.kubernetes.io/name=portfolio-app-api" \
  --no-headers 2>/dev/null || \
kubectl get pods -n "${ANTHRA_NS}" \
  --no-headers 2>/dev/null | grep api | head -5

echo ""
echo "============================================================"
echo "BREAK COMPLETE"
echo ""
echo "Rollout status: ${ROLLOUT_STATUS}"
echo "Vulnerable image deployed: ${VULNERABLE_IMAGE}"
echo ""
if [[ "${ROLLOUT_STATUS}" == "degraded" ]]; then
  echo "AVAILABILITY IMPACT OBSERVED: The application is degraded."
  echo "This is a dual finding: CVE vulnerability + availability incident."
  echo "Both must be documented in the POA&M under SI-2."
  echo ""
fi
echo "Next steps:"
echo "  1. Run: trivy image ${VULNERABLE_IMAGE} --severity CRITICAL,HIGH"
echo "  2. Read detect.md for the L1 analyst workflow"
echo "  3. Run fix.sh when ready to remediate"
echo "============================================================"
