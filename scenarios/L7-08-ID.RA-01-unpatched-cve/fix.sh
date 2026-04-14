#!/usr/bin/env bash
# =============================================================================
# L7-08 — ID.RA-01: Unpatched CVE in Container Image
# Phase: FIX — Rollback the API deployment to the last known-good image
#
# CSF:       IDENTIFY / ID.RA-01 (Vulnerabilities identified, validated, recorded)
# CIS v8:    7.4 — Perform Automated Application Patch Management
# NIST:      SI-2 — Flaw Remediation; RA-5 — Vulnerability Scanning
# Cluster:   k3d-seclab
# Namespace: anthra
#
# WHAT THIS DOES:
#   1. Rolls back the API deployment to the previous revision (the original image).
#   2. Waits for the rollout to complete.
#   3. Shows the proper long-term fix: pinning by digest in CI.
#
# NOTE: rollout undo restores the previous ReplicaSet. The original production
#       image is preserved in rollout history and is restored cleanly without
#       requiring knowledge of the exact image tag.
# =============================================================================
set -euo pipefail

ANTHRA_NS="anthra"
API_DEPLOY="portfolio-anthra-portfolio-app-api"

echo "============================================================"
echo "L7-08 FIX — Rollback API Deployment"
echo "Namespace:  ${ANTHRA_NS}"
echo "Deployment: ${API_DEPLOY}"
echo "============================================================"
echo ""

# Verify the deployment exists
if ! kubectl get deployment "${API_DEPLOY}" -n "${ANTHRA_NS}" &>/dev/null; then
  echo "ERROR: Deployment ${API_DEPLOY} not found in namespace ${ANTHRA_NS}."
  exit 1
fi

# Show current (broken) state before rollback
CURRENT_IMAGE=$(kubectl get deployment "${API_DEPLOY}" -n "${ANTHRA_NS}" \
  -o jsonpath='{.spec.template.spec.containers[0].image}' 2>/dev/null || echo "unknown")
echo "Current (vulnerable) image:"
echo "  ${CURRENT_IMAGE}"
echo ""

# Show rollout history so the analyst can see what they are rolling back to
echo "Rollout history:"
kubectl rollout history deployment/"${API_DEPLOY}" -n "${ANTHRA_NS}" 2>/dev/null || \
  echo "  (rollout history not available)"
echo ""

# Perform the rollback
echo "Executing rollback to previous revision..."
kubectl rollout undo deployment/"${API_DEPLOY}" -n "${ANTHRA_NS}"

echo ""
echo "Waiting for rollback to complete..."
kubectl rollout status deployment/"${API_DEPLOY}" \
  -n "${ANTHRA_NS}" \
  --timeout=120s

echo ""
RESTORED_IMAGE=$(kubectl get deployment "${API_DEPLOY}" -n "${ANTHRA_NS}" \
  -o jsonpath='{.spec.template.spec.containers[0].image}' 2>/dev/null || echo "unknown")

echo "------------------------------------------------------------"
echo "Rollback complete."
echo "Restored image: ${RESTORED_IMAGE}"
echo ""

# Check pod health after rollback
echo "Pod state after rollback:"
kubectl get pods -n "${ANTHRA_NS}" --no-headers 2>/dev/null | grep api | head -5 || \
  kubectl get pods -n "${ANTHRA_NS}" --no-headers 2>/dev/null | head -10

echo ""
echo "============================================================"
echo "ROLLBACK COMPLETE — IMMEDIATE REMEDIATION DONE"
echo ""
echo "This was the emergency fix. The application is restored."
echo "This is NOT the full remediation."
echo ""
echo "------------------------------------------------------------"
echo "PROPER LONG-TERM FIX: Pin images by digest in CI/CD"
echo "------------------------------------------------------------"
echo ""
echo "Step 1: Get the digest of the production image:"
echo "  crane digest <your-production-image-tag>"
echo "  # or: docker inspect --format='{{index .RepoDigests 0}}' <image>"
echo ""
echo "Step 2: Update the deployment manifest to use the digest:"
echo "  # Before (vulnerable — tag can drift silently):"
echo "  image: python:3.9-slim"
echo ""
echo "  # After (safe — immutable, auditable):"
echo "  image: python@sha256:<digest>"
echo ""
echo "Step 3: Add Trivy to CI before every image push:"
echo "  # In your GitHub Actions / GitLab CI pipeline:"
echo "  - name: Scan image for vulnerabilities"
echo "    run: |"
echo "      trivy image --severity CRITICAL,HIGH --exit-code 1 \\"
echo "        \${{ env.IMAGE }}:\${{ env.TAG }}"
echo "  # exit-code 1 means the pipeline fails if CRITICAL or HIGH CVEs are found"
echo ""
echo "Step 4: Re-scan running images on a schedule (RA-5 requires periodic scans):"
echo "  # Weekly CronJob in the cluster:"
echo "  # kubectl apply -f tools/image-scan-cronjob.yaml (see 01-APP-SEC package)"
echo ""
echo "------------------------------------------------------------"
echo "Run verify.sh to confirm the restored image has no CRITICAL CVEs."
echo "============================================================"
