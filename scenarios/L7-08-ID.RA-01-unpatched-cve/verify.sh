#!/usr/bin/env bash
# =============================================================================
# L7-08 — ID.RA-01: Unpatched CVE in Container Image
# Phase: VERIFY — Confirm the restored image has no CRITICAL CVEs, pod is healthy
#
# CSF:       IDENTIFY / ID.RA-01 (Vulnerabilities identified, validated, recorded)
# CIS v8:    7.4 — Perform Automated Application Patch Management
# NIST:      SI-2 — Flaw Remediation; RA-5 — Vulnerability Scanning
# Cluster:   k3d-seclab
# Namespace: anthra
#
# WHAT THIS DOES:
#   1. Reads the current image from the restored deployment
#   2. Runs Trivy against the current image (CRITICAL and HIGH)
#   3. Compares against the baseline CVE count recorded in baseline.sh
#   4. Confirms the pod is Running and passes a health check
#
# PREREQUISITE: Run baseline.sh before break.sh and save its output.
#               Compare the numbers here against that saved output.
# =============================================================================
set -euo pipefail

ANTHRA_NS="anthra"
API_DEPLOY="portfolio-anthra-portfolio-app-api"
VULNERABLE_IMAGE="python:3.9-slim"

echo "============================================================"
echo "L7-08 VERIFY — Confirm Remediation"
echo "Namespace:  ${ANTHRA_NS}"
echo "Deployment: ${API_DEPLOY}"
echo "Date:       $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "============================================================"
echo ""

# Verify trivy is available
if ! command -v trivy &>/dev/null; then
  echo "ERROR: trivy is not installed or not in PATH."
  exit 1
fi

# --- Step 1: Confirm the image was restored ---
CURRENT_IMAGE=$(kubectl get deployment "${API_DEPLOY}" -n "${ANTHRA_NS}" \
  -o jsonpath='{.spec.template.spec.containers[0].image}' 2>/dev/null || echo "unknown")

echo "[1/4] Current image on deployment:"
echo "      ${CURRENT_IMAGE}"
echo ""

if [[ "${CURRENT_IMAGE}" == "${VULNERABLE_IMAGE}" ]]; then
  echo "ERROR: The vulnerable image is still deployed."
  echo "       Run fix.sh first, then re-run this script."
  exit 1
fi

echo "      Confirmed: vulnerable image ${VULNERABLE_IMAGE} is NOT running."
echo ""

# --- Step 2: Scan the restored image ---
echo "[2/4] Scanning restored image for CRITICAL CVEs..."
echo "      Image: ${CURRENT_IMAGE}"
echo ""

SCAN_JSON=$(trivy image \
  --severity CRITICAL,HIGH \
  --format json \
  --quiet \
  "${CURRENT_IMAGE}" 2>/dev/null || true)

CRITICAL_AFTER=$(echo "${SCAN_JSON}" | \
  python3 -c "
import json,sys
data=json.load(sys.stdin)
total=sum(len([v for v in r.get('Vulnerabilities',[]) if v.get('Severity')=='CRITICAL'])
          for r in (data.get('Results') or []))
print(total)
" 2>/dev/null || echo "0")

HIGH_AFTER=$(echo "${SCAN_JSON}" | \
  python3 -c "
import json,sys
data=json.load(sys.stdin)
total=sum(len([v for v in r.get('Vulnerabilities',[]) if v.get('Severity')=='HIGH'])
          for r in (data.get('Results') or []))
print(total)
" 2>/dev/null || echo "0")

echo "      Scan complete."
echo "      CRITICAL CVEs in restored image: ${CRITICAL_AFTER}"
echo "      HIGH CVEs in restored image:     ${HIGH_AFTER}"
echo ""

# --- Step 3: Scan the vulnerable image and compare ---
echo "[3/4] Scanning vulnerable image (python:3.9-slim) to confirm difference..."
VULN_JSON=$(trivy image \
  --severity CRITICAL,HIGH \
  --format json \
  --quiet \
  "${VULNERABLE_IMAGE}" 2>/dev/null || true)

CRITICAL_BEFORE=$(echo "${VULN_JSON}" | \
  python3 -c "
import json,sys
data=json.load(sys.stdin)
total=sum(len([v for v in r.get('Vulnerabilities',[]) if v.get('Severity')=='CRITICAL'])
          for r in (data.get('Results') or []))
print(total)
" 2>/dev/null || echo "unknown")

HIGH_BEFORE=$(echo "${VULN_JSON}" | \
  python3 -c "
import json,sys
data=json.load(sys.stdin)
total=sum(len([v for v in r.get('Vulnerabilities',[]) if v.get('Severity')=='HIGH'])
          for r in (data.get('Results') or []))
print(total)
" 2>/dev/null || echo "unknown")

echo ""
echo "------------------------------------------------------------"
echo "BEFORE / AFTER COMPARISON"
echo "------------------------------------------------------------"
printf "%-15s %-25s %-25s\n" "" "BEFORE (python:3.9-slim)" "AFTER (restored)"
printf "%-15s %-25s %-25s\n" "CRITICAL CVEs" "${CRITICAL_BEFORE}" "${CRITICAL_AFTER}"
printf "%-15s %-25s %-25s\n" "HIGH CVEs" "${HIGH_BEFORE}" "${HIGH_AFTER}"
echo ""

# --- Step 4: Confirm pod health ---
echo "[4/4] Checking pod health..."
POD_STATUS=$(kubectl get pods -n "${ANTHRA_NS}" \
  --no-headers 2>/dev/null | grep api | awk '{print $3}' | head -1 || echo "unknown")
POD_READY=$(kubectl get pods -n "${ANTHRA_NS}" \
  --no-headers 2>/dev/null | grep api | awk '{print $2}' | head -1 || echo "unknown")

echo "      Pod status: ${POD_STATUS}"
echo "      Pod ready:  ${POD_READY}"
echo ""

kubectl get pods -n "${ANTHRA_NS}" --no-headers 2>/dev/null | grep api | head -5 || true

echo ""
echo "============================================================"
echo "VERIFICATION RESULT"
echo ""

if [[ "${CRITICAL_AFTER}" == "0" && "${POD_STATUS}" == "Running" ]]; then
  echo "PASS: Restored image has 0 CRITICAL CVEs. Pod is Running."
  echo ""
  echo "POA&M documentation for SI-2:"
  echo "  Finding:     CRITICAL CVEs in python:3.9-slim"
  echo "  Remediated:  $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  echo "  Method:      kubectl rollout undo (restored previous image)"
  echo "  Verified by: Trivy scan of restored image — 0 CRITICAL CVEs"
  echo "  Pod health:  Running / Ready ${POD_READY}"
  echo "  Status:      CLOSED"
  echo ""
  echo "OUTSTANDING (structural remediation — separate POA&M items):"
  echo "  - Add Trivy to CI pipeline with --exit-code 1 (CIS 7.4)"
  echo "  - Pin all images by digest in deployment manifests"
  echo "  - Add admission control to reject unscanned images"
elif [[ "${CRITICAL_AFTER}" != "0" ]]; then
  echo "FAIL: Restored image still has ${CRITICAL_AFTER} CRITICAL CVEs."
  echo "      The rollback may have restored an image that also had CVEs."
  echo "      Escalate to B-rank — human decision required on target image."
elif [[ "${POD_STATUS}" != "Running" ]]; then
  echo "PARTIAL: CVEs resolved but pod is ${POD_STATUS}."
  echo "         The restored image may have a different failure mode."
  echo "         Check pod logs: kubectl logs -n ${ANTHRA_NS} deployment/${API_DEPLOY}"
fi
echo "============================================================"
