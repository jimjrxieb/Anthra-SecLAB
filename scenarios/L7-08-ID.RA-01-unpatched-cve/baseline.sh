#!/usr/bin/env bash
# =============================================================================
# L7-08 — ID.RA-01: Unpatched CVE in Container Image
# Phase: BASELINE — Scan production images and record CVE counts before break
#
# CSF:       IDENTIFY / ID.RA-01 (Vulnerabilities identified, validated, recorded)
# CIS v8:    7.4 — Perform Automated Application Patch Management
# NIST:      SI-2 — Flaw Remediation; RA-5 — Vulnerability Scanning
# Cluster:   k3d-seclab
# Namespace: anthra
#
# WHAT THIS DOES:
#   Reads the current image tags from all anthra deployments, runs Trivy against
#   each, and prints a summary of CRITICAL and HIGH CVE counts. This establishes
#   the pre-break baseline. Run this before break.sh, save the output.
#
# PREREQUISITE: trivy must be installed locally.
#   Install: https://aquasecurity.github.io/trivy/latest/getting-started/installation/
# =============================================================================
set -euo pipefail

ANTHRA_NS="anthra"

echo "============================================================"
echo "L7-08 BASELINE — Container Image CVE Scan"
echo "Namespace: ${ANTHRA_NS}"
echo "Date:      $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "============================================================"
echo ""

# Verify trivy is available
if ! command -v trivy &>/dev/null; then
  echo "ERROR: trivy is not installed or not in PATH."
  echo "       Install: https://aquasecurity.github.io/trivy/latest/getting-started/installation/"
  exit 1
fi

# Collect all unique images currently running in the anthra namespace
echo "Collecting images from anthra deployments..."
IMAGES=$(kubectl get deployments -n "${ANTHRA_NS}" \
  -o jsonpath='{range .items[*]}{range .spec.template.spec.containers[*]}{.image}{"\n"}{end}{end}' \
  2>/dev/null | sort -u)

if [[ -z "${IMAGES}" ]]; then
  echo "ERROR: No deployments found in namespace ${ANTHRA_NS}."
  echo "       Verify the anthra namespace is deployed: kubectl get deployments -n ${ANTHRA_NS}"
  exit 1
fi

echo ""
echo "Images found:"
while IFS= read -r img; do
  echo "  - ${img}"
done <<< "${IMAGES}"
echo ""

# Scan each image and record CRITICAL/HIGH counts
echo "------------------------------------------------------------"
echo "SCAN RESULTS (CRITICAL and HIGH CVEs only)"
echo "------------------------------------------------------------"
printf "%-60s %10s %10s\n" "IMAGE" "CRITICAL" "HIGH"
printf "%-60s %10s %10s\n" "-----" "--------" "----"

TOTAL_CRITICAL=0
TOTAL_HIGH=0

while IFS= read -r img; do
  # Run trivy in quiet mode, table output, filter to CRITICAL/HIGH
  SCAN_OUT=$(trivy image \
    --severity CRITICAL,HIGH \
    --format json \
    --quiet \
    "${img}" 2>/dev/null || true)

  CRITICAL_COUNT=$(echo "${SCAN_OUT}" | \
    python3 -c "
import json,sys
data=json.load(sys.stdin)
total=sum(len([v for v in r.get('Vulnerabilities',[]) if v.get('Severity')=='CRITICAL'])
          for r in (data.get('Results') or []))
print(total)
" 2>/dev/null || echo "0")

  HIGH_COUNT=$(echo "${SCAN_OUT}" | \
    python3 -c "
import json,sys
data=json.load(sys.stdin)
total=sum(len([v for v in r.get('Vulnerabilities',[]) if v.get('Severity')=='HIGH'])
          for r in (data.get('Results') or []))
print(total)
" 2>/dev/null || echo "0")

  TOTAL_CRITICAL=$(( TOTAL_CRITICAL + CRITICAL_COUNT ))
  TOTAL_HIGH=$(( TOTAL_HIGH + HIGH_COUNT ))

  printf "%-60s %10s %10s\n" "${img:0:59}" "${CRITICAL_COUNT}" "${HIGH_COUNT}"
done <<< "${IMAGES}"

echo ""
printf "%-60s %10s %10s\n" "TOTAL" "${TOTAL_CRITICAL}" "${TOTAL_HIGH}"
echo ""
echo "============================================================"
echo "BASELINE RECORDED"
echo ""
echo "Save this output before running break.sh."
echo "You will compare these numbers in verify.sh after remediation."
echo ""
echo "Expected: production image should show 0 CRITICAL CVEs."
echo "If CRITICAL > 0 at baseline, the environment already has a finding."
echo "Document it in the POA&M before proceeding."
echo "============================================================"
