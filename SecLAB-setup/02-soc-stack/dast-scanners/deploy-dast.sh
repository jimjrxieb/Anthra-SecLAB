#!/usr/bin/env bash
# CSF 2.0: ID.RA-01 (Vulnerabilities identified), PR.AC-05 (Network integrity protected)
# CIS v8: 16.12 (Implement Code-Level Security Checks), 12.2 (Secure Network Architecture)
# NIST: RA-5 (Vulnerability Scanning), SC-7 (Boundary Protection)
#
# deploy-dast.sh — Deploy ZAP and Nuclei DAST scanners in the SecLAB environment.
#
# What this does:
#   1. Applies NetworkPolicy allowing scanner pods to reach anthra services
#   2. Deploys ZAP baseline scan job
#   3. Deploys Nuclei template scan job
#   4. Waits for both to complete
#   5. Copies results to evidence directory
#   6. Prints summary
#
# Scanners run inside the cluster as K8s Jobs. They hit ClusterIP services
# directly, appear in Falco (visible in Splunk gp_security), and are subject
# to NetworkPolicy enforcement.
#
# Usage:
#   bash deploy-dast.sh
#   bash deploy-dast.sh --target <service-name> --port <port>
#
# Prerequisites:
#   kubectl configured against the SecLAB cluster
#   anthra namespace exists (created by SecLAB setup)
#   SOC stack deployed (deploy-stack.sh run first — Falco must be running)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONSULTING_DAST="${SCRIPT_DIR}/../../../../../../GP-CONSULTING/09-OSI-MODEL-SECURITY/07-APPLICATION-LAYER/03-templates/dast"
EVIDENCE_DIR="${SCRIPT_DIR}/../../../../evidence/dast"
NAMESPACE="anthra"

# Defaults
TARGET_SERVICE="portfolio-anthra-portfolio-app-api"
TARGET_PORT="8000"

# ---- Argument parsing ----
while [[ $# -gt 0 ]]; do
    case "$1" in
        --target) TARGET_SERVICE="$2"; shift 2 ;;
        --port)   TARGET_PORT="$2"; shift 2 ;;
        --help|-h)
            echo "Usage: $0 [--target <service-name>] [--port <port>]"
            exit 0
            ;;
        *) echo "Unknown argument: $1"; exit 1 ;;
    esac
done

echo "============================================"
echo "SecLAB DAST Scanner Deployment"
echo "  Target:    ${TARGET_SERVICE}:${TARGET_PORT}"
echo "  Namespace: ${NAMESPACE}"
echo "============================================"
echo ""

# ---- Prerequisites ----
if ! kubectl cluster-info &>/dev/null; then
    echo "ERROR: No cluster connection. Run SecLAB setup first."
    exit 1
fi

if ! kubectl get namespace "${NAMESPACE}" &>/dev/null; then
    echo "ERROR: Namespace '${NAMESPACE}' not found. Deploy the target application first."
    exit 1
fi

if ! command -v envsubst &>/dev/null; then
    echo "ERROR: envsubst not found. Install with: apt-get install gettext"
    exit 1
fi

mkdir -p "${EVIDENCE_DIR}"

# ---- Step 1: NetworkPolicy ----
echo "--- [1/5] Applying DAST NetworkPolicy ---"
kubectl apply -f "${SCRIPT_DIR}/scanner-networkpolicy.yaml"
echo "  NetworkPolicy allow-dast-to-portfolio applied"
echo "  Scanner pods (seclab-tool: dast) can now reach port ${TARGET_PORT} on API pods"
echo ""

# ---- Step 2: Clean up any previous jobs ----
echo "--- [2/5] Cleaning up previous scan jobs ---"
for job in zap-baseline-scan nuclei-scan; do
    if kubectl get job "${job}" -n "${NAMESPACE}" &>/dev/null; then
        echo "  Deleting existing job/${job}..."
        kubectl delete job "${job}" -n "${NAMESPACE}" --wait=true
    fi
done
echo "  Clean"
echo ""

# ---- Step 3: Deploy scanner jobs ----
echo "--- [3/5] Deploying ZAP and Nuclei jobs ---"
export TARGET_SERVICE TARGET_PORT

envsubst '${TARGET_SERVICE} ${TARGET_PORT}' < "${CONSULTING_DAST}/zap-job.yaml" \
    | kubectl apply -f -
echo "  job/zap-baseline-scan created"

envsubst '${TARGET_SERVICE} ${TARGET_PORT}' < "${CONSULTING_DAST}/nuclei-job.yaml" \
    | kubectl apply -f -
echo "  job/nuclei-scan created"
echo ""

# ---- Step 4: Wait for completion ----
echo "--- [4/5] Waiting for scans to complete (timeout: 10 minutes each) ---"

wait_for_job() {
    local job_name="$1"
    echo "  Waiting for ${job_name}..."
    if kubectl wait --for=condition=complete "job/${job_name}" -n "${NAMESPACE}" --timeout=600s; then
        echo "  ${job_name}: complete"
        return 0
    else
        echo "  WARNING: ${job_name} did not complete within timeout."
        echo "  Last logs:"
        kubectl logs "job/${job_name}" -n "${NAMESPACE}" --tail=20 2>/dev/null || true
        return 1
    fi
}

ZAP_OK=0
NUCLEI_OK=0
wait_for_job "zap-baseline-scan" && ZAP_OK=1 || true
wait_for_job "nuclei-scan"       && NUCLEI_OK=1 || true
echo ""

# ---- Step 5: Copy results ----
echo "--- [5/5] Copying results to evidence directory ---"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)

copy_report() {
    local pod_label="$1"
    local src_path="$2"
    local dest_name="$3"

    local pod
    pod=$(kubectl get pods -n "${NAMESPACE}" \
        -l "app.kubernetes.io/name=${pod_label}" \
        --field-selector=status.phase=Succeeded \
        -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)

    if [[ -z "${pod}" ]]; then
        echo "  WARNING: No completed pod found for label ${pod_label}"
        return 1
    fi

    local dest="${EVIDENCE_DIR}/${TIMESTAMP}-${dest_name}"
    kubectl cp "${NAMESPACE}/${pod}:${src_path}" "${dest}" 2>/dev/null \
        && echo "  Saved: ${dest}" \
        || echo "  WARNING: Could not copy ${src_path}"
}

[[ "${ZAP_OK}" -eq 1 ]] && {
    copy_report "zap-scanner" "/tmp/zap-report.json" "zap-report.json"
    copy_report "zap-scanner" "/tmp/zap-report.html" "zap-report.html" || true
}

[[ "${NUCLEI_OK}" -eq 1 ]] && {
    copy_report "nuclei-scanner" "/tmp/nuclei-results.jsonl" "nuclei-results.jsonl"
}

echo ""

# ---- Summary ----
echo "============================================"
echo "DAST Scan Summary"
echo "============================================"
echo "  ZAP scan:    $( [[ "${ZAP_OK}" -eq 1 ]] && echo 'COMPLETE' || echo 'FAILED/TIMEOUT')"
echo "  Nuclei scan: $( [[ "${NUCLEI_OK}" -eq 1 ]] && echo 'COMPLETE' || echo 'FAILED/TIMEOUT')"
echo ""
echo "  Evidence directory: ${EVIDENCE_DIR}/"
ls -lh "${EVIDENCE_DIR}/" 2>/dev/null || true
echo ""
echo "Next steps:"
echo "  1. Review reports in ${EVIDENCE_DIR}/"
echo "  2. Check Splunk → Search: index=gp_security sourcetype=falco"
echo "     Filter for scanner pod names to see Falco detections triggered by the scan"
echo "  3. ZAP alerts → map to OWASP Top 10 findings"
echo "  4. Nuclei findings → check http/exposures for credential/config leaks"
echo "  5. Map all findings to RA-5 evidence in 05-COMPLIANCE-READY"
echo ""
echo "To re-run:"
echo "  bash ${SCRIPT_DIR}/deploy-dast.sh"
echo "============================================"
