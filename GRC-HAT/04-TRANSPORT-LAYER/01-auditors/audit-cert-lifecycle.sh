#!/usr/bin/env bash
# audit-cert-lifecycle.sh — Certificate lifecycle and management audit
# NIST: IA-5 (authenticator management), SC-23 (session authenticity)
# Usage: ./audit-cert-lifecycle.sh [cert-file-or-dir]
#
# CSF 2.0: PR.DS-08 (Hardware/software integrity verified)
# CIS v8: 3.10 (Encrypt Sensitive Data in Transit)
# NIST: IA-5 (Authenticator Management)
#
set -euo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
PASS() { echo -e "${GREEN}[PASS]${NC} $*"; }
WARN() { echo -e "${YELLOW}[WARN]${NC} $*"; }
FAIL() { echo -e "${RED}[FAIL]${NC} $*"; }
INFO() { echo -e "${CYAN}[INFO]${NC} $*"; }

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
EVIDENCE_DIR="/tmp/jsa-evidence/cert-lifecycle-${TIMESTAMP}"
mkdir -p "$EVIDENCE_DIR"

CERT_PATH="${1:-}"

echo "======================================================"
echo " L4 Certificate Lifecycle Audit — IA-5 / SC-23"
echo " Evidence: ${EVIDENCE_DIR}"
echo " $(date)"
echo "======================================================"
echo ""

# ─── Helper: Check single cert file expiry ────────────────────────────────
check_cert_expiry() {
    local cert_file="$1"
    local label="${2:-$(basename "$cert_file")}"

    if ! openssl x509 -noout -dates -subject -in "$cert_file" 2>/dev/null; then
        WARN "Cannot parse: ${cert_file}"
        return
    fi

    local NOT_AFTER SUBJECT DAYS_LEFT EXPIRY_EPOCH NOW_EPOCH
    NOT_AFTER=$(openssl x509 -noout -enddate -in "$cert_file" 2>/dev/null | cut -d= -f2)
    SUBJECT=$(openssl x509 -noout -subject -in "$cert_file" 2>/dev/null | sed 's/subject=//')
    EXPIRY_EPOCH=$(date -d "$NOT_AFTER" +%s 2>/dev/null || echo 0)
    NOW_EPOCH=$(date +%s)
    DAYS_LEFT=$(( (EXPIRY_EPOCH - NOW_EPOCH) / 86400 ))

    echo "${label}: subject=${SUBJECT} expires=${NOT_AFTER} days_left=${DAYS_LEFT}" >> "${EVIDENCE_DIR}/cert-inventory.txt"

    if [[ $DAYS_LEFT -lt 0 ]]; then
        FAIL "[${label}] EXPIRED ${DAYS_LEFT#-} days ago — IA-5 violation"
    elif [[ $DAYS_LEFT -lt 30 ]]; then
        WARN "[${label}] Expires in ${DAYS_LEFT} days — renew immediately"
    elif [[ $DAYS_LEFT -lt 60 ]]; then
        WARN "[${label}] Expires in ${DAYS_LEFT} days — schedule renewal"
    else
        PASS "[${label}] Valid for ${DAYS_LEFT} days"
    fi
}

# ─── 1. cert-manager (Kubernetes) ─────────────────────────────────────────
echo "── 1. cert-manager Certificate Resources ──────────────────────────"

if command -v kubectl &>/dev/null; then
    INFO "kubectl available — checking cert-manager resources"

    # List all Certificate resources
    CERT_LIST=$(kubectl get certificates --all-namespaces 2>/dev/null || true)
    echo "$CERT_LIST" > "${EVIDENCE_DIR}/k8s-certificates.txt"

    if [[ -z "$CERT_LIST" ]] || [[ "$CERT_LIST" == "No resources found"* ]]; then
        WARN "No cert-manager Certificate resources found"
        INFO "Is cert-manager installed? Check: kubectl get pods -n cert-manager"
    else
        echo "$CERT_LIST"
        echo ""

        # Check for NOT READY certs
        NOT_READY=$(echo "$CERT_LIST" | awk 'NR>1 && $4 != "True" {print $0}' || true)
        if [[ -n "$NOT_READY" ]]; then
            FAIL "Certificates NOT READY (IA-5 violation):"
            echo "$NOT_READY"
        fi

        # Check expiring within 30 days
        INFO "Checking certificate expiry windows..."
        while IFS= read -r line; do
            NAMESPACE=$(echo "$line" | awk '{print $1}')
            CERT_NAME=$(echo "$line" | awk '{print $2}')
            if [[ "$NAMESPACE" == "NAMESPACE" ]]; then continue; fi

            RENEWAL=$(kubectl get certificate "$CERT_NAME" -n "$NAMESPACE" \
                -o jsonpath='{.status.renewalTime}' 2>/dev/null || echo "unknown")
            NOT_AFTER=$(kubectl get certificate "$CERT_NAME" -n "$NAMESPACE" \
                -o jsonpath='{.status.notAfter}' 2>/dev/null || echo "unknown")

            if [[ "$NOT_AFTER" != "unknown" ]] && [[ -n "$NOT_AFTER" ]]; then
                EXPIRY_EPOCH=$(date -d "$NOT_AFTER" +%s 2>/dev/null || echo 0)
                NOW_EPOCH=$(date +%s)
                DAYS_LEFT=$(( (EXPIRY_EPOCH - NOW_EPOCH) / 86400 ))
                if [[ $DAYS_LEFT -lt 0 ]]; then
                    FAIL "[${NAMESPACE}/${CERT_NAME}] EXPIRED — immediate action required"
                elif [[ $DAYS_LEFT -lt 30 ]]; then
                    WARN "[${NAMESPACE}/${CERT_NAME}] Expires in ${DAYS_LEFT} days"
                else
                    PASS "[${NAMESPACE}/${CERT_NAME}] Valid for ${DAYS_LEFT} days (renewal: ${RENEWAL})"
                fi
            fi
        done <<< "$CERT_LIST"
    fi

    echo ""

    # ── ClusterIssuer health ────────────────────────────────────────────
    echo "── 2. ClusterIssuer Health ─────────────────────────────────────────"
    ISSUERS=$(kubectl get clusterissuers 2>/dev/null || true)
    echo "$ISSUERS" > "${EVIDENCE_DIR}/clusterissuers.txt"

    if [[ -z "$ISSUERS" ]] || [[ "$ISSUERS" == "No resources found"* ]]; then
        WARN "No ClusterIssuers found — auto-renewal not configured"
        INFO "Deploy ClusterIssuer: see 03-templates/cert-manager/clusterissuer.yaml"
    else
        echo "$ISSUERS"
        NOT_READY_ISSUERS=$(echo "$ISSUERS" | awk 'NR>1 && $2 != "True" {print $0}' || true)
        if [[ -n "$NOT_READY_ISSUERS" ]]; then
            FAIL "ClusterIssuers NOT READY — IA-5 auto-renewal broken:"
            echo "$NOT_READY_ISSUERS"
        else
            PASS "All ClusterIssuers healthy"
        fi
    fi

    echo ""

    # ── Auto-renewal status ─────────────────────────────────────────────
    echo "── 3. Auto-Renewal Configuration ──────────────────────────────────"
    CERT_MANAGER_PODS=$(kubectl get pods -n cert-manager 2>/dev/null || true)
    echo "$CERT_MANAGER_PODS" > "${EVIDENCE_DIR}/cert-manager-pods.txt"

    if [[ -z "$CERT_MANAGER_PODS" ]] || [[ "$CERT_MANAGER_PODS" == "No resources found"* ]]; then
        FAIL "cert-manager pods not found in cert-manager namespace — IA-5 auto-renewal unavailable"
        INFO "Install: kubectl apply -f https://github.com/cert-manager/cert-manager/releases/latest/download/cert-manager.yaml"
    else
        RUNNING=$(echo "$CERT_MANAGER_PODS" | grep -c "Running" || true)
        NOT_RUNNING=$(echo "$CERT_MANAGER_PODS" | awk 'NR>1' | grep -cv "Running" || true)
        PASS "cert-manager pods running: ${RUNNING}"
        if [[ $NOT_RUNNING -gt 0 ]]; then
            WARN "${NOT_RUNNING} cert-manager pods not in Running state"
        fi
    fi

else
    WARN "kubectl not available — skipping Kubernetes cert-manager checks"
fi

echo ""

# ─── 4. Local Certificate Files ────────────────────────────────────────────
echo "── 4. Local Certificate File Audit ────────────────────────────────"

if ! command -v openssl &>/dev/null; then
    FAIL "openssl not installed — cannot audit local certificates"
else
    SEARCH_PATH="${CERT_PATH:-/etc/ssl/certs}"
    if [[ -f "$SEARCH_PATH" ]]; then
        INFO "Checking single cert file: ${SEARCH_PATH}"
        check_cert_expiry "$SEARCH_PATH"
    elif [[ -d "$SEARCH_PATH" ]]; then
        INFO "Scanning directory: ${SEARCH_PATH}"
        CERT_COUNT=0
        while IFS= read -r -d '' cert_file; do
            check_cert_expiry "$cert_file"
            (( CERT_COUNT++ )) || true
        done < <(find "$SEARCH_PATH" -maxdepth 2 -name "*.crt" -o -name "*.pem" 2>/dev/null | head -50 | tr '\n' '\0' || true)

        if [[ $CERT_COUNT -eq 0 ]]; then
            INFO "No .crt or .pem files found in ${SEARCH_PATH}"
        else
            PASS "Scanned ${CERT_COUNT} certificate files"
        fi
    else
        INFO "No cert path specified and /etc/ssl/certs not found — pass cert file or dir as argument"
        INFO "Usage: $0 /path/to/cert.crt"
    fi
fi

echo ""

# ─── Evidence Summary ──────────────────────────────────────────────────────
echo "======================================================"
echo " Evidence saved to: ${EVIDENCE_DIR}"
ls -1 "$EVIDENCE_DIR" 2>/dev/null || true
echo "======================================================"
