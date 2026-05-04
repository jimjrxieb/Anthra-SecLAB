#!/usr/bin/env bash
# fix-expired-cert.sh — Certificate renewal and rotation
# NIST: IA-5 (authenticator management), SC-23 (session authenticity)
# Usage: ./fix-expired-cert.sh [--method certmanager|manual|letsencrypt] [--cert-name <name>] [--namespace <ns>]
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
EVIDENCE_DIR="/tmp/jsa-evidence/fix-cert-${TIMESTAMP}"
mkdir -p "$EVIDENCE_DIR"

METHOD=""
CERT_NAME=""
NAMESPACE="default"
DOMAIN=""
OUTPUT_DIR="${EVIDENCE_DIR}/certs"
mkdir -p "$OUTPUT_DIR"

# ─── Parse arguments ──────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --method)    METHOD="$2"; shift 2 ;;
        --cert-name) CERT_NAME="$2"; shift 2 ;;
        --namespace) NAMESPACE="$2"; shift 2 ;;
        --domain)    DOMAIN="$2"; shift 2 ;;
        *) echo "Unknown argument: $1"; exit 1 ;;
    esac
done

echo "======================================================"
echo " L4 Certificate Renewal — IA-5 / SC-23"
echo " Evidence: ${EVIDENCE_DIR}"
echo " $(date)"
echo "======================================================"
echo ""

# ─── Auto-detect method if not specified ──────────────────────────────────
if [[ -z "$METHOD" ]]; then
    if command -v kubectl &>/dev/null && kubectl get certificates --all-namespaces &>/dev/null 2>&1; then
        METHOD="certmanager"
        INFO "Auto-detected: cert-manager (kubectl available, Certificate resources found)"
    elif command -v certbot &>/dev/null; then
        METHOD="letsencrypt"
        INFO "Auto-detected: certbot (Let's Encrypt)"
    elif command -v openssl &>/dev/null; then
        METHOD="manual"
        INFO "Auto-detected: manual (openssl only)"
    else
        FAIL "No certificate management tool found. Install cert-manager, certbot, or openssl."
        exit 1
    fi
fi

# ─── Method 1: cert-manager ───────────────────────────────────────────────
renew_certmanager() {
    if ! command -v kubectl &>/dev/null; then
        FAIL "kubectl not available — cert-manager method requires kubectl"
        exit 1
    fi

    if [[ -z "$CERT_NAME" ]]; then
        # List all certs and offer to renew expired/expiring ones
        INFO "No --cert-name specified. Checking all certificates..."
        kubectl get certificates --all-namespaces 2>/dev/null > "${EVIDENCE_DIR}/before-certs.txt" || true
        cat "${EVIDENCE_DIR}/before-certs.txt"

        WARN "Pass --cert-name to renew a specific certificate"
        INFO "Example: $0 --method certmanager --cert-name my-tls-cert --namespace production"

        # Auto-renew all not-ready certs
        NOT_READY=$(kubectl get certificates --all-namespaces 2>/dev/null \
            | awk 'NR>1 && $4 != "True" {print $1":"$2}' || true)

        if [[ -n "$NOT_READY" ]]; then
            WARN "Found certificates NOT READY — attempting renewal..."
            while IFS=: read -r NS CERT; do
                INFO "Renewing: ${NS}/${CERT}"
                # Trigger renewal by annotating
                kubectl annotate certificate "$CERT" -n "$NS" \
                    cert-manager.io/issue-temporary-certificate="true" \
                    --overwrite 2>/dev/null || true
                # Use cert-manager kubectl plugin if available
                kubectl cert-manager renew "$CERT" -n "$NS" 2>/dev/null \
                    && PASS "Renewal triggered: ${NS}/${CERT}" \
                    || WARN "kubectl cert-manager plugin not available — annotating to force renewal"

                # Force renewal by deleting the TLS secret (cert-manager will recreate)
                SECRET_NAME=$(kubectl get certificate "$CERT" -n "$NS" \
                    -o jsonpath='{.spec.secretName}' 2>/dev/null || echo "")
                if [[ -n "$SECRET_NAME" ]]; then
                    INFO "Backing up secret: ${SECRET_NAME}"
                    kubectl get secret "$SECRET_NAME" -n "$NS" -o yaml 2>/dev/null \
                        > "${EVIDENCE_DIR}/backup-secret-${SECRET_NAME}.yaml" || true
                    WARN "To force cert-manager to reissue, delete the TLS secret:"
                    INFO "  kubectl delete secret ${SECRET_NAME} -n ${NS}"
                    INFO "  cert-manager will automatically recreate it"
                fi
            done <<< "$NOT_READY"
        else
            PASS "All cert-manager certificates are READY"
        fi
        return
    fi

    # Renew specific cert
    INFO "Renewing certificate: ${CERT_NAME} in namespace: ${NAMESPACE}"

    # Save before state
    kubectl get certificate "$CERT_NAME" -n "$NAMESPACE" -o yaml 2>/dev/null \
        > "${EVIDENCE_DIR}/before-cert-${CERT_NAME}.yaml" || true
    kubectl describe certificate "$CERT_NAME" -n "$NAMESPACE" 2>/dev/null \
        > "${EVIDENCE_DIR}/before-describe-${CERT_NAME}.txt" || true

    # Get secret name
    SECRET_NAME=$(kubectl get certificate "$CERT_NAME" -n "$NAMESPACE" \
        -o jsonpath='{.spec.secretName}' 2>/dev/null || echo "")

    # Attempt renewal via cert-manager plugin
    if kubectl cert-manager 2>/dev/null | grep -q "renew"; then
        kubectl cert-manager renew "$CERT_NAME" -n "$NAMESPACE"
        PASS "Renewal triggered via cert-manager plugin"
    else
        # Force re-issuance by deleting the certificate's secret
        if [[ -n "$SECRET_NAME" ]]; then
            INFO "Backing up existing secret: ${SECRET_NAME}"
            kubectl get secret "$SECRET_NAME" -n "$NAMESPACE" -o yaml \
                > "${EVIDENCE_DIR}/backup-${SECRET_NAME}.yaml" 2>/dev/null || true
            kubectl delete secret "$SECRET_NAME" -n "$NAMESPACE" 2>/dev/null \
                && PASS "Secret deleted — cert-manager will reissue" \
                || WARN "Could not delete secret — manual intervention needed"
        else
            WARN "Could not find secretName for certificate ${CERT_NAME}"
        fi
    fi

    # Wait and verify
    INFO "Waiting up to 60s for cert renewal..."
    for i in $(seq 1 12); do
        sleep 5
        READY=$(kubectl get certificate "$CERT_NAME" -n "$NAMESPACE" \
            -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || echo "Unknown")
        if [[ "$READY" == "True" ]]; then
            PASS "Certificate renewed and READY"
            kubectl get certificate "$CERT_NAME" -n "$NAMESPACE" 2>/dev/null \
                > "${EVIDENCE_DIR}/after-cert-${CERT_NAME}.txt" || true
            break
        fi
        INFO "Waiting... (${i}/12)"
    done

    if [[ "$READY" != "True" ]]; then
        WARN "Certificate not yet READY after 60s — check cert-manager logs:"
        INFO "  kubectl logs -n cert-manager -l app=cert-manager | tail -20"
    fi
}

# ─── Method 2: Manual (openssl) ───────────────────────────────────────────
renew_manual() {
    if ! command -v openssl &>/dev/null; then
        FAIL "openssl not installed"
        exit 1
    fi

    local domain="${DOMAIN:-localhost}"
    local key_file="${OUTPUT_DIR}/${domain}.key"
    local csr_file="${OUTPUT_DIR}/${domain}.csr"
    local cert_file="${OUTPUT_DIR}/${domain}.crt"

    INFO "Generating new self-signed certificate for: ${domain}"
    INFO "WHY: Lab/internal use only. For production use cert-manager or Let's Encrypt."

    # Generate private key (RSA 4096 or EC P-256)
    if openssl ecparam -genkey -name prime256v1 -noout -out "${key_file}" 2>/dev/null; then
        PASS "EC P-256 private key generated: ${key_file}"
    else
        openssl genrsa -out "${key_file}" 4096 2>/dev/null
        PASS "RSA 4096 private key generated: ${key_file}"
    fi
    chmod 600 "${key_file}"

    # Generate CSR
    openssl req -new \
        -key "${key_file}" \
        -out "${csr_file}" \
        -subj "/CN=${domain}/O=SecLAB/C=US" \
        -addext "subjectAltName=DNS:${domain},DNS:*.${domain}" 2>/dev/null
    PASS "CSR generated: ${csr_file}"

    # Self-sign for 90 days (IA-5: short-lived certs reduce exposure window)
    openssl x509 -req \
        -in "${csr_file}" \
        -signkey "${key_file}" \
        -out "${cert_file}" \
        -days 90 \
        -sha256 \
        -extfile <(printf "subjectAltName=DNS:%s,DNS:*.%s\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth" "$domain" "$domain") 2>/dev/null
    PASS "Certificate generated (90 days, SHA-256): ${cert_file}"

    # Verify
    openssl x509 -noout -text -in "${cert_file}" > "${EVIDENCE_DIR}/cert-verify.txt" 2>/dev/null
    EXPIRY=$(openssl x509 -noout -enddate -in "${cert_file}" | cut -d= -f2)
    PASS "Certificate expires: ${EXPIRY}"

    INFO ""
    INFO "Deploy steps:"
    INFO "  nginx: ssl_certificate ${cert_file}; ssl_certificate_key ${key_file};"
    INFO "  k8s:   kubectl create secret tls my-tls --cert=${cert_file} --key=${key_file} -n ${NAMESPACE}"
}

# ─── Method 3: Let's Encrypt (certbot) ───────────────────────────────────
renew_letsencrypt() {
    if ! command -v certbot &>/dev/null; then
        FAIL "certbot not installed. Install: apt-get install certbot"
        exit 1
    fi

    if [[ -z "$DOMAIN" ]]; then
        INFO "Renewing all certificates with certbot..."
        certbot renew --force-renewal 2>&1 | tee "${EVIDENCE_DIR}/certbot-renew.log"
        PASS "certbot renew completed — check log for details"
    else
        INFO "Renewing Let's Encrypt certificate for: ${DOMAIN}"
        certbot renew --cert-name "$DOMAIN" --force-renewal 2>&1 \
            | tee "${EVIDENCE_DIR}/certbot-renew-${DOMAIN}.log"
        PASS "certbot renew for ${DOMAIN} completed"
    fi

    # Show cert status
    certbot certificates 2>/dev/null > "${EVIDENCE_DIR}/certbot-certs.txt" || true
    PASS "Certificate inventory saved to: ${EVIDENCE_DIR}/certbot-certs.txt"
}

# ─── Dispatch ─────────────────────────────────────────────────────────────
case "$METHOD" in
    certmanager) renew_certmanager ;;
    manual)      renew_manual ;;
    letsencrypt) renew_letsencrypt ;;
    *)
        FAIL "Unknown method: ${METHOD}"
        echo "Valid: certmanager, manual, letsencrypt"
        exit 1
        ;;
esac

echo ""
echo "======================================================"
echo " Evidence saved to: ${EVIDENCE_DIR}"
ls -R "$EVIDENCE_DIR"
echo "======================================================"
