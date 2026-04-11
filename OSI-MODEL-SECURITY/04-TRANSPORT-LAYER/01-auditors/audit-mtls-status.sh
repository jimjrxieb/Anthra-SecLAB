#!/usr/bin/env bash
# audit-mtls-status.sh — Mutual TLS enforcement audit
# NIST: SC-8 (transmission confidentiality), SC-23 (session authenticity)
# Usage: ./audit-mtls-status.sh [namespace]
set -euo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
PASS() { echo -e "${GREEN}[PASS]${NC} $*"; }
WARN() { echo -e "${YELLOW}[WARN]${NC} $*"; }
FAIL() { echo -e "${RED}[FAIL]${NC} $*"; }
INFO() { echo -e "${CYAN}[INFO]${NC} $*"; }
GAP()  { echo -e "${RED}[GAP]${NC} $*"; }

NAMESPACE="${1:-default}"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
EVIDENCE_DIR="/tmp/jsa-evidence/mtls-audit-${TIMESTAMP}"
mkdir -p "$EVIDENCE_DIR"

echo "======================================================"
echo " L4 mTLS Status Audit — SC-8 / SC-23"
echo " Namespace: ${NAMESPACE}"
echo " Evidence: ${EVIDENCE_DIR}"
echo " $(date)"
echo "======================================================"
echo ""

if ! command -v kubectl &>/dev/null; then
    WARN "kubectl not available — skipping Kubernetes mTLS checks"
    INFO "For non-Kubernetes mTLS, check nginx/HAProxy mutual TLS config manually"
    echo ""
    GAP "mTLS status: UNKNOWN — install kubectl for automated audit"
    exit 0
fi

# ─── 1. Detect service mesh ───────────────────────────────────────────────
echo "── 1. Service Mesh Detection ────────────────────────────────────────"

MESH_DETECTED=""

# Check Istio
ISTIO_NS=$(kubectl get namespace istio-system 2>/dev/null | grep -v NAME || true)
if [[ -n "$ISTIO_NS" ]]; then
    MESH_DETECTED="istio"
    PASS "Istio detected (istio-system namespace found)"
    ISTIO_PODS=$(kubectl get pods -n istio-system 2>/dev/null || true)
    echo "$ISTIO_PODS" > "${EVIDENCE_DIR}/istio-pods.txt"
    INFO "Istio pods:"
    echo "$ISTIO_PODS" | head -10
fi

# Check Linkerd
LINKERD_NS=$(kubectl get namespace linkerd 2>/dev/null | grep -v NAME || true)
if [[ -n "$LINKERD_NS" ]]; then
    if [[ -n "$MESH_DETECTED" ]]; then
        WARN "Both Istio and Linkerd detected — review dual-mesh configuration"
    else
        MESH_DETECTED="linkerd"
        PASS "Linkerd detected (linkerd namespace found)"
    fi
    LINKERD_PODS=$(kubectl get pods -n linkerd 2>/dev/null || true)
    echo "$LINKERD_PODS" > "${EVIDENCE_DIR}/linkerd-pods.txt"
fi

# Check for Envoy sidecars as proxy indicator
ENVOY_COUNT=$(kubectl get pods --all-namespaces 2>/dev/null | grep -c "istio-proxy\|envoy" || true)
if [[ $ENVOY_COUNT -gt 0 ]]; then
    INFO "Envoy sidecar proxies detected in ${ENVOY_COUNT} pods"
fi

if [[ -z "$MESH_DETECTED" ]]; then
    GAP "No service mesh detected (Istio or Linkerd)"
    echo ""
    echo "  REMEDIATION OPTIONS:"
    echo "  1. Istio (recommended for enterprise mTLS + policy):"
    echo "     istioctl install --set profile=default"
    echo "     kubectl label namespace default istio-injection=enabled"
    echo ""
    echo "  2. Linkerd (simpler, lower overhead):"
    echo "     linkerd install | kubectl apply -f -"
    echo "     kubectl annotate namespace default linkerd.io/inject=enabled"
    echo ""
    echo "  3. cert-manager mTLS (without full service mesh):"
    echo "     Deploy mutual TLS at ingress level using Certificate resources"
    echo "     See: 03-templates/cert-manager/certificate.yaml"
    echo ""
    INFO "Without mTLS, east-west traffic between services is unencrypted (SC-8 gap)"
    exit 0
fi

echo ""

# ─── 2. Istio PeerAuthentication ──────────────────────────────────────────
if [[ "$MESH_DETECTED" == "istio" ]]; then
    echo "── 2. PeerAuthentication (Istio mTLS Policy) ───────────────────────"

    PA_ALL=$(kubectl get peerauthentication --all-namespaces 2>/dev/null || true)
    echo "$PA_ALL" > "${EVIDENCE_DIR}/peerauthentication.txt"

    if [[ -z "$PA_ALL" ]] || [[ "$PA_ALL" == "No resources found"* ]]; then
        FAIL "No PeerAuthentication policies found"
        INFO "Without PeerAuthentication, mTLS is PERMISSIVE (accepts plaintext)"
        INFO "Create STRICT policy:"
        cat << 'EOF'
  kubectl apply -f - <<POLICY
  apiVersion: security.istio.io/v1beta1
  kind: PeerAuthentication
  metadata:
    name: default
    namespace: istio-system
  spec:
    mtls:
      mode: STRICT
  POLICY
EOF
    else
        echo "$PA_ALL"
        echo ""

        # Check for STRICT mode policies
        PA_STRICT=$(echo "$PA_ALL" | grep -i "STRICT" | wc -l || true)
        PA_PERMISSIVE=$(echo "$PA_ALL" | grep -i "PERMISSIVE" | wc -l || true)
        PA_DISABLE=$(echo "$PA_ALL" | grep -i "DISABLE" | wc -l || true)

        if [[ $PA_STRICT -gt 0 ]]; then
            PASS "STRICT mTLS policies found: ${PA_STRICT}"
        fi
        if [[ $PA_PERMISSIVE -gt 0 ]]; then
            WARN "PERMISSIVE mTLS policies found: ${PA_PERMISSIVE} — allows plaintext, SC-8 gap"
        fi
        if [[ $PA_DISABLE -gt 0 ]]; then
            FAIL "mTLS DISABLED policies found: ${PA_DISABLE} — SC-8 violation"
        fi
    fi

    echo ""

    # ── Check namespace-level policy ──────────────────────────────────
    echo "── 3. Namespace mTLS Coverage: ${NAMESPACE} ────────────────────────"

    NS_PA=$(kubectl get peerauthentication -n "$NAMESPACE" 2>/dev/null || true)
    MESH_PA=$(kubectl get peerauthentication -n istio-system 2>/dev/null || true)

    if echo "$NS_PA $MESH_PA" | grep -qi "STRICT"; then
        PASS "STRICT mTLS enforcement found for namespace ${NAMESPACE}"
    elif echo "$NS_PA $MESH_PA" | grep -qi "PERMISSIVE"; then
        WARN "mTLS is PERMISSIVE in namespace ${NAMESPACE} — plaintext allowed"
    else
        WARN "No explicit PeerAuthentication for namespace ${NAMESPACE} — inheriting mesh default"
        INFO "Verify mesh-wide default: kubectl get peerauthentication -n istio-system"
    fi

    echo ""

    # ── Check sidecar injection status ────────────────────────────────
    echo "── 4. Sidecar Injection Status ─────────────────────────────────────"

    NS_LABEL=$(kubectl get namespace "$NAMESPACE" -o jsonpath='{.metadata.labels.istio-injection}' 2>/dev/null || echo "not-set")
    if [[ "$NS_LABEL" == "enabled" ]]; then
        PASS "Sidecar injection enabled on namespace: ${NAMESPACE}"
    else
        WARN "Sidecar injection label not set on namespace ${NAMESPACE}"
        INFO "Enable: kubectl label namespace ${NAMESPACE} istio-injection=enabled"
    fi

    PODS_WITHOUT_SIDECAR=$(kubectl get pods -n "$NAMESPACE" 2>/dev/null \
        | awk 'NR>1 {split($2,a,"/"); if (a[1] < 2) print $1}' || true)
    if [[ -n "$PODS_WITHOUT_SIDECAR" ]]; then
        WARN "Pods potentially missing Envoy sidecar (single container):"
        echo "$PODS_WITHOUT_SIDECAR" | head -10
        INFO "Restart pods to inject sidecar: kubectl rollout restart deployment -n ${NAMESPACE}"
    fi

    echo ""

    # Save full PeerAuthentication details
    kubectl get peerauthentication --all-namespaces -o yaml 2>/dev/null > "${EVIDENCE_DIR}/peerauthentication-full.yaml" || true

fi

# ─── 3. Linkerd mesh check ────────────────────────────────────────────────
if [[ "$MESH_DETECTED" == "linkerd" ]]; then
    echo "── 2. Linkerd mTLS Status ──────────────────────────────────────────"

    # Check meshed pods
    MESHED=$(kubectl get pods -n "$NAMESPACE" -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.metadata.annotations.linkerd\.io/proxy-version}{"\n"}{end}' 2>/dev/null || true)
    echo "$MESHED" > "${EVIDENCE_DIR}/linkerd-meshed-pods.txt"

    MESHED_COUNT=$(echo "$MESHED" | grep -v "^$" | grep -v $'\t$' | wc -l || true)
    TOTAL_PODS=$(kubectl get pods -n "$NAMESPACE" --no-headers 2>/dev/null | wc -l || true)

    if [[ $MESHED_COUNT -eq 0 ]]; then
        FAIL "No meshed pods found in namespace ${NAMESPACE} — mTLS not active"
        INFO "Annotate namespace: kubectl annotate namespace ${NAMESPACE} linkerd.io/inject=enabled"
    elif [[ $MESHED_COUNT -lt $TOTAL_PODS ]]; then
        WARN "Only ${MESHED_COUNT}/${TOTAL_PODS} pods meshed in ${NAMESPACE} — partial mTLS coverage"
    else
        PASS "All ${MESHED_COUNT} pods meshed in ${NAMESPACE} — mTLS active"
    fi

    echo ""

    # Check Linkerd identity component
    LINKERD_IDENTITY=$(kubectl get pods -n linkerd -l linkerd.io/control-plane-component=identity 2>/dev/null || true)
    echo "$LINKERD_IDENTITY" > "${EVIDENCE_DIR}/linkerd-identity.txt"
    if echo "$LINKERD_IDENTITY" | grep -q "Running"; then
        PASS "Linkerd identity (cert issuer) running"
    else
        FAIL "Linkerd identity component not running — mTLS cert issuance broken"
    fi
fi

echo ""

# ─── Evidence Summary ──────────────────────────────────────────────────────
echo "======================================================"
echo " Evidence saved to: ${EVIDENCE_DIR}"
ls -1 "$EVIDENCE_DIR"
echo "======================================================"
