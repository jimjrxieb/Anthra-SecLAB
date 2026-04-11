#!/usr/bin/env bash
# fix-cis-failures.sh — Remediate common kube-bench CIS Kubernetes benchmark failures
# NIST: CM-6 (configuration settings), CM-7 (least functionality), SI-7 (integrity)
# Usage: ./fix-cis-failures.sh [--dry-run] [--check <check-id>]
set -euo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'; NC='\033[0m'
PASS() { echo -e "${GREEN}[PASS]${NC} $*"; }
WARN() { echo -e "${YELLOW}[WARN]${NC} $*"; }
FAIL() { echo -e "${RED}[FAIL]${NC} $*"; }
INFO() { echo -e "       $*"; }
SECTION() { echo -e "\n${BLUE}═══ $* ═══${NC}"; }

DRY_RUN=false
TARGET_CHECK="${2:-all}"
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=true

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
EVIDENCE_DIR="/tmp/jsa-evidence/cis-failures-${TIMESTAMP}"
mkdir -p "$EVIDENCE_DIR"

echo "======================================================"
echo " CIS Kubernetes Benchmark Remediation — CM-6 / CM-7"
echo " Dry run: ${DRY_RUN}"
echo " Target: ${TARGET_CHECK}"
echo " Evidence: ${EVIDENCE_DIR}"
echo " $(date)"
echo "======================================================"
echo ""

FIXES_APPLIED=0
FIXES_SKIPPED=0

# ─── Helper Functions ─────────────────────────────────────────────────────────

apply_fix() {
    local CHECK_ID="$1"
    local DESCRIPTION="$2"
    local FIX_CMD="$3"

    echo ""
    echo "[$CHECK_ID] $DESCRIPTION"

    if $DRY_RUN; then
        WARN "DRY RUN — would run: $FIX_CMD"
        FIXES_SKIPPED=$((FIXES_SKIPPED + 1))
    else
        if eval "$FIX_CMD" 2>/dev/null; then
            PASS "Applied: $CHECK_ID"
            FIXES_APPLIED=$((FIXES_APPLIED + 1))
            echo "CHECK_ID=$CHECK_ID ACTION=applied TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$EVIDENCE_DIR/fixes-applied.txt"
        else
            WARN "Fix may need manual review: $CHECK_ID"
            FIXES_SKIPPED=$((FIXES_SKIPPED + 1))
        fi
    fi
}

# ─── 1.2.1 — API Server: Ensure anonymous auth is disabled ────────────────────
if [[ "$TARGET_CHECK" == "all" || "$TARGET_CHECK" == "1.2.1" ]]; then
    SECTION "CIS 1.2.1 — API Server: Disable anonymous authentication"

    # Check current state
    if kubectl get pod -n kube-system kube-apiserver-$(hostname) -o yaml 2>/dev/null | grep -q "anonymous-auth=false"; then
        PASS "anonymous-auth already disabled"
    else
        INFO "Checking API server manifest..."
        APISERVER_MANIFEST="/etc/kubernetes/manifests/kube-apiserver.yaml"
        if [[ -f "$APISERVER_MANIFEST" ]]; then
            INFO "Static pod manifest found: $APISERVER_MANIFEST"
            cp "$APISERVER_MANIFEST" "$EVIDENCE_DIR/kube-apiserver.yaml.before"

            if $DRY_RUN; then
                WARN "DRY RUN — would add --anonymous-auth=false to kube-apiserver.yaml"
            else
                # Add anonymous-auth=false if not already present
                if ! grep -q "anonymous-auth=false" "$APISERVER_MANIFEST"; then
                    sed -i '/- kube-apiserver/a \    - --anonymous-auth=false' "$APISERVER_MANIFEST"
                    PASS "Added --anonymous-auth=false to API server manifest"
                    FIXES_APPLIED=$((FIXES_APPLIED + 1))
                    cp "$APISERVER_MANIFEST" "$EVIDENCE_DIR/kube-apiserver.yaml.after"
                    diff "$EVIDENCE_DIR/kube-apiserver.yaml.before" "$EVIDENCE_DIR/kube-apiserver.yaml.after" > "$EVIDENCE_DIR/kube-apiserver.diff" 2>/dev/null || true
                else
                    PASS "anonymous-auth=false already in manifest"
                fi
            fi
        else
            WARN "API server manifest not found — may be managed cluster (EKS/AKS/GKE)"
            INFO "For managed clusters: use provider-specific security hardening"
            INFO "AKS: az aks update with --enable-aad-auth"
        fi
    fi
fi

# ─── 1.2.22 — API Server: Audit logging enabled ───────────────────────────────
if [[ "$TARGET_CHECK" == "all" || "$TARGET_CHECK" == "1.2.22" ]]; then
    SECTION "CIS 1.2.22 — API Server: Enable audit logging"

    # Create audit policy if it doesn't exist
    AUDIT_POLICY="/etc/kubernetes/audit-policy.yaml"
    if [[ ! -f "$AUDIT_POLICY" ]] && ! $DRY_RUN; then
        cat > "$AUDIT_POLICY" << 'EOF'
# Kubernetes Audit Policy — CIS 1.2.22 compliance
# NIST: AU-2 (event logging), AU-12 (audit generation)
apiVersion: audit.k8s.io/v1
kind: Policy
omitStages:
  - RequestReceived          # Reduce noise — log on Response only
rules:
  # Log all auth-related events at RequestResponse level
  - level: RequestResponse
    groups: [""]
    resources:
      - group: ""
        resources: ["secrets", "serviceaccounts", "configmaps"]
    verbs: ["create", "update", "delete", "patch"]

  # Log all RBAC changes
  - level: RequestResponse
    resources:
      - group: "rbac.authorization.k8s.io"
        resources: ["clusterroles", "clusterrolebindings", "roles", "rolebindings"]

  # Log pod exec (high risk — T1609)
  - level: Request
    resources:
      - group: ""
        resources: ["pods/exec", "pods/portforward", "pods/proxy"]

  # Log namespace changes
  - level: Metadata
    resources:
      - group: ""
        resources: ["namespaces"]

  # Log node changes
  - level: Metadata
    resources:
      - group: ""
        resources: ["nodes"]

  # Default: log metadata only (who, what, when — not request body)
  - level: Metadata
    omitStages:
      - RequestReceived
EOF
        PASS "Created audit policy: $AUDIT_POLICY"
    fi

    APISERVER_MANIFEST="/etc/kubernetes/manifests/kube-apiserver.yaml"
    if [[ -f "$APISERVER_MANIFEST" ]] && ! grep -q "audit-log-path" "$APISERVER_MANIFEST"; then
        if $DRY_RUN; then
            WARN "DRY RUN — would add audit logging flags to kube-apiserver.yaml"
        else
            mkdir -p /var/log/kubernetes/audit
            # Add audit flags
            sed -i '/- kube-apiserver/a \    - --audit-log-path=/var/log/kubernetes/audit/audit.log\n    - --audit-log-maxage=30\n    - --audit-log-maxbackup=3\n    - --audit-log-maxsize=100\n    - --audit-policy-file=/etc/kubernetes/audit-policy.yaml' "$APISERVER_MANIFEST"
            PASS "Enabled API server audit logging"
            FIXES_APPLIED=$((FIXES_APPLIED + 1))
        fi
    else
        PASS "Audit logging already configured or manifest not found"
    fi
fi

# ─── 2.1 — etcd: TLS encryption ───────────────────────────────────────────────
if [[ "$TARGET_CHECK" == "all" || "$TARGET_CHECK" == "2.1" ]]; then
    SECTION "CIS 2.1 — etcd: Ensure TLS peer certificates"

    ETCD_MANIFEST="/etc/kubernetes/manifests/etcd.yaml"
    if [[ -f "$ETCD_MANIFEST" ]]; then
        if grep -q "peer-cert-file\|peer-key-file" "$ETCD_MANIFEST"; then
            PASS "etcd peer TLS already configured"
        else
            WARN "etcd peer TLS not explicitly set — check etcd configuration"
            INFO "Certificates should be at: /etc/kubernetes/pki/etcd/"
            INFO "Verify: ls -la /etc/kubernetes/pki/etcd/"
        fi
    else
        INFO "etcd manifest not found — may be external etcd or managed cluster"
    fi
fi

# ─── 4.2.1 — Kubelet: Disable anonymous auth ──────────────────────────────────
if [[ "$TARGET_CHECK" == "all" || "$TARGET_CHECK" == "4.2.1" ]]; then
    SECTION "CIS 4.2.1 — Kubelet: Disable anonymous authentication"

    KUBELET_CONFIG="/etc/kubernetes/kubelet.conf"
    KUBELET_CONFIG_ALT="/var/lib/kubelet/config.yaml"

    for KCF in "$KUBELET_CONFIG" "$KUBELET_CONFIG_ALT"; do
        if [[ -f "$KCF" ]]; then
            if grep -q "anonymous:.*enabled.*false\|authentication.*anonymous.*false" "$KCF"; then
                PASS "Kubelet anonymous auth already disabled in $KCF"
            else
                cp "$KCF" "$EVIDENCE_DIR/$(basename $KCF).before" 2>/dev/null || true

                if $DRY_RUN; then
                    WARN "DRY RUN — would disable anonymous auth in $KCF"
                else
                    # Patch using kubectl or direct edit depending on config format
                    if grep -q "^authentication:" "$KCF"; then
                        WARN "Complex kubelet config — manual edit required"
                        INFO "Add to authentication section: anonymous:\n  enabled: false"
                        WARN "Review: $KCF"
                    else
                        # Add authentication section
                        echo -e "\nauthentication:\n  anonymous:\n    enabled: false\n  webhook:\n    enabled: true" >> "$KCF"
                        PASS "Added anonymous auth disable to $KCF"
                        FIXES_APPLIED=$((FIXES_APPLIED + 1))
                    fi
                fi
            fi
            break
        fi
    done
fi

# ─── 5.2.2 — Pod Security: Minimize privileged containers ────────────────────
if [[ "$TARGET_CHECK" == "all" || "$TARGET_CHECK" == "5.2.2" ]]; then
    SECTION "CIS 5.2.2 — Pod Security: Enforce no privileged containers"

    # Apply a Kyverno policy if Kyverno is available
    if kubectl get crd clusterpolicies.kyverno.io &>/dev/null 2>&1; then
        KYVERNO_POLICY=$(cat << 'EOF'
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: disallow-privileged-containers
  annotations:
    policies.kyverno.io/title: Disallow Privileged Containers
    policies.kyverno.io/description: "CIS 5.2.2 — Privileged containers share the host kernel. NIST CM-6."
spec:
  validationFailureAction: Enforce
  background: true
  rules:
    - name: check-privileged
      match:
        any:
        - resources:
            kinds: [Pod]
      exclude:
        any:
        - resources:
            namespaces: [kube-system]
      validate:
        message: "Privileged containers are not allowed. Remove securityContext.privileged: true."
        pattern:
          spec:
            containers:
              - =(securityContext):
                  =(privileged): "false"
EOF
        )
        echo "$KYVERNO_POLICY" > "$EVIDENCE_DIR/kyverno-no-privileged.yaml"

        if $DRY_RUN; then
            WARN "DRY RUN — would apply Kyverno policy: disallow-privileged-containers"
            INFO "Policy file: $EVIDENCE_DIR/kyverno-no-privileged.yaml"
        else
            kubectl apply -f "$EVIDENCE_DIR/kyverno-no-privileged.yaml" && \
                PASS "Applied Kyverno policy: disallow-privileged-containers" && \
                FIXES_APPLIED=$((FIXES_APPLIED + 1)) || \
                WARN "Could not apply Kyverno policy"
        fi
    else
        # Fall back to Pod Security Admission
        WARN "Kyverno not found — using Pod Security Admission instead"
        TARGET_NS="${TARGET_NAMESPACE:-default}"

        if $DRY_RUN; then
            WARN "DRY RUN — would label namespace $TARGET_NS with pod-security=restricted"
        else
            kubectl label namespace "$TARGET_NS" \
                pod-security.kubernetes.io/enforce=restricted \
                pod-security.kubernetes.io/warn=restricted \
                --overwrite && \
                PASS "Applied Pod Security Standards to namespace: $TARGET_NS" && \
                FIXES_APPLIED=$((FIXES_APPLIED + 1)) || \
                WARN "Could not apply Pod Security Standards"
        fi
    fi
fi

# ─── 5.7.1 — RBAC: Create namespaces ─────────────────────────────────────────
if [[ "$TARGET_CHECK" == "all" || "$TARGET_CHECK" == "5.7.1" ]]; then
    SECTION "CIS 5.7.1 — RBAC: Namespace isolation check"

    # Check for overly permissive ClusterRoleBindings
    echo "Checking for cluster-admin bindings..."
    CLUSTER_ADMIN_BINDINGS=$(kubectl get clusterrolebinding -o json 2>/dev/null | \
        jq -r '.items[] | select(.roleRef.name == "cluster-admin") | "\(.metadata.name): \(.subjects[]?.name // "N/A")"' 2>/dev/null | \
        grep -v "system:\|kubeadm\|kube-" || echo "none found")

    echo "$CLUSTER_ADMIN_BINDINGS" > "$EVIDENCE_DIR/cluster-admin-bindings.txt"

    if [[ "$CLUSTER_ADMIN_BINDINGS" == "none found" || -z "$CLUSTER_ADMIN_BINDINGS" ]]; then
        PASS "No suspicious cluster-admin bindings found"
    else
        WARN "Cluster-admin bindings found — review manually:"
        echo "$CLUSTER_ADMIN_BINDINGS" | head -10 | sed 's/^/  /'
        INFO "Review file: $EVIDENCE_DIR/cluster-admin-bindings.txt"
    fi
fi

# ─── Summary ──────────────────────────────────────────────────────────────────
echo ""
echo "======================================================"
echo " CIS Remediation Complete"
echo " Fixes applied: $FIXES_APPLIED"
echo " Fixes skipped (dry-run or manual): $FIXES_SKIPPED"
echo " Evidence: ${EVIDENCE_DIR}"
echo "======================================================"
echo ""
INFO "Run kube-bench to verify: docker run --rm --pid=host -v /etc:/etc:ro -v /var:/var:ro aquasec/kube-bench:latest"

{
    echo "timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "action: fix-cis-failures"
    echo "dry_run: $DRY_RUN"
    echo "fixes_applied: $FIXES_APPLIED"
    echo "fixes_skipped: $FIXES_SKIPPED"
    echo "evidence_dir: $EVIDENCE_DIR"
} > "$EVIDENCE_DIR/fix-summary.txt"
