#!/usr/bin/env bash
#
# CSF: PROTECT / PR.PS-01 — Configuration management practices applied to IT assets
# CIS v8: 4.1 — Establish and Maintain a Secure Configuration Process
# NIST 800-53: CM-6 — Configuration Settings, CM-7 — Least Functionality
#
# L7-03 PR.PS-01 — Fix: Remediate top 5 CIS benchmark findings
#
# This script addresses the five most common, fixable CIS findings
# for the anthra namespace:
#
#   Fix 1: Verify and patch securityContext (CIS 5.2.5, 5.2.6 / C-0013, C-0017)
#   Fix 2: Add default-deny NetworkPolicy (CIS 5.3.2 / C-0030)
#   Fix 3: Verify resource limits exist (CIS 5.7.4 / C-0044)
#   Fix 4: Add PSS labels to anthra namespace (CIS 5.2.1)
#   Fix 5: Disable service account token auto-mounting (CIS 5.1.6)
#
# Each fix prints what changed and why (CIS reference included).
# This script does NOT modify kube-bench node-level findings (kubelet config)
# — those require cluster admin access and are documented as POA&M.
#
# Usage: bash fix.sh
# Prerequisite: Run baseline.sh first to establish the pre-fix counts.

set -euo pipefail

NAMESPACE="anthra"
DEPLOYMENTS=(
  "portfolio-anthra-portfolio-app-api"
  "portfolio-anthra-portfolio-app-ui"
  "portfolio-anthra-portfolio-app-chroma"
)

FIX_LOG="/tmp/L7-03-fix-$(date +%Y%m%d-%H%M%S).log"

log() {
  echo "$*" | tee -a "${FIX_LOG}"
}

log "=== L7-03 PR.PS-01 Fix: CIS Benchmark Remediation ==="
log "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
log "Namespace: ${NAMESPACE}"
log "Fix log: ${FIX_LOG}"
log ""

# Verify namespace exists
if ! kubectl get namespace "${NAMESPACE}" &>/dev/null; then
  log "ERROR: Namespace '${NAMESPACE}' not found."
  log "       Run: kubectl get namespaces"
  exit 1
fi

# --- Fix 1: securityContext verification ---
# CIS 5.2.5 (Do not allow privilege escalation), CIS 5.2.6 (Do not run as root)
# kubescape C-0013 (Non-root containers), C-0017 (Immutable container filesystem)
# CM-7: Limit the functions, ports, protocols, and services permitted
log "--- Fix 1: Security Context (CIS 5.2.5, 5.2.6 / C-0013, C-0017) ---"
log ""
log "Verifying securityContext on all Portfolio deployments..."
log "If a deployment is missing required fields, this fix patches them."
log ""

for DEPLOY in "${DEPLOYMENTS[@]}"; do
  if ! kubectl get deployment "${DEPLOY}" -n "${NAMESPACE}" &>/dev/null; then
    log "  SKIP: ${DEPLOY} not found"
    continue
  fi

  # Check current state
  ALLOW_PRIV=$(kubectl get deployment "${DEPLOY}" -n "${NAMESPACE}" \
    -o jsonpath='{.spec.template.spec.containers[0].securityContext.allowPrivilegeEscalation}' \
    2>/dev/null || echo "")
  READONLY_FS=$(kubectl get deployment "${DEPLOY}" -n "${NAMESPACE}" \
    -o jsonpath='{.spec.template.spec.containers[0].securityContext.readOnlyRootFilesystem}' \
    2>/dev/null || echo "")
  RUN_NON_ROOT=$(kubectl get deployment "${DEPLOY}" -n "${NAMESPACE}" \
    -o jsonpath='{.spec.template.spec.securityContext.runAsNonRoot}' \
    2>/dev/null || echo "")

  NEEDS_PATCH=false

  if [[ "${ALLOW_PRIV}" != "false" ]]; then
    log "  FINDING: ${DEPLOY} — allowPrivilegeEscalation not explicitly set to false"
    NEEDS_PATCH=true
  fi

  if [[ "${READONLY_FS}" != "true" ]]; then
    log "  FINDING: ${DEPLOY} — readOnlyRootFilesystem not set to true"
    NEEDS_PATCH=true
  fi

  if [[ "${RUN_NON_ROOT}" != "true" ]]; then
    log "  FINDING: ${DEPLOY} — runAsNonRoot not set to true on pod spec"
    NEEDS_PATCH=true
  fi

  if [[ "${NEEDS_PATCH}" == "true" ]]; then
    log "  ACTION: Patching securityContext on ${DEPLOY}"
    log "  CIS 5.2.5: allowPrivilegeEscalation=false prevents setuid-based escalation"
    log "  CIS 5.2.6: runAsNonRoot=true prevents UID 0 container processes"
    log "  CIS 5.2.4: readOnlyRootFilesystem=true prevents runtime file modification"
    log ""

    # Patch container securityContext
    kubectl patch deployment "${DEPLOY}" -n "${NAMESPACE}" \
      --type='json' \
      -p='[
        {"op":"add","path":"/spec/template/spec/securityContext/runAsNonRoot","value":true},
        {"op":"add","path":"/spec/template/spec/containers/0/securityContext/allowPrivilegeEscalation","value":false},
        {"op":"add","path":"/spec/template/spec/containers/0/securityContext/readOnlyRootFilesystem","value":true}
      ]' 2>/dev/null && log "  PATCHED: ${DEPLOY}" || \
      log "  NOTE: Patch may have partially applied or fields already exist — verify manually"
  else
    log "  OK: ${DEPLOY} securityContext already configured correctly"
  fi
done

log ""

# --- Fix 2: Default-deny NetworkPolicy ---
# CIS 5.3.2: Ensure that all Namespaces have Network Policies defined
# kubescape C-0030: Ingress and Egress blocked
# CM-7: Least functionality — only permit necessary communications
log "--- Fix 2: Default-Deny NetworkPolicy (CIS 5.3.2 / C-0030) ---"
log ""

NP_COUNT=$(kubectl get networkpolicy -n "${NAMESPACE}" --no-headers 2>/dev/null | wc -l | tr -d ' ')

if [[ "${NP_COUNT}" -eq 0 ]]; then
  log "FINDING: No NetworkPolicies exist in namespace ${NAMESPACE}"
  log "ACTION: Creating default-deny-all policy"
  log "CIS 5.3.2: All namespaces must have NetworkPolicies defined"
  log "This policy blocks all ingress and egress unless explicitly permitted."
  log "WARNING: After applying this, create explicit allow policies for your services."
  log ""

  kubectl apply -f - <<'EOF'
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: anthra
  labels:
    app.kubernetes.io/managed-by: seclab-fix
    cis-control: "5.3.2"
    csf-control: "PR.PS-01"
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
EOF

  log "APPLIED: default-deny-all NetworkPolicy in namespace ${NAMESPACE}"
  log ""
  log "IMPORTANT: This is a default-deny policy. Add explicit allow policies for:"
  log "  - API service ingress (from ingress controller or UI pods)"
  log "  - UI service ingress (from ingress controller)"
  log "  - Chroma service egress (from API pods)"
  log "  - DNS egress (port 53 UDP/TCP to kube-dns)"
  log "  See remediate.md for allow policy examples."
else
  log "OK: ${NP_COUNT} NetworkPolicy/ies already exist in namespace ${NAMESPACE}"
  kubectl get networkpolicy -n "${NAMESPACE}" 2>/dev/null | tee -a "${FIX_LOG}"
fi

log ""

# --- Fix 3: Resource limits verification ---
# CIS 5.7.4: CPU and memory limits should be set for containers
# kubescape C-0044: Container resource limits
# CM-7: Prevent resource exhaustion from unconstrained containers
log "--- Fix 3: Resource Limits Verification (CIS 5.7.4 / C-0044) ---"
log ""

for DEPLOY in "${DEPLOYMENTS[@]}"; do
  if ! kubectl get deployment "${DEPLOY}" -n "${NAMESPACE}" &>/dev/null; then
    log "  SKIP: ${DEPLOY} not found"
    continue
  fi

  CPU_LIMIT=$(kubectl get deployment "${DEPLOY}" -n "${NAMESPACE}" \
    -o jsonpath='{.spec.template.spec.containers[0].resources.limits.cpu}' \
    2>/dev/null || echo "")
  MEM_LIMIT=$(kubectl get deployment "${DEPLOY}" -n "${NAMESPACE}" \
    -o jsonpath='{.spec.template.spec.containers[0].resources.limits.memory}' \
    2>/dev/null || echo "")

  if [[ -z "${CPU_LIMIT}" || -z "${MEM_LIMIT}" ]]; then
    log "  FINDING: ${DEPLOY} — resource limits missing (cpu=${CPU_LIMIT:-unset}, memory=${MEM_LIMIT:-unset})"
    log "  CIS 5.7.4: Missing limits allow unbounded resource consumption"
    log "  NOTE: Setting limits requires knowledge of actual workload needs."
    log "        Consult the application team before patching these values."
    log "        Document this as a POA&M item if the team has not profiled usage."
  else
    log "  OK: ${DEPLOY} — cpu=${CPU_LIMIT}, memory=${MEM_LIMIT}"
  fi
done

log ""

# --- Fix 4: PSS labels on namespace ---
# CIS 5.2.1: Ensure namespace-level Pod Security Standards admission controls are configured
# CM-6: Configuration settings for admission control
log "--- Fix 4: PSS Labels on Namespace (CIS 5.2.1) ---"
log ""

PSS_ENFORCE=$(kubectl get namespace "${NAMESPACE}" \
  -o jsonpath='{.metadata.labels.pod-security\.kubernetes\.io/enforce}' \
  2>/dev/null || echo "")

if [[ -z "${PSS_ENFORCE}" ]]; then
  log "FINDING: No PSS enforce label on namespace ${NAMESPACE}"
  log "ACTION: Adding pod-security.kubernetes.io/enforce=baseline"
  log "CIS 5.2.1: Namespace must enforce Pod Security Standards at admission"
  log "Using 'baseline' level — blocks privileged containers while allowing most workloads"
  log ""

  kubectl label namespace "${NAMESPACE}" \
    pod-security.kubernetes.io/enforce=baseline \
    pod-security.kubernetes.io/enforce-version=latest \
    pod-security.kubernetes.io/warn=restricted \
    pod-security.kubernetes.io/warn-version=latest \
    --overwrite

  log "APPLIED: PSS labels on namespace ${NAMESPACE}"
  log "  enforce=baseline  — blocks privileged containers at admission"
  log "  warn=restricted   — warns on restricted violations without blocking"
else
  log "OK: PSS enforce label already set: ${PSS_ENFORCE}"
fi

log ""

# --- Fix 5: Service account token auto-mounting ---
# CIS 5.1.6: Ensure that Service Account Tokens are not automatically mounted
# CM-7: Disable unnecessary capabilities
log "--- Fix 5: Service Account Token Auto-Mount (CIS 5.1.6) ---"
log ""
log "Checking automountServiceAccountToken on all Portfolio deployments..."
log ""

for DEPLOY in "${DEPLOYMENTS[@]}"; do
  if ! kubectl get deployment "${DEPLOY}" -n "${NAMESPACE}" &>/dev/null; then
    log "  SKIP: ${DEPLOY} not found"
    continue
  fi

  AUTO_MOUNT=$(kubectl get deployment "${DEPLOY}" -n "${NAMESPACE}" \
    -o jsonpath='{.spec.template.spec.automountServiceAccountToken}' \
    2>/dev/null || echo "")

  if [[ "${AUTO_MOUNT}" != "false" ]]; then
    log "  FINDING: ${DEPLOY} — automountServiceAccountToken is '${AUTO_MOUNT:-not set}' (defaults to true)"
    log "  CIS 5.1.6: Pods that do not need API access should not mount SA tokens"
    log "  ACTION: Setting automountServiceAccountToken=false"
    log ""

    kubectl patch deployment "${DEPLOY}" -n "${NAMESPACE}" \
      --type='json' \
      -p='[{"op":"add","path":"/spec/template/spec/automountServiceAccountToken","value":false}]' \
      2>/dev/null && log "  PATCHED: ${DEPLOY} — automountServiceAccountToken=false" || \
      log "  NOTE: Patch may have failed — verify with kubectl get deployment ${DEPLOY} -n ${NAMESPACE} -o yaml"
  else
    log "  OK: ${DEPLOY} — automountServiceAccountToken=false already set"
  fi
done

log ""

# --- Wait for any rollouts triggered by patches ---
log "--- Waiting for rollouts to stabilize ---"
log ""

for DEPLOY in "${DEPLOYMENTS[@]}"; do
  if kubectl get deployment "${DEPLOY}" -n "${NAMESPACE}" &>/dev/null; then
    log "Checking rollout: ${DEPLOY}"
    kubectl rollout status deployment/"${DEPLOY}" -n "${NAMESPACE}" --timeout=90s \
      2>/dev/null && log "  OK: ${DEPLOY} rollout complete" || \
      log "  WARN: ${DEPLOY} rollout may still be in progress — check: kubectl rollout status deployment/${DEPLOY} -n ${NAMESPACE}"
  fi
done

log ""
log "=== Fix complete ==="
log ""
log "What changed:"
log "  Fix 1: securityContext patched on deployments missing allowPrivilegeEscalation=false,"
log "         readOnlyRootFilesystem=true, runAsNonRoot=true"
log "  Fix 2: default-deny-all NetworkPolicy created (or verified existing)"
log "  Fix 3: Resource limits verified (POA&M documented if missing)"
log "  Fix 4: PSS baseline enforcement label added to namespace anthra"
log "  Fix 5: automountServiceAccountToken=false patched on pods that did not have it"
log ""
log "Fix log saved to: ${FIX_LOG}"
log ""
log "NEXT STEP: Run verify.sh to compare FAIL counts before vs after."
