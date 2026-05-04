#!/usr/bin/env bash
# fix-plaintext-secrets.sh — Migrate K8s ConfigMap secrets to proper K8s Secrets
# NIST: SC-28 (protection of information at rest), SI-10 (info input validation)
# Usage: ./fix-plaintext-secrets.sh [--namespace <ns>] [--dry-run]
# WHY: K8s Secrets (with etcd encryption) provide encryption at rest.
#      ConfigMaps are plain text in etcd and in audit logs.
#
# CSF 2.0: PR.DS-01 (Data-at-rest confidentiality)
# CIS v8: 3.11 (Encrypt Sensitive Data at Rest)
# NIST: SC-28 (Protection of Information at Rest)
#
set -euo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; NC='\033[0m'
INFO() { echo -e "       $*"; }
PASS() { echo -e "${GREEN}[PASS]${NC} $*"; }
WARN() { echo -e "${YELLOW}[WARN]${NC} $*"; }
FAIL() { echo -e "${RED}[FAIL]${NC} $*"; }
STEP() { echo -e "\n${YELLOW}── $* ──${NC}"; }

NAMESPACE=""
DRY_RUN=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --namespace|-n) NAMESPACE="$2"; shift 2 ;;
        --dry-run) DRY_RUN=true; shift ;;
        *) shift ;;
    esac
done

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
EVIDENCE_DIR="/tmp/jsa-evidence/plaintext-secrets-fix-${TIMESTAMP}"
mkdir -p "$EVIDENCE_DIR"

NS_FLAG=""
[[ -n "$NAMESPACE" ]] && NS_FLAG="-n $NAMESPACE" || NS_FLAG="-A"

echo "======================================================"
echo " L6 Plaintext Secrets Fix — SC-28"
echo " Namespace: ${NAMESPACE:-all}"
echo " Dry-run: ${DRY_RUN}"
echo " Evidence: ${EVIDENCE_DIR}"
echo " $(date)"
echo "======================================================"
echo ""

if ! command -v kubectl &>/dev/null; then
    FAIL "kubectl not found"
    exit 1
fi
if ! kubectl cluster-info &>/dev/null 2>&1; then
    FAIL "kubectl not connected to a cluster"
    exit 1
fi

SECRET_KEYS=(
    "password" "passwd" "secret" "api_key" "apikey" "api-key"
    "token" "private_key" "private-key" "credentials"
    "database_url" "db_password" "aws_secret" "aws_access_key"
    "client_secret" "refresh_token" "access_token"
)

MIGRATED=0
SKIPPED=0

# ─── Step 1: Find ConfigMaps with secret-like keys ───────────────────────
STEP "Scanning ConfigMaps for secret-like keys"

CONFIGMAPS=$(kubectl get configmaps $NS_FLAG -o json 2>/dev/null || echo '{"items":[]}')
CM_COUNT=$(echo "$CONFIGMAPS" | python3 -c "import json,sys; print(len(json.load(sys.stdin).get('items',[])))" 2>/dev/null || echo "0")
INFO "ConfigMaps scanned: ${CM_COUNT}"

# Find suspicious ConfigMaps
SUSPICIOUS=$(echo "$CONFIGMAPS" | python3 -c "
import json,sys,re

data = json.load(sys.stdin)
secret_keys = [
    'password','passwd','secret','api_key','apikey','api-key',
    'token','private_key','private-key','credentials',
    'database_url','db_password','aws_secret','aws_access_key',
    'client_secret','refresh_token','access_token'
]

# Skip system/infra ConfigMaps
skip_prefixes = ['kube-', 'calico-', 'coredns', 'aws-', 'gce-', 'azure-']

results = []
for cm in data.get('items', []):
    ns = cm['metadata']['namespace']
    name = cm['metadata']['name']

    # Skip system ConfigMaps
    if any(name.startswith(p) for p in skip_prefixes):
        continue
    if ns in ['kube-system', 'kube-public', 'kube-node-lease']:
        continue

    cm_data = cm.get('data', {}) or {}
    suspicious_keys = {}

    for key, value in cm_data.items():
        key_lower = key.lower().replace('-','_').replace('.','_')
        if any(sk in key_lower for sk in secret_keys):
            if value and len(str(value)) > 3 and not str(value).startswith('\$'):
                suspicious_keys[key] = value

    if suspicious_keys:
        results.append({'ns': ns, 'name': name, 'keys': suspicious_keys})

for r in results:
    print(json.dumps(r))
" 2>/dev/null || echo "")

if [[ -z "$SUSPICIOUS" ]]; then
    PASS "No suspicious ConfigMaps found"
    exit 0
fi

SUSP_COUNT=$(echo "$SUSPICIOUS" | grep -c '.' || echo "0")
WARN "Found ${SUSP_COUNT} ConfigMap(s) with secret-like keys"

# ─── Step 2: Migrate each suspicious ConfigMap ───────────────────────────
STEP "Migrating ConfigMap secrets to K8s Secrets"

echo "$SUSPICIOUS" | while IFS= read -r cm_json; do
    [[ -z "$cm_json" ]] && continue

    NS=$(echo "$cm_json" | python3 -c "import json,sys; print(json.loads(sys.stdin.read())['ns'])" 2>/dev/null)
    NAME=$(echo "$cm_json" | python3 -c "import json,sys; print(json.loads(sys.stdin.read())['name'])" 2>/dev/null)
    KEYS=$(echo "$cm_json" | python3 -c "import json,sys; print(json.dumps(json.loads(sys.stdin.read())['keys']))" 2>/dev/null)

    INFO ""
    INFO "ConfigMap: ${NS}/${NAME}"
    INFO "Secret-like keys found: $(echo "$KEYS" | python3 -c "import json,sys; print(', '.join(json.load(sys.stdin).keys()))" 2>/dev/null)"

    # Save original ConfigMap
    kubectl get configmap "$NAME" -n "$NS" -o yaml > "${EVIDENCE_DIR}/cm-before-${NS}-${NAME}.yaml" 2>/dev/null || true

    # Build kubectl create secret command
    SECRET_ARGS=$(echo "$KEYS" | python3 -c "
import json,sys,base64
keys = json.load(sys.stdin)
args = []
for k, v in keys.items():
    # Sanitize key name for K8s Secret (lowercase, no special chars)
    safe_k = k.lower().replace('_','-').replace('.','-')
    args.append(f'--from-literal={safe_k}={v}')
print(' '.join(args))
" 2>/dev/null || echo "")

    SECRET_NAME="${NAME}-secrets"

    if [[ "$DRY_RUN" == "true" ]]; then
        INFO "[DRY-RUN] Would create Secret: ${NS}/${SECRET_NAME}"
        INFO "[DRY-RUN] kubectl create secret generic ${SECRET_NAME} -n ${NS} ${SECRET_ARGS}"
        echo "DRY-RUN: ${NS}/${SECRET_NAME}" >> "${EVIDENCE_DIR}/migration-log.txt"
    else
        # Check if Secret already exists
        if kubectl get secret "$SECRET_NAME" -n "$NS" &>/dev/null 2>&1; then
            WARN "Secret ${NS}/${SECRET_NAME} already exists — skipping (manual review required)"
            echo "SKIPPED: ${NS}/${SECRET_NAME} (already exists)" >> "${EVIDENCE_DIR}/migration-log.txt"
        else
            # Create Secret
            eval "kubectl create secret generic ${SECRET_NAME} -n ${NS} ${SECRET_ARGS}" \
                >> "${EVIDENCE_DIR}/migration-log.txt" 2>&1

            if kubectl get secret "$SECRET_NAME" -n "$NS" &>/dev/null 2>&1; then
                PASS "Created Secret: ${NS}/${SECRET_NAME}"
                echo "CREATED: ${NS}/${SECRET_NAME}" >> "${EVIDENCE_DIR}/migration-log.txt"

                # Generate patch instructions for affected deployments
                STEP "Patch instructions for workloads using ConfigMap ${NAME}"
                INFO "Find pods using this ConfigMap:"
                INFO "  kubectl get pods -n ${NS} -o json | python3 -c \\"
                INFO "    \"import json,sys; [print(p['metadata']['name']) for p in json.load(sys.stdin)['items']"
                INFO "     if any(v.get('configMap',{}).get('name')=='${NAME}'"
                INFO "     for v in p.get('spec',{}).get('volumes',[]))]\""
                INFO ""
                INFO "Update Deployment to use Secret (example):"
                cat >> "${EVIDENCE_DIR}/patch-example-${NAME}.yaml" <<PATCHEOF
# WHY: Replace ConfigMap env vars with Secret env vars.
# SC-28 requires secrets to be encrypted at rest (K8s Secrets + etcd encryption).
# patch for deployment using configmap ${NAME}
apiVersion: apps/v1
kind: Deployment
metadata:
  name: <your-deployment>
  namespace: ${NS}
spec:
  template:
    spec:
      containers:
        - name: <your-container>
          envFrom:
            # REMOVE this:
            # - configMapRef:
            #     name: ${NAME}
            # ADD this:
            - secretRef:
                name: ${SECRET_NAME}
PATCHEOF
                INFO "Patch template saved: ${EVIDENCE_DIR}/patch-example-${NAME}.yaml"

                MIGRATED=$((MIGRATED + 1))
            else
                FAIL "Failed to create Secret ${NS}/${SECRET_NAME}"
            fi
        fi
    fi
done

echo ""

# ─── Step 3: External Secrets Operator recommendation ────────────────────
STEP "External Secrets Operator (ESO) — Production Recommendation"
INFO "WHY: For production, don't store secrets in K8s at all."
INFO "     ESO syncs secrets from Azure Key Vault / HashiCorp Vault → K8s Secrets."
INFO "     The source of truth stays in the vault, not in etcd."
INFO ""
INFO "Install ESO:"
INFO "  helm repo add external-secrets https://charts.external-secrets.io"
INFO "  helm install external-secrets external-secrets/external-secrets \\"
INFO "    --namespace external-secrets --create-namespace \\"
INFO "    --set installCRDs=true"
INFO ""
INFO "Example SecretStore (Azure Key Vault):"
cat >> "${EVIDENCE_DIR}/eso-example-azure.yaml" <<ESOEOF
# WHY: ExternalSecret pulls from Azure Key Vault and creates a K8s Secret.
# Secret value never enters git or a ConfigMap. Only the reference does.
apiVersion: external-secrets.io/v1beta1
kind: SecretStore
metadata:
  name: azure-kv-store
  namespace: default
spec:
  provider:
    azurekv:
      authType: WorkloadIdentity
      vaultUrl: "https://<your-vault>.vault.azure.net"
---
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: app-secrets
  namespace: default
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: azure-kv-store
    kind: SecretStore
  target:
    name: app-secrets
    creationPolicy: Owner
  data:
    - secretKey: database-password
      remoteRef:
        key: database-password   # Key Vault secret name
ESOEOF
INFO "ESO example saved: ${EVIDENCE_DIR}/eso-example-azure.yaml"

echo ""
echo "======================================================"
echo " Plaintext Secrets Fix Complete"
echo " Migrated: ${MIGRATED}"
echo " Evidence: ${EVIDENCE_DIR}"
echo " $(date)"
echo "======================================================"

cat > "${EVIDENCE_DIR}/summary.txt" <<EOF
L6 Plaintext Secrets Fix Summary
Date: $(date)
Namespace: ${NAMESPACE:-all}
Dry-run: ${DRY_RUN}
Migrated: ${MIGRATED}
NIST Control: SC-28 (Protection of Information at Rest)

Files:
- cm-before-<ns>-<name>.yaml: Original ConfigMap snapshots (before migration)
- migration-log.txt: Created/skipped Secret log
- patch-example-<name>.yaml: Deployment patch instructions
- eso-example-azure.yaml: External Secrets Operator configuration example

Next Steps:
1. Update Deployments to use Secrets (secretRef) instead of ConfigMaps
2. Test that workloads start correctly
3. Delete old ConfigMap keys (after confirming Secret works)
4. Consider ESO for long-term secret lifecycle management
EOF
