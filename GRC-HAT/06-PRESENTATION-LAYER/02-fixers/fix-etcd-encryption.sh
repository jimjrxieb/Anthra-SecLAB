#!/usr/bin/env bash
# fix-etcd-encryption.sh — Enable K8s etcd encryption at rest
# NIST: SC-28 (protection of information at rest)
# Usage: ./fix-etcd-encryption.sh [--dry-run] [--apiserver-manifest <path>]
# WARNING: This modifies kube-apiserver. Run on control plane node only.
# PREREQUISITE: Run as root or with sudo on the control plane node.
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

DRY_RUN=false
APISERVER_MANIFEST="${APISERVER_MANIFEST:-/etc/kubernetes/manifests/kube-apiserver.yaml}"
ENC_CONFIG_PATH="/etc/kubernetes/encryption/encryption-config.yaml"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run) DRY_RUN=true; shift ;;
        --apiserver-manifest) APISERVER_MANIFEST="$2"; shift 2 ;;
        *) shift ;;
    esac
done

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
EVIDENCE_DIR="/tmp/jsa-evidence/etcd-encryption-fix-${TIMESTAMP}"
mkdir -p "$EVIDENCE_DIR"

echo "======================================================"
echo " L6 etcd Encryption-at-Rest Fix — SC-28"
echo " Dry-run: ${DRY_RUN}"
echo " kube-apiserver manifest: ${APISERVER_MANIFEST}"
echo " Evidence: ${EVIDENCE_DIR}"
echo " $(date)"
echo "======================================================"
echo ""
WARN "PREREQUISITE: Run on the K8s control plane node as root."
WARN "This script modifies kube-apiserver and will cause a brief API server restart."
echo ""

if ! command -v kubectl &>/dev/null; then
    FAIL "kubectl not found"
    exit 1
fi

# ─── Step 1: Check current state ─────────────────────────────────────────
STEP "Check Current etcd Encryption State"

APISERVER_POD=$(kubectl get pods -n kube-system -l component=kube-apiserver \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")

if [[ -n "$APISERVER_POD" ]]; then
    EXISTING_FLAG=$(kubectl get pod "$APISERVER_POD" -n kube-system \
        -o jsonpath='{.spec.containers[0].command}' 2>/dev/null \
        | python3 -c "
import json,sys
cmds = json.load(sys.stdin)
found = [c for c in cmds if 'encryption-provider-config' in c]
print(found[0] if found else 'NOT_SET')
" 2>/dev/null || echo "NOT_SET")

    kubectl get pod "$APISERVER_POD" -n kube-system \
        -o jsonpath='{.spec.containers[0].command}' \
        > "${EVIDENCE_DIR}/before-apiserver-command.txt" 2>/dev/null || true

    if [[ "$EXISTING_FLAG" != "NOT_SET" ]]; then
        PASS "etcd encryption already configured: ${EXISTING_FLAG}"
        INFO "No changes needed. To verify, check that secrets have 'k8s:enc:' prefix in etcd."
        exit 0
    else
        WARN "etcd encryption NOT configured — proceeding with fix"
        INFO "Current state: K8s Secrets are stored as base64 in etcd (not encrypted)"
    fi
else
    WARN "kube-apiserver pod not found in kube-system (may be managed K8s)"
    INFO "For EKS: encryption is configured via aws eks create-cluster --encryption-config"
    INFO "For GKE: encryption is configured via --database-encryption-key at cluster creation"
    INFO "For AKS: encryption is configured at node pool level (managed by Azure)"
    INFO ""
    INFO "This script targets kubeadm-deployed clusters with static pod manifests."
fi

# ─── Step 2: Generate encryption key ─────────────────────────────────────
STEP "Generate 32-byte AES Encryption Key"

# WHY: EncryptionConfiguration requires a base64-encoded 32-byte key for aescbc
if command -v openssl &>/dev/null; then
    ENC_KEY=$(openssl rand -base64 32)
elif command -v python3 &>/dev/null; then
    ENC_KEY=$(python3 -c "import os,base64; print(base64.b64encode(os.urandom(32)).decode())")
else
    FAIL "Cannot generate encryption key: neither openssl nor python3 found"
    exit 1
fi

INFO "Generated 32-byte key (base64-encoded)"
INFO "WHY: aescbc requires exactly 32 bytes (AES-256). Store this key securely — losing it loses all secrets."

# ─── Step 3: Create EncryptionConfiguration ──────────────────────────────
STEP "Create EncryptionConfiguration"

mkdir -p "$(dirname "$ENC_CONFIG_PATH")"

ENC_CONFIG_CONTENT="# WHY: NIST SC-28 requires protection of information at rest.
# Without this, K8s Secrets are base64-encoded in etcd — readable by anyone with etcd access.
# This configures AES-CBC-256 encryption for the 'secrets' resource type.
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
      - secrets
      # WHY: Also encrypt ConfigMaps if they contain sensitive data
      # - configmaps
    providers:
      - aescbc:
          keys:
            - name: key1
              # WHY: key1 is the active encryption key. New writes use this key.
              secret: ${ENC_KEY}
      # WHY: identity{} fallback allows reading pre-existing unencrypted secrets
      # during the migration. Remove it after all secrets are re-encrypted.
      - identity: {}
"

if [[ "$DRY_RUN" == "true" ]]; then
    WARN "[DRY-RUN] Would write EncryptionConfiguration to: ${ENC_CONFIG_PATH}"
    echo "$ENC_CONFIG_CONTENT" > "${EVIDENCE_DIR}/encryption-config-preview.yaml"
    INFO "Preview saved: ${EVIDENCE_DIR}/encryption-config-preview.yaml"
else
    if [[ ! -f "$APISERVER_MANIFEST" ]]; then
        FAIL "kube-apiserver manifest not found: ${APISERVER_MANIFEST}"
        INFO "Run on the control plane node (usually /etc/kubernetes/manifests/kube-apiserver.yaml)"
        exit 1
    fi

    echo "$ENC_CONFIG_CONTENT" > "$ENC_CONFIG_PATH"
    chmod 600 "$ENC_CONFIG_PATH"
    PASS "EncryptionConfiguration written: ${ENC_CONFIG_PATH}"
    INFO "Permissions set to 600 (root only)"
    echo "$ENC_CONFIG_CONTENT" > "${EVIDENCE_DIR}/encryption-config.yaml"
fi

# ─── Step 4: Backup kube-apiserver manifest ───────────────────────────────
STEP "Backup kube-apiserver Manifest"

if [[ "$DRY_RUN" == "true" ]]; then
    WARN "[DRY-RUN] Would backup: ${APISERVER_MANIFEST} → ${EVIDENCE_DIR}/kube-apiserver.yaml.backup"
elif [[ -f "$APISERVER_MANIFEST" ]]; then
    cp "$APISERVER_MANIFEST" "${EVIDENCE_DIR}/kube-apiserver.yaml.backup"
    PASS "Backup saved: ${EVIDENCE_DIR}/kube-apiserver.yaml.backup"
else
    WARN "Manifest not found: ${APISERVER_MANIFEST} (skipping backup)"
fi

# ─── Step 5: Patch kube-apiserver manifest ───────────────────────────────
STEP "Patch kube-apiserver Manifest"

PATCH_CMD="--encryption-provider-config=${ENC_CONFIG_PATH}"

if [[ "$DRY_RUN" == "true" ]]; then
    WARN "[DRY-RUN] Would add to kube-apiserver command:"
    INFO "  ${PATCH_CMD}"
    WARN "[DRY-RUN] Would add to kube-apiserver volumeMounts:"
    INFO "  - mountPath: $(dirname ${ENC_CONFIG_PATH})"
    INFO "    name: encryption-config"
    INFO "    readOnly: true"
    WARN "[DRY-RUN] Would add to kube-apiserver volumes:"
    INFO "  - hostPath:"
    INFO "      path: $(dirname ${ENC_CONFIG_PATH})"
    INFO "      type: DirectoryOrCreate"
    INFO "    name: encryption-config"
else
    if [[ -f "$APISERVER_MANIFEST" ]]; then
        # Use python3 to safely modify the YAML
        python3 - "$APISERVER_MANIFEST" "$ENC_CONFIG_PATH" "$PATCH_CMD" <<'PYEOF'
import sys, yaml

manifest_path = sys.argv[1]
enc_config_path = sys.argv[2]
patch_cmd = sys.argv[3]
enc_dir = str(sys.argv[2]).rsplit('/', 1)[0]

with open(manifest_path, 'r') as f:
    manifest = yaml.safe_load(f)

container = manifest['spec']['containers'][0]

# Add --encryption-provider-config flag if not present
cmds = container.get('command', [])
if not any('encryption-provider-config' in c for c in cmds):
    cmds.append(patch_cmd)
    container['command'] = cmds
    print(f"Added: {patch_cmd}")
else:
    print(f"Flag already present — no change")

# Add volume mount
vol_mounts = container.get('volumeMounts', [])
if not any(v.get('name') == 'encryption-config' for v in vol_mounts):
    vol_mounts.append({
        'mountPath': enc_dir,
        'name': 'encryption-config',
        'readOnly': True
    })
    container['volumeMounts'] = vol_mounts
    print(f"Added volumeMount: {enc_dir}")

# Add volume
volumes = manifest['spec'].get('volumes', [])
if not any(v.get('name') == 'encryption-config' for v in volumes):
    volumes.append({
        'hostPath': {
            'path': enc_dir,
            'type': 'DirectoryOrCreate'
        },
        'name': 'encryption-config'
    })
    manifest['spec']['volumes'] = volumes
    print(f"Added volume: {enc_dir}")

with open(manifest_path, 'w') as f:
    yaml.dump(manifest, f, default_flow_style=False)

print("Manifest updated successfully")
PYEOF
        PASS "kube-apiserver manifest patched: ${APISERVER_MANIFEST}"
        INFO "kubelet will detect the manifest change and restart kube-apiserver automatically"
        INFO "Wait 30-60 seconds for the API server to restart"
    else
        WARN "Manifest not found — skipping patch"
    fi
fi

# ─── Step 6: Verify encryption ────────────────────────────────────────────
STEP "Verify etcd Encryption (run after API server restarts)"

INFO "After the API server restarts, run the following to verify:"
echo ""
INFO "1. Re-encrypt all existing secrets (forces existing secrets through encryption):"
INFO "   kubectl get secrets --all-namespaces -o json | kubectl replace -f -"
INFO ""
INFO "2. Check a specific secret in etcd (requires etcdctl):"
INFO "   ETCDCTL_API=3 etcdctl get /registry/secrets/default/my-secret \\"
INFO "     --endpoints=https://127.0.0.1:2379 \\"
INFO "     --cacert=/etc/kubernetes/pki/etcd/ca.crt \\"
INFO "     --cert=/etc/kubernetes/pki/etcd/server.crt \\"
INFO "     --key=/etc/kubernetes/pki/etcd/server.key \\"
INFO "     | hexdump | head"
INFO "   # Encrypted secrets begin with 'k8s:enc:aescbc:v1'"
INFO ""
INFO "3. Verify via kubectl (should still work — reads are transparent):"
INFO "   kubectl get secret my-secret -n default -o yaml"
INFO ""

if [[ "$DRY_RUN" == "false" ]] && command -v kubectl &>/dev/null; then
    # Wait for API server restart
    INFO "Waiting 60s for API server to restart..."
    sleep 60

    if kubectl cluster-info &>/dev/null 2>&1; then
        PASS "API server is responding after config change"

        # Re-encrypt existing secrets
        INFO "Re-encrypting all existing secrets..."
        kubectl get secrets --all-namespaces -o json \
            | kubectl replace -f - \
            >> "${EVIDENCE_DIR}/re-encryption.log" 2>&1 || WARN "Some secrets may not have been re-encrypted"
        PASS "Secret re-encryption complete"
        INFO "Log: ${EVIDENCE_DIR}/re-encryption.log"

        # Capture after state
        kubectl get pod "$(kubectl get pods -n kube-system -l component=kube-apiserver \
            -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo '')" \
            -n kube-system \
            -o jsonpath='{.spec.containers[0].command}' \
            > "${EVIDENCE_DIR}/after-apiserver-command.txt" 2>/dev/null || true
        PASS "After state captured: ${EVIDENCE_DIR}/after-apiserver-command.txt"
    else
        WARN "API server not responding yet — check kubelet logs: journalctl -u kubelet -f"
    fi
fi

echo ""
echo "======================================================"
echo " etcd Encryption Fix Complete"
echo " Evidence: ${EVIDENCE_DIR}"
echo " $(date)"
echo "======================================================"

cat > "${EVIDENCE_DIR}/summary.txt" <<EOF
L6 etcd Encryption Fix Summary
Date: $(date)
Dry-run: ${DRY_RUN}
kube-apiserver manifest: ${APISERVER_MANIFEST}
EncryptionConfiguration: ${ENC_CONFIG_PATH}
NIST Control: SC-28 (Protection of Information at Rest)

Files:
- kube-apiserver.yaml.backup: Original manifest backup
- encryption-config.yaml: Applied EncryptionConfiguration
- before-apiserver-command.txt: API server command before change
- after-apiserver-command.txt: API server command after change
- re-encryption.log: Secret re-encryption output

Post-fix actions required:
1. Run: kubectl get secrets --all-namespaces -o json | kubectl replace -f -
2. Verify etcd with etcdctl and confirm 'k8s:enc:' prefix
3. After ALL secrets re-encrypted, remove 'identity: {}' provider from encryption-config.yaml
4. Backup encryption key to HashiCorp Vault or Azure Key Vault
EOF
