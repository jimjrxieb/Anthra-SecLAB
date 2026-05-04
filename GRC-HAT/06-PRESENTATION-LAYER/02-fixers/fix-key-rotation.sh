#!/usr/bin/env bash
# fix-key-rotation.sh — L6 Presentation Layer dual-stack key rotation
# NIST: SC-12 (cryptographic key establishment and management)
# Usage: ./fix-key-rotation.sh [--azure | --vault] --key-name <name> [--vault-name <vault>]
# Env vars: VAULT_ADDR, VAULT_TOKEN, AZURE_VAULT_NAME
#
# CSF 2.0: PR.DS-10 (Data-in-use confidentiality)
# CIS v8: 3.11 (Encrypt Sensitive Data at Rest)
# NIST: SC-12 (Cryptographic Key Management)
#
set -euo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; NC='\033[0m'
INFO() { echo -e "       $*"; }
PASS() { echo -e "${GREEN}[PASS]${NC} $*"; }
WARN() { echo -e "${YELLOW}[WARN]${NC} $*"; }
FAIL() { echo -e "${RED}[FAIL]${NC} $*"; }
STEP() { echo -e "\n${YELLOW}── $* ──${NC}"; }

STACK=""
KEY_NAME=""
AZURE_VAULT_NAME="${AZURE_VAULT_NAME:-}"
VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"
VAULT_TOKEN="${VAULT_TOKEN:-}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --azure) STACK="azure"; shift ;;
        --vault) STACK="vault"; shift ;;
        --key-name) KEY_NAME="$2"; shift 2 ;;
        --vault-name) AZURE_VAULT_NAME="$2"; shift 2 ;;
        *) shift ;;
    esac
done

if [[ -z "$KEY_NAME" && -z "$STACK" ]]; then
    echo "Usage: $0 [--azure | --vault] --key-name <name>"
    echo "       $0 --azure --key-name mykey --vault-name my-akv"
    echo "       $0 --vault --key-name mykey"
    echo ""
    echo "If no stack specified, runs both."
    echo "Env: AZURE_VAULT_NAME, VAULT_ADDR, VAULT_TOKEN"
    exit 1
fi

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
EVIDENCE_DIR="/tmp/jsa-evidence/key-rotation-fix-${TIMESTAMP}"
mkdir -p "$EVIDENCE_DIR"

echo "======================================================"
echo " L6 Key Rotation Fix — SC-12"
echo " Stack: ${STACK:-both}"
echo " Key name: ${KEY_NAME:-all}"
echo " Evidence: ${EVIDENCE_DIR}"
echo " $(date)"
echo "======================================================"

# ─── Azure Key Vault Rotation ─────────────────────────────────────────────
run_azure_rotation() {
    local key="$1"
    STEP "Azure Key Vault: Rotating key '${key}'"

    if ! command -v az &>/dev/null; then
        FAIL "az CLI not found"
        return 1
    fi
    if ! az account show &>/dev/null 2>&1; then
        FAIL "Not logged into Azure — run: az login"
        return 1
    fi
    if [[ -z "$AZURE_VAULT_NAME" ]]; then
        FAIL "AZURE_VAULT_NAME not set"
        return 1
    fi

    # BEFORE: capture current key version
    BEFORE=$(az keyvault key show \
        --vault-name "$AZURE_VAULT_NAME" \
        --name "$key" \
        --query "{version:key.kid, created:attributes.created, enabled:attributes.enabled}" \
        -o json 2>/dev/null || echo '{"error":"key not found"}')
    echo "BEFORE: $BEFORE" | tee -a "${EVIDENCE_DIR}/azure-rotation-${key}.txt"
    INFO "Before version: $(echo "$BEFORE" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('version','unknown').split('/')[-1])" 2>/dev/null || echo "unknown")"

    # ROTATE: az keyvault key rotate
    INFO "Rotating key..."
    ROTATE_RESULT=$(az keyvault key rotate \
        --vault-name "$AZURE_VAULT_NAME" \
        --name "$key" \
        -o json 2>/dev/null || echo '{"error":"rotation failed"}')

    if echo "$ROTATE_RESULT" | python3 -c "import json,sys; d=json.load(sys.stdin); exit(0 if 'key' in d or 'id' in d else 1)" 2>/dev/null; then
        AFTER_VERSION=$(echo "$ROTATE_RESULT" | python3 -c "
import json,sys
d = json.load(sys.stdin)
kid = d.get('key',{}).get('kid', d.get('id',''))
print(kid.split('/')[-1] if kid else 'unknown')
" 2>/dev/null || echo "unknown")
        echo "AFTER: $ROTATE_RESULT" | tee -a "${EVIDENCE_DIR}/azure-rotation-${key}.txt"
        PASS "Azure Key Vault: key '${key}' rotated — new version: ${AFTER_VERSION}"
    else
        echo "ROTATE_RESULT: $ROTATE_RESULT" | tee -a "${EVIDENCE_DIR}/azure-rotation-${key}.txt"
        FAIL "Azure Key Vault: rotation failed for key '${key}'"
        INFO "Check permissions: key rotate requires Key Rotate permission"
        return 1
    fi
}

# ─── HashiCorp Vault Transit Rotation ─────────────────────────────────────
run_vault_rotation() {
    local key="$1"
    STEP "HashiCorp Vault: Rotating transit key '${key}'"

    if ! command -v vault &>/dev/null; then
        FAIL "vault CLI not found"
        return 1
    fi
    if [[ -z "$VAULT_TOKEN" ]]; then
        FAIL "VAULT_TOKEN not set"
        return 1
    fi

    export VAULT_ADDR VAULT_TOKEN

    if ! vault status &>/dev/null 2>&1; then
        FAIL "Cannot connect to Vault at ${VAULT_ADDR}"
        return 1
    fi

    # BEFORE: capture current key version
    BEFORE=$(vault read -format=json "transit/keys/${key}" 2>/dev/null \
        | python3 -c "
import json,sys
d = json.load(sys.stdin).get('data',{})
print(json.dumps({'latest_version': d.get('latest_version'), 'min_decryption_version': d.get('min_decryption_version')}))
" 2>/dev/null || echo '{"error":"key not found"}')
    echo "BEFORE: $BEFORE" | tee -a "${EVIDENCE_DIR}/vault-rotation-${key}.txt"

    BEFORE_VERSION=$(echo "$BEFORE" | python3 -c "import json,sys; print(json.load(sys.stdin).get('latest_version','unknown'))" 2>/dev/null || echo "unknown")
    INFO "Before version: ${BEFORE_VERSION}"

    # ROTATE
    INFO "Rotating key..."
    vault write -f "transit/keys/${key}/rotate" >> "${EVIDENCE_DIR}/vault-rotation-${key}.txt" 2>&1

    # AFTER: capture new key version
    AFTER=$(vault read -format=json "transit/keys/${key}" 2>/dev/null \
        | python3 -c "
import json,sys
d = json.load(sys.stdin).get('data',{})
print(json.dumps({'latest_version': d.get('latest_version'), 'min_decryption_version': d.get('min_decryption_version')}))
" 2>/dev/null || echo '{"error":"read failed"}')
    echo "AFTER: $AFTER" | tee -a "${EVIDENCE_DIR}/vault-rotation-${key}.txt"

    AFTER_VERSION=$(echo "$AFTER" | python3 -c "import json,sys; print(json.load(sys.stdin).get('latest_version','unknown'))" 2>/dev/null || echo "unknown")
    INFO "After version: ${AFTER_VERSION}"

    if [[ "$AFTER_VERSION" != "$BEFORE_VERSION" && "$AFTER_VERSION" != "unknown" ]]; then
        PASS "Vault: transit key '${key}' rotated — version ${BEFORE_VERSION} → ${AFTER_VERSION}"
    else
        FAIL "Vault: key version did not change (before=${BEFORE_VERSION}, after=${AFTER_VERSION})"
        return 1
    fi

    # REWRAP: rewrap any existing ciphertexts to new key version
    STEP "Vault: Re-wrap existing ciphertexts for key '${key}'"
    INFO "WHY: After rotation, existing ciphertexts still use old key version."
    INFO "     Rewrap upgrades them to the new version, allowing old versions to be retired."
    INFO ""
    INFO "To rewrap a specific ciphertext:"
    INFO "  vault write transit/rewrap/${key} ciphertext=<vault:v${BEFORE_VERSION}:...>"
    INFO ""
    INFO "To set minimum decryption version (retire old keys):"
    INFO "  vault write transit/keys/${key}/config min_decryption_version=${AFTER_VERSION}"
    INFO ""
    INFO "WARNING: Only set min_decryption_version after ALL data has been re-encrypted."
}

# ─── Execute ──────────────────────────────────────────────────────────────
case "$STACK" in
    azure)
        if [[ -n "$KEY_NAME" ]]; then
            run_azure_rotation "$KEY_NAME"
        else
            # Rotate all keys in vault
            if command -v az &>/dev/null && az account show &>/dev/null 2>&1 && [[ -n "$AZURE_VAULT_NAME" ]]; then
                KEYS=$(az keyvault key list --vault-name "$AZURE_VAULT_NAME" \
                    --query "[].name" -o tsv 2>/dev/null || echo "")
                if [[ -n "$KEYS" ]]; then
                    while IFS= read -r k; do run_azure_rotation "$k"; done <<< "$KEYS"
                else
                    WARN "No keys found in vault ${AZURE_VAULT_NAME}"
                fi
            fi
        fi
        ;;
    vault)
        if [[ -n "$KEY_NAME" ]]; then
            run_vault_rotation "$KEY_NAME"
        else
            # Rotate all transit keys
            if command -v vault &>/dev/null && [[ -n "$VAULT_TOKEN" ]]; then
                export VAULT_ADDR VAULT_TOKEN
                KEYS=$(vault list -format=json transit/keys 2>/dev/null \
                    | python3 -c "import json,sys; ks=json.load(sys.stdin); print('\n'.join(ks) if isinstance(ks,list) else '')" \
                    2>/dev/null || echo "")
                if [[ -n "$KEYS" ]]; then
                    while IFS= read -r k; do run_vault_rotation "$k"; done <<< "$KEYS"
                else
                    WARN "No transit keys found"
                fi
            fi
        fi
        ;;
    *)
        # Both stacks
        if [[ -n "$KEY_NAME" ]]; then
            run_azure_rotation "$KEY_NAME" || true
            run_vault_rotation "$KEY_NAME" || true
        else
            WARN "Specify --key-name or a specific --azure/--vault stack to rotate all"
        fi
        ;;
esac

echo ""
echo "======================================================"
echo " Key Rotation Complete"
echo " Evidence: ${EVIDENCE_DIR}"
echo " $(date)"
echo "======================================================"

cat > "${EVIDENCE_DIR}/summary.txt" <<EOF
L6 Key Rotation Fix Summary
Date: $(date)
Stack: ${STACK:-both}
Key: ${KEY_NAME:-all}
NIST Control: SC-12 (Cryptographic Key Establishment and Management)

Files:
- azure-rotation-<key>.txt: Azure Key Vault before/after version evidence
- vault-rotation-<key>.txt: HashiCorp Vault before/after version evidence
EOF
