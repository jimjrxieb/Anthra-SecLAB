#!/usr/bin/env bash
# audit-key-rotation.sh — L6 Presentation Layer key rotation age audit
# NIST: SC-12 (cryptographic key establishment and management)
# Usage: ./audit-key-rotation.sh [--azure-only | --vault-only | --k8s-only]
#        VAULT_ADDR, VAULT_TOKEN env vars for HashiCorp Vault
#        AZURE_VAULT_NAME env var for Azure Key Vault
set -euo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; NC='\033[0m'
PASS() { echo -e "${GREEN}[PASS]${NC} $*"; }
WARN() { echo -e "${YELLOW}[WARN]${NC} $*"; }
FAIL() { echo -e "${RED}[FAIL]${NC} $*"; }
INFO() { echo -e "       $*"; }

MODE="${1:-all}"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
EVIDENCE_DIR="/tmp/jsa-evidence/key-rotation-${TIMESTAMP}"
mkdir -p "$EVIDENCE_DIR"

VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"
VAULT_TOKEN="${VAULT_TOKEN:-}"
AZURE_VAULT_NAME="${AZURE_VAULT_NAME:-}"

# Thresholds (days)
WARN_THRESHOLD=90
FAIL_THRESHOLD=365

echo "======================================================"
echo " L6 Key Rotation Audit — SC-12"
echo " Mode: ${MODE}"
echo " Warn if key age > ${WARN_THRESHOLD} days"
echo " Fail if key age > ${FAIL_THRESHOLD} days"
echo " Evidence: ${EVIDENCE_DIR}"
echo " $(date)"
echo "======================================================"
echo ""

FINDINGS=0
NOW_EPOCH=$(date +%s)

# Helper: days since epoch timestamp
days_since() {
    local ts="$1"
    echo $(( (NOW_EPOCH - ts) / 86400 ))
}

# Helper: parse ISO 8601 date to epoch
iso_to_epoch() {
    local iso="$1"
    date -d "$iso" +%s 2>/dev/null || python3 -c "
import sys
from datetime import datetime, timezone
import re
iso = '$iso'.replace('Z','+00:00')
try:
    dt = datetime.fromisoformat(iso)
    print(int(dt.timestamp()))
except:
    print(0)
"
}

# ─── Azure Key Vault ─────────────────────────────────────────────────────
if [[ "$MODE" == "all" || "$MODE" == "--azure-only" ]]; then
    echo "═══════════════════════════════════════════════════════"
    echo " Azure Key Vault Key Rotation"
    echo "═══════════════════════════════════════════════════════"

    if ! command -v az &>/dev/null; then
        WARN "az CLI not found — skipping Azure Key Vault checks"
    elif ! az account show &>/dev/null 2>&1; then
        WARN "Not logged into Azure — run: az login"
    elif [[ -z "$AZURE_VAULT_NAME" ]]; then
        WARN "AZURE_VAULT_NAME not set — skipping Azure Key Vault checks"
        INFO "Set: export AZURE_VAULT_NAME=<your-vault-name>"
    else
        INFO "Azure Key Vault: ${AZURE_VAULT_NAME}"
        echo ""

        # List all keys in vault
        AKV_KEYS=$(az keyvault key list \
            --vault-name "$AZURE_VAULT_NAME" \
            -o json 2>/dev/null || echo "[]")
        echo "$AKV_KEYS" > "${EVIDENCE_DIR}/azure-kv-keys.json"

        KEY_COUNT=$(echo "$AKV_KEYS" | python3 -c "import json,sys; print(len(json.load(sys.stdin)))" 2>/dev/null || echo "0")
        INFO "Keys found in vault: ${KEY_COUNT}"

        if [[ "$KEY_COUNT" == "0" ]]; then
            WARN "No keys found in Azure Key Vault ${AZURE_VAULT_NAME}"
        else
            echo "$AKV_KEYS" | python3 -c "
import json,sys,datetime
keys = json.load(sys.stdin)
now = datetime.datetime.now(datetime.timezone.utc)
for key in keys:
    name = key.get('name', 'unknown')
    attrs = key.get('attributes', {})
    created = attrs.get('created', None)
    expires = attrs.get('expires', None)
    enabled = attrs.get('enabled', True)

    if created:
        created_dt = datetime.datetime.fromisoformat(created.replace('Z','+00:00'))
        age_days = (now - created_dt).days
        if age_days > 365:
            status = '[FAIL]'
        elif age_days > 90:
            status = '[WARN]'
        else:
            status = '[PASS]'
        print(f'{status} Key: {name} | Age: {age_days}d | Created: {created} | Enabled: {enabled}')
        if expires:
            exp_dt = datetime.datetime.fromisoformat(expires.replace('Z','+00:00'))
            days_until_exp = (exp_dt - now).days
            if days_until_exp < 30:
                print(f'  [WARN] Expires in {days_until_exp} days: {expires}')
    else:
        print(f'[WARN] Key: {name} | No creation date available')
" 2>/dev/null || WARN "Could not parse Azure Key Vault key data"
        fi

        # Check auto-rotation policies
        echo ""
        echo "── Azure Key Vault: Auto-Rotation Policies ──────────────────"
        echo "$AKV_KEYS" | python3 -c "
import json,sys,subprocess
keys = json.load(sys.stdin)
for key in keys:
    name = key.get('name', '')
    if not name:
        continue
    # Try to get rotation policy
    result = subprocess.run(
        ['az','keyvault','key','rotation-policy','show',
         '--vault-name', '$AZURE_VAULT_NAME', '--name', name],
        capture_output=True, text=True)
    if result.returncode == 0:
        try:
            policy = json.loads(result.stdout)
            attrs = policy.get('attributes', {})
            expiry = attrs.get('expiryTime', 'NOT_SET')
            print(f'[INFO] Key: {name} | Rotation policy expiryTime: {expiry}')
        except:
            print(f'[WARN] Key: {name} | Could not parse rotation policy')
    else:
        print(f'[WARN] Key: {name} | No rotation policy configured — manual rotation required')
" 2>/dev/null || WARN "Could not check rotation policies"
    fi
    echo ""
fi

# ─── HashiCorp Vault Transit ──────────────────────────────────────────────
if [[ "$MODE" == "all" || "$MODE" == "--vault-only" ]]; then
    echo "═══════════════════════════════════════════════════════"
    echo " HashiCorp Vault Transit Key Rotation"
    echo "═══════════════════════════════════════════════════════"

    if ! command -v vault &>/dev/null; then
        WARN "vault CLI not found — skipping HashiCorp Vault checks"
        INFO "Install: https://developer.hashicorp.com/vault/downloads"
    elif [[ -z "$VAULT_TOKEN" ]]; then
        WARN "VAULT_TOKEN not set — skipping HashiCorp Vault checks"
        INFO "Set: export VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=<token>"
    else
        export VAULT_ADDR VAULT_TOKEN
        INFO "Vault addr: ${VAULT_ADDR}"

        if ! vault status &>/dev/null 2>&1; then
            WARN "Cannot connect to Vault at ${VAULT_ADDR}"
        else
            # List transit keys
            TRANSIT_KEYS=$(vault list -format=json transit/keys 2>/dev/null || echo "[]")
            echo "$TRANSIT_KEYS" > "${EVIDENCE_DIR}/vault-transit-keys.json"

            KEY_COUNT=$(echo "$TRANSIT_KEYS" | python3 -c "import json,sys; k=json.load(sys.stdin); print(len(k) if isinstance(k,list) else 0)" 2>/dev/null || echo "0")
            INFO "Transit keys found: ${KEY_COUNT}"

            if [[ "$KEY_COUNT" == "0" ]]; then
                WARN "No transit keys found (or transit engine not enabled)"
                INFO "Enable: vault secrets enable transit"
            else
                echo "$TRANSIT_KEYS" | python3 -c "
import json,sys,subprocess,datetime

keys = json.load(sys.stdin)
if not isinstance(keys, list):
    keys = []

now = datetime.datetime.now(datetime.timezone.utc)

for key_name in keys:
    result = subprocess.run(
        ['vault', 'read', '-format=json', f'transit/keys/{key_name}'],
        capture_output=True, text=True,
        env={'VAULT_ADDR': '$VAULT_ADDR', 'VAULT_TOKEN': '$VAULT_TOKEN', 'HOME': '/', 'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'})

    if result.returncode != 0:
        print(f'[WARN] Key: {key_name} | Could not read key info')
        continue

    try:
        data = json.loads(result.stdout).get('data', {})
        latest_version = data.get('latest_version', 1)
        keys_data = data.get('keys', {})
        allow_rotation = data.get('allow_plaintext_backup', False)
        min_decryption = data.get('min_decryption_version', 1)

        if str(latest_version) in keys_data:
            key_info = keys_data[str(latest_version)]
            # Vault key creation time is Unix epoch
            creation_time = key_info.get('creation_time', '') if isinstance(key_info, dict) else ''
            if creation_time:
                try:
                    created_dt = datetime.datetime.fromisoformat(creation_time.replace('Z','+00:00'))
                    age_days = (now - created_dt).days
                    if age_days > 365:
                        status = '[FAIL]'
                    elif age_days > 90:
                        status = '[WARN]'
                    else:
                        status = '[PASS]'
                    print(f'{status} Key: {key_name} | Version: {latest_version} | Age: {age_days}d | Created: {creation_time}')
                    print(f'       Min decryption version: {min_decryption} (old versions still usable)')
                except Exception as e:
                    print(f'[WARN] Key: {key_name} | Could not parse creation time: {creation_time}')
            else:
                print(f'[INFO] Key: {key_name} | Version: {latest_version} | No creation timestamp')
        else:
            print(f'[INFO] Key: {key_name} | Version: {latest_version} | Key version data not accessible')
    except Exception as e:
        print(f'[WARN] Key: {key_name} | Parse error: {e}')
" 2>/dev/null || WARN "Could not parse transit key data"
            fi
        fi
    fi
    echo ""
fi

# ─── cert-manager Certificate Ages ───────────────────────────────────────
if [[ "$MODE" == "all" || "$MODE" == "--k8s-only" ]]; then
    echo "═══════════════════════════════════════════════════════"
    echo " cert-manager Certificate Ages"
    echo "═══════════════════════════════════════════════════════"

    if ! command -v kubectl &>/dev/null; then
        WARN "kubectl not found — skipping cert-manager checks"
    elif ! kubectl cluster-info &>/dev/null 2>&1; then
        WARN "kubectl not connected to a cluster"
    else
        # Check if cert-manager CRD exists
        if kubectl get crd certificates.cert-manager.io &>/dev/null 2>&1; then
            CERTS=$(kubectl get certificates.cert-manager.io -A \
                -o json 2>/dev/null || echo '{"items":[]}')
            echo "$CERTS" > "${EVIDENCE_DIR}/cert-manager-certs.json"

            CERT_COUNT=$(echo "$CERTS" | python3 -c "
import json,sys
print(len(json.load(sys.stdin).get('items',[])))
" 2>/dev/null || echo "0")
            INFO "cert-manager certificates found: ${CERT_COUNT}"

            if [[ "$CERT_COUNT" == "0" ]]; then
                INFO "No cert-manager certificates found"
            else
                echo "$CERTS" | python3 -c "
import json,sys,datetime
data = json.load(sys.stdin)
now = datetime.datetime.now(datetime.timezone.utc)

for cert in data.get('items', []):
    name = cert['metadata']['name']
    ns = cert['metadata']['namespace']
    status = cert.get('status', {})
    not_after = status.get('notAfter', '')
    renewal_time = status.get('renewalTime', '')
    ready_conditions = [c for c in status.get('conditions', []) if c.get('type') == 'Ready']
    ready = ready_conditions[0].get('status', 'Unknown') if ready_conditions else 'Unknown'

    creation = cert['metadata']['creationTimestamp']
    created_dt = datetime.datetime.fromisoformat(creation.replace('Z','+00:00'))
    age_days = (now - created_dt).days

    if not_after:
        exp_dt = datetime.datetime.fromisoformat(not_after.replace('Z','+00:00'))
        days_to_exp = (exp_dt - now).days
        if days_to_exp < 0:
            print(f'[FAIL] {ns}/{name} | EXPIRED {abs(days_to_exp)}d ago | Ready: {ready}')
        elif days_to_exp < 30:
            print(f'[WARN] {ns}/{name} | Expires in {days_to_exp}d | Ready: {ready}')
        else:
            print(f'[PASS] {ns}/{name} | Expires in {days_to_exp}d | Ready: {ready}')
    else:
        print(f'[WARN] {ns}/{name} | No expiry date | Age: {age_days}d | Ready: {ready}')
" 2>/dev/null || WARN "Could not parse cert-manager certificate data"
            fi
        else
            INFO "cert-manager CRD not found — cert-manager not installed"
            INFO "Install: helm install cert-manager jetstack/cert-manager --set installCRDs=true"
        fi
    fi
    echo ""
fi

# ─── Summary ──────────────────────────────────────────────────────────────
echo "======================================================"
echo " Key Rotation Audit Summary"
echo " Total findings: ${FINDINGS}"
echo " Evidence: ${EVIDENCE_DIR}"
echo " $(date)"
echo "======================================================"

cat > "${EVIDENCE_DIR}/summary.txt" <<EOF
L6 Key Rotation Audit Summary
Date: $(date)
Mode: ${MODE}
Total Findings: ${FINDINGS}
NIST Control: SC-12 (Cryptographic Key Establishment and Management)
Thresholds: WARN=${WARN_THRESHOLD}d, FAIL=${FAIL_THRESHOLD}d

Files:
- azure-kv-keys.json: Azure Key Vault key list
- vault-transit-keys.json: HashiCorp Vault transit key list
- cert-manager-certs.json: cert-manager certificate list
EOF

if [[ $FINDINGS -gt 0 ]]; then
    echo ""
    WARN "Remediation: see 02-fixers/fix-key-rotation.sh"
fi
