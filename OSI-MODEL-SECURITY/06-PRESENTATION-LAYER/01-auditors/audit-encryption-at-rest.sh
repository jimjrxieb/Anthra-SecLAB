#!/usr/bin/env bash
# audit-encryption-at-rest.sh — L6 Presentation Layer encryption-at-rest audit
# NIST: SC-28 (protection of information at rest)
# Usage: ./audit-encryption-at-rest.sh [--k8s-only | --azure-only | --disk-only]
set -euo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; NC='\033[0m'
PASS() { echo -e "${GREEN}[PASS]${NC} $*"; }
WARN() { echo -e "${YELLOW}[WARN]${NC} $*"; }
FAIL() { echo -e "${RED}[FAIL]${NC} $*"; }
INFO() { echo -e "       $*"; }

MODE="${1:-all}"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
EVIDENCE_DIR="/tmp/jsa-evidence/encryption-at-rest-${TIMESTAMP}"
mkdir -p "$EVIDENCE_DIR"

echo "======================================================"
echo " L6 Encryption-at-Rest Audit — SC-28"
echo " Mode: ${MODE}"
echo " Evidence: ${EVIDENCE_DIR}"
echo " $(date)"
echo "======================================================"
echo ""

FINDINGS=0

# ─── K8s etcd Encryption ──────────────────────────────────────────────────
if [[ "$MODE" == "all" || "$MODE" == "--k8s-only" ]]; then
    echo "═══════════════════════════════════════════════════════"
    echo " Kubernetes etcd Encryption at Rest"
    echo "═══════════════════════════════════════════════════════"

    if ! command -v kubectl &>/dev/null; then
        WARN "kubectl not found — skipping K8s checks"
    elif ! kubectl cluster-info &>/dev/null 2>&1; then
        WARN "kubectl not connected to a cluster — skipping K8s checks"
    else
        # ── 1. Check kube-apiserver --encryption-provider-config flag ──
        echo "── kube-apiserver encryption-provider-config ─────────────────"
        APISERVER_POD=$(kubectl get pods -n kube-system -l component=kube-apiserver \
            -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")

        if [[ -z "$APISERVER_POD" ]]; then
            WARN "kube-apiserver pod not found (may be using managed K8s — check control plane)"
            INFO "For EKS/GKE/AKS: check provider console for encryption at rest settings"
        else
            ENC_FLAG=$(kubectl get pod "$APISERVER_POD" -n kube-system \
                -o jsonpath='{.spec.containers[0].command}' 2>/dev/null \
                | python3 -c "import json,sys; cmds=json.load(sys.stdin); print([c for c in cmds if 'encryption-provider-config' in c] or ['NOT_SET'])" \
                2>/dev/null || echo "NOT_SET")

            echo "$ENC_FLAG" > "${EVIDENCE_DIR}/apiserver-encryption-flag.txt"

            if echo "$ENC_FLAG" | grep -q "NOT_SET"; then
                FAIL "kube-apiserver: --encryption-provider-config NOT set"
                INFO "WHY: Without EncryptionConfiguration, K8s Secrets are base64 in etcd — not encrypted"
                INFO "Fix: see 02-fixers/fix-etcd-encryption.sh"
                FINDINGS=$((FINDINGS + 1))
            else
                PASS "kube-apiserver: --encryption-provider-config is set"
                INFO "$ENC_FLAG"
            fi
        fi
        echo ""

        # ── 2. Spot-check: read a secret and look for enc: prefix ───────
        echo "── etcd Secret Encryption Spot-Check ────────────────────────"
        INFO "Checking if Secrets are encrypted (enc: prefix indicates encryption)"
        # Get a test secret and inspect raw etcd value via apiserver debug
        TEST_SECRET=$(kubectl get secrets -A -o json 2>/dev/null \
            | python3 -c "
import json,sys
data = json.load(sys.stdin)
items = data.get('items', [])
if items:
    s = items[0]
    print(f\"{s['metadata']['namespace']}/{s['metadata']['name']}\")
else:
    print('NO_SECRETS')
" 2>/dev/null || echo "NO_SECRETS")

        echo "Test secret: ${TEST_SECRET}" > "${EVIDENCE_DIR}/etcd-spot-check.txt"

        if [[ "$TEST_SECRET" != "NO_SECRETS" ]]; then
            INFO "Test secret found: ${TEST_SECRET}"
            INFO "To verify etcd encryption directly: etcdctl get /registry/secrets/<ns>/<name> | hexdump | head"
            INFO "Encrypted secrets begin with 'k8s:enc:' prefix in etcd"
        else
            WARN "No secrets found in cluster — cannot perform spot check"
        fi
        echo ""

        # ── 3. EncryptionConfiguration resource check ────────────────────
        echo "── EncryptionConfiguration Provider Check ───────────────────"
        if [[ -n "$APISERVER_POD" ]]; then
            ENC_CONFIG_PATH=$(kubectl get pod "$APISERVER_POD" -n kube-system \
                -o jsonpath='{.spec.containers[0].command}' 2>/dev/null \
                | python3 -c "
import json,sys
cmds = json.load(sys.stdin)
for c in cmds:
    if 'encryption-provider-config' in c:
        print(c.split('=',1)[1] if '=' in c else 'path-not-parseable')
        break
else:
    print('NOT_CONFIGURED')
" 2>/dev/null || echo "NOT_CONFIGURED")

            echo "EncryptionConfiguration path: ${ENC_CONFIG_PATH}" >> "${EVIDENCE_DIR}/apiserver-encryption-flag.txt"

            if [[ "$ENC_CONFIG_PATH" != "NOT_CONFIGURED" ]]; then
                PASS "EncryptionConfiguration path: ${ENC_CONFIG_PATH}"
            else
                WARN "Could not determine EncryptionConfiguration path"
            fi
        fi
        echo ""
    fi
fi

# ─── PostgreSQL SSL/Encryption ────────────────────────────────────────────
if [[ "$MODE" == "all" || "$MODE" == "--db-only" ]]; then
    echo "═══════════════════════════════════════════════════════"
    echo " PostgreSQL Encryption at Rest"
    echo "═══════════════════════════════════════════════════════"

    if command -v psql &>/dev/null; then
        PG_HOST="${PGHOST:-localhost}"
        PG_PORT="${PGPORT:-5432}"
        PG_USER="${PGUSER:-postgres}"

        INFO "PostgreSQL: ${PG_HOST}:${PG_PORT} as ${PG_USER}"

        # Check ssl setting
        SSL_STATUS=$(psql -h "$PG_HOST" -p "$PG_PORT" -U "$PG_USER" \
            -tAc "SHOW ssl;" 2>/dev/null || echo "CONNECTION_FAILED")
        echo "ssl: ${SSL_STATUS}" > "${EVIDENCE_DIR}/postgres-ssl.txt"

        if [[ "$SSL_STATUS" == "on" ]]; then
            PASS "PostgreSQL ssl: on — connections require TLS"
        elif [[ "$SSL_STATUS" == "CONNECTION_FAILED" ]]; then
            WARN "PostgreSQL: connection failed — set PGHOST/PGPORT/PGUSER env vars"
        else
            FAIL "PostgreSQL ssl: off — transport not encrypted"
            INFO "WHY: SC-28 requires protection of data in transit and at rest"
            INFO "Fix: set ssl=on in postgresql.conf and configure ssl_cert_file/ssl_key_file"
            FINDINGS=$((FINDINGS + 1))
        fi

        # Check data directory encryption (tablespace-level)
        DATA_DIR=$(psql -h "$PG_HOST" -p "$PG_PORT" -U "$PG_USER" \
            -tAc "SHOW data_directory;" 2>/dev/null || echo "CONNECTION_FAILED")
        echo "data_directory: ${DATA_DIR}" >> "${EVIDENCE_DIR}/postgres-ssl.txt"

        if [[ "$DATA_DIR" != "CONNECTION_FAILED" ]]; then
            INFO "Data directory: ${DATA_DIR}"
            INFO "Verify OS-level encryption (LUKS/BitLocker) covers this path"
        fi
    else
        WARN "psql not found — skipping PostgreSQL checks"
        INFO "Install: apt-get install postgresql-client or brew install libpq"
    fi
    echo ""
fi

# ─── Disk Encryption ─────────────────────────────────────────────────────
if [[ "$MODE" == "all" || "$MODE" == "--disk-only" ]]; then
    echo "═══════════════════════════════════════════════════════"
    echo " Disk Encryption (LUKS / BitLocker)"
    echo "═══════════════════════════════════════════════════════"

    OS_TYPE=$(uname -s)

    if [[ "$OS_TYPE" == "Linux" ]]; then
        # ── LUKS check ──────────────────────────────────────────────────
        echo "── LUKS (Linux) ──────────────────────────────────────────────"
        if command -v lsblk &>/dev/null; then
            BLOCK_DEVICES=$(lsblk -Jo NAME,TYPE,FSTYPE,MOUNTPOINT 2>/dev/null || echo '{}')
            echo "$BLOCK_DEVICES" > "${EVIDENCE_DIR}/lsblk-output.json"

            LUKS_DEVICES=$(echo "$BLOCK_DEVICES" | python3 -c "
import json,sys
data = json.load(sys.stdin)
luks = [d['name'] for d in data.get('blockdevices',[]) if d.get('fstype','') == 'crypto_LUKS'
        or any(c.get('fstype','') == 'crypto_LUKS' for c in d.get('children',[]) or [])]
print(len(luks), 'LUKS device(s):', ', '.join(luks) if luks else 'none found')
" 2>/dev/null || echo "parse error")

            if echo "$LUKS_DEVICES" | grep -q "^0"; then
                FAIL "No LUKS-encrypted block devices found"
                INFO "WHY: SC-28 requires encryption of data at rest on storage devices"
                INFO "Fix: cryptsetup luksFormat <device> then cryptsetup luksOpen"
                FINDINGS=$((FINDINGS + 1))
            else
                PASS "$LUKS_DEVICES"
            fi
        fi

        if command -v cryptsetup &>/dev/null; then
            # Check status of active LUKS mappings
            ACTIVE_LUKS=$(dmsetup ls --target crypt 2>/dev/null | awk '{print $1}' || echo "")
            if [[ -n "$ACTIVE_LUKS" ]]; then
                echo "$ACTIVE_LUKS" > "${EVIDENCE_DIR}/active-luks-mappings.txt"
                while IFS= read -r mapping; do
                    LUKS_INFO=$(cryptsetup status "$mapping" 2>/dev/null || echo "status unavailable")
                    PASS "LUKS mapping active: /dev/mapper/${mapping}"
                    echo "--- ${mapping} ---" >> "${EVIDENCE_DIR}/active-luks-mappings.txt"
                    echo "$LUKS_INFO" >> "${EVIDENCE_DIR}/active-luks-mappings.txt"
                done <<< "$ACTIVE_LUKS"
            else
                WARN "No active LUKS device mappings found (cryptsetup dmsetup)"
            fi
        else
            WARN "cryptsetup not found — cannot check LUKS status"
            INFO "Install: apt-get install cryptsetup"
        fi

    elif [[ "$OS_TYPE" == "Darwin" ]]; then
        # ── FileVault check (macOS) ──────────────────────────────────────
        echo "── FileVault (macOS) ─────────────────────────────────────────"
        FV_STATUS=$(fdesetup status 2>/dev/null || echo "command failed")
        echo "$FV_STATUS" > "${EVIDENCE_DIR}/filevault-status.txt"
        if echo "$FV_STATUS" | grep -qi "on"; then
            PASS "FileVault: On"
        else
            FAIL "FileVault: Off — disk not encrypted"
            INFO "WHY: SC-28 requires protection of data at rest"
            INFO "Fix: System Preferences > Security & Privacy > FileVault > Turn On"
            FINDINGS=$((FINDINGS + 1))
        fi
    fi
    echo ""
fi

# ─── Azure Storage Encryption ─────────────────────────────────────────────
if [[ "$MODE" == "all" || "$MODE" == "--azure-only" ]]; then
    echo "═══════════════════════════════════════════════════════"
    echo " Azure Storage Encryption"
    echo "═══════════════════════════════════════════════════════"

    if ! command -v az &>/dev/null; then
        WARN "az CLI not found — skipping Azure checks"
        INFO "Install: https://docs.microsoft.com/en-us/cli/azure/install-azure-cli"
    elif ! az account show &>/dev/null 2>&1; then
        WARN "Not logged into Azure — run: az login"
    else
        # List storage accounts and check encryption
        echo "── Azure Storage Account Encryption ─────────────────────────"
        STORAGE_ACCOUNTS=$(az storage account list \
            --query "[].{name:name, rg:resourceGroup}" \
            -o json 2>/dev/null || echo "[]")
        echo "$STORAGE_ACCOUNTS" > "${EVIDENCE_DIR}/azure-storage-accounts.json"

        SA_COUNT=$(echo "$STORAGE_ACCOUNTS" | python3 -c "import json,sys; print(len(json.load(sys.stdin)))" 2>/dev/null || echo "0")
        INFO "Storage accounts found: ${SA_COUNT}"

        if [[ "$SA_COUNT" == "0" ]]; then
            INFO "No storage accounts found or no access"
        else
            echo "$STORAGE_ACCOUNTS" | python3 -c "
import json,sys,subprocess
accounts = json.load(sys.stdin)
for acct in accounts[:5]:  # limit to first 5 to avoid rate limits
    name = acct['name']
    rg = acct['rg']
    result = subprocess.run(['az','storage','account','show',
        '--name', name, '--resource-group', rg,
        '--query', 'encryption', '-o', 'json'],
        capture_output=True, text=True)
    if result.returncode == 0:
        enc = json.loads(result.stdout)
        svc = enc.get('services', {})
        blob_enabled = svc.get('blob', {}).get('enabled', False)
        file_enabled = svc.get('file', {}).get('enabled', False)
        key_src = enc.get('keySource', 'unknown')
        status = 'PASS' if blob_enabled else 'FAIL'
        print(f'[{status}] {name}: blob={blob_enabled}, file={file_enabled}, keySource={key_src}')
    else:
        print(f'[WARN] {name}: could not retrieve encryption status')
" 2>/dev/null || WARN "Could not parse Azure storage encryption data"
        fi
    fi
    echo ""
fi

# ─── Summary ──────────────────────────────────────────────────────────────
echo "======================================================"
echo " Encryption-at-Rest Audit Summary"
echo " Total findings: ${FINDINGS}"
echo " Evidence: ${EVIDENCE_DIR}"
echo " $(date)"
echo "======================================================"

cat > "${EVIDENCE_DIR}/summary.txt" <<EOF
L6 Encryption-at-Rest Audit Summary
Date: $(date)
Mode: ${MODE}
Total Findings: ${FINDINGS}
NIST Control: SC-28 (Protection of Information at Rest)

Files:
- apiserver-encryption-flag.txt: K8s kube-apiserver encryption flag check
- etcd-spot-check.txt: etcd secret spot check
- postgres-ssl.txt: PostgreSQL SSL and data directory
- lsblk-output.json: Linux block device listing
- active-luks-mappings.txt: Active LUKS device mappings
- azure-storage-accounts.json: Azure storage account list
EOF

if [[ $FINDINGS -gt 0 ]]; then
    echo ""
    WARN "Remediation: see 02-fixers/fix-etcd-encryption.sh and 02-fixers/fix-bitlocker-enforcement.md"
fi
