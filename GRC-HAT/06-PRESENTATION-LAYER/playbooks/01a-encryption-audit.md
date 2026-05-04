# 01a-encryption-audit.md — L6 Deep-Dive: Encryption at Rest

| Field | Value |
|---|---|
| **NIST Controls** | SC-28 (protection of information at rest), SC-28(1) (cryptographic protection) |
| **Prerequisite** | `01-assess.md` checklist complete — at least one SC-28 finding identified |
| **Objective** | Verify encryption status at every data layer: etcd, database, disk, cloud storage |
| **Time** | 1–3 hours depending on environment size |
| **Rank** | D (investigation and evidence collection) |

---

## Layer 1: Kubernetes etcd Encryption

### What is the risk?

K8s Secrets are stored in etcd. Without EncryptionConfiguration, they are stored as base64 — not encrypted. Anyone with direct etcd access reads everything: API tokens, TLS certs, database passwords, all Secrets.

### Step 1: Check if encryption is configured

```bash
# Check kube-apiserver for --encryption-provider-config flag
kubectl get pod -n kube-system -l component=kube-apiserver \
    -o jsonpath='{.items[0].spec.containers[0].command}' \
    | python3 -c "
import json,sys
cmds = json.load(sys.stdin)
enc = [c for c in cmds if 'encryption-provider-config' in c]
print('CONFIGURED:', enc[0] if enc else 'NOT SET')
"
```

### Step 2: Read the EncryptionConfiguration

```bash
# Get the config path from the flag, then read it
# On control plane node:
cat /etc/kubernetes/encryption/encryption-config.yaml

# What to look for:
# GOOD: provider 'aescbc' or 'aesgcm' or 'kms' is FIRST in the list
# BAD:  provider 'identity' is FIRST in the list (means no encryption for new writes)
# BAD:  no EncryptionConfiguration file at all
```

### Step 3: Verify a secret is actually encrypted in etcd

```bash
# On control plane node (requires etcdctl + cluster PKI certs)
ETCDCTL_API=3 etcdctl get /registry/secrets/default/my-secret \
    --endpoints=https://127.0.0.1:2379 \
    --cacert=/etc/kubernetes/pki/etcd/ca.crt \
    --cert=/etc/kubernetes/pki/etcd/server.crt \
    --key=/etc/kubernetes/pki/etcd/server.key \
    | hexdump -C | head -3

# PASS: first line shows bytes matching 'k8s:enc:aescbc:v1' prefix
# Hex: 6b 38 73 3a 65 6e 63 3a 61 65 73 63 62 63 3a 76 31
# FAIL: first line shows 'k8s:' without 'enc:' — plain base64
```

### Step 4: List all resources that should be encrypted

```bash
# Count Secrets by namespace to understand scope
kubectl get secrets -A \
    --no-headers \
    | awk '{print $1}' \
    | sort | uniq -c | sort -rn
# This is how many secrets need to be re-encrypted if you just enabled encryption
```

### Step 5: Force re-encryption of all existing secrets

```bash
# After enabling EncryptionConfiguration, existing secrets are still unencrypted.
# This command reads and re-writes every secret, triggering encryption.
kubectl get secrets --all-namespaces -o json | kubectl replace -f -
# Verify by running Step 3 again — should now see k8s:enc: prefix
```

### Evidence to save

```bash
EVIDENCE_DIR="/tmp/jsa-evidence/etcd-encryption-$(date +%Y%m%d)"
mkdir -p "$EVIDENCE_DIR"

kubectl get pod -n kube-system -l component=kube-apiserver \
    -o jsonpath='{.items[0].spec.containers[0].command}' \
    > "${EVIDENCE_DIR}/apiserver-flags.json"

kubectl get secrets -A --no-headers \
    | wc -l \
    > "${EVIDENCE_DIR}/secret-count.txt"

echo "Evidence: ${EVIDENCE_DIR}"
```

---

## Layer 2: Database Encryption

### PostgreSQL

```bash
# SSL/TLS status
psql -h localhost -U postgres -c "SHOW ssl;"
# PASS: on   FAIL: off

# Encryption settings
psql -h localhost -U postgres -c "
SELECT name, setting, unit, short_desc
FROM pg_settings
WHERE name IN ('ssl', 'ssl_ca_file', 'ssl_cert_file', 'ssl_key_file',
               'ssl_ciphers', 'ssl_min_protocol_version')
ORDER BY name;
"
# Look for ssl_min_protocol_version: TLSv1.2+
# Look for ssl_ciphers: not RC4, not MD5

# Data directory (for LUKS coverage verification)
psql -h localhost -U postgres -c "SHOW data_directory;"
# Example: /var/lib/postgresql/14/main
# Verify this path is on an encrypted volume (see Disk Encryption section below)

# Column encryption check (application-level)
# If PII/PHI is stored, look for pgcrypto usage
psql -h localhost -U postgres -c "
SELECT table_name, column_name
FROM information_schema.columns
WHERE table_schema = 'public'
AND column_name ILIKE '%ssn%'
OR column_name ILIKE '%dob%'
OR column_name ILIKE '%credit_card%';
"
# If found: verify application encrypts before insert (pgcrypto or app-layer AES)
```

### MySQL / MariaDB

```bash
# Check SSL
mysql -u root -p -e "SHOW VARIABLES LIKE '%ssl%';"
# PASS: ssl_cipher is set, have_ssl = YES

# Check tablespace encryption (MySQL 8.0+)
mysql -u root -p -e "
SELECT SCHEMA_NAME, DEFAULT_ENCRYPTION
FROM information_schema.SCHEMATA;
"
# PASS: DEFAULT_ENCRYPTION = YES for sensitive databases
```

---

## Layer 3: Disk Encryption

### Linux: LUKS

```bash
# List all block devices and their encryption status
lsblk -o NAME,TYPE,FSTYPE,SIZE,MOUNTPOINT | grep -E "disk|part|crypt|lvm"

# Check if OS disk is LUKS-encrypted
sudo cryptsetup isLuks /dev/sda
echo $?  # 0 = LUKS, 1 = not LUKS

# Get LUKS header info
sudo cryptsetup luksDump /dev/sda
# Look for: Cipher: aes-xts-plain64, Key Size: 512
# FAIL: if Cipher is des or 3des (should not appear in modern systems)
# WARN: if Key Size is 256 (AES-128) rather than 512 (AES-256)

# Check active encrypted device mappings
dmsetup ls --target crypt
# Each line = an active LUKS device

# Verify encryption is active on the data volume
cryptsetup status /dev/mapper/data
# Shows: cipher, keysize, iv, sector size
```

### Windows: BitLocker

```powershell
# Check all volumes
Get-BitLockerVolume | Select-Object MountPoint, EncryptionMethod, EncryptionPercentage, VolumeStatus, ProtectionStatus

# Detailed check on C:
manage-bde -status C:
# Look for: Protection Status: Protection On
#           Encryption Method: XTS-AES 256  (not AES-CBC 128)
#           Key Protectors: TPM + Recovery Password

# Check if XTS-AES-256 (required for FedRAMP)
Get-BitLockerVolume -MountPoint "C:" | Select-Object EncryptionMethod
# PASS: XtsAes256
# WARN: Aes128 or Aes256 (older mode, acceptable for non-federal)
# FAIL: None or Unknown

# Get recovery key info (verify it is backed up — SC-12)
manage-bde -protectors -get C:
# Should show: Recovery Password with ID
# Verify this ID exists in Azure AD or AD DS
```

---

## Layer 4: Cloud Storage Encryption

### Azure Storage

```bash
# List all storage accounts and encryption status
az storage account list \
    --query "[].{name:name, rg:resourceGroup, encryption:encryption}" \
    -o json | python3 -c "
import json,sys
accounts = json.load(sys.stdin)
for a in accounts:
    enc = a.get('encryption', {})
    svcs = enc.get('services', {})
    blob_on = svcs.get('blob', {}).get('enabled', False)
    key_src = enc.get('keySource', 'unknown')
    print(f\"{a['name']}: blob={blob_on}, keySource={key_src}\")
    if key_src == 'Microsoft.Storage':
        print(f'  WARN: Platform-managed key. Consider BYOK with Azure Key Vault.')
    elif key_src == 'Microsoft.Keyvault':
        print(f'  PASS: Customer-managed key (BYOK) — SC-12 compliant.')
"

# Check managed disk encryption on VMs
az vm list \
    --query "[].{name:name, rg:resourceGroup}" -o json \
    | python3 -c "
import json,sys,subprocess
vms = json.load(sys.stdin)
for vm in vms[:5]:  # first 5
    result = subprocess.run(
        ['az','vm','encryption','show',
         '--name', vm['name'], '--resource-group', vm['rg'], '-o', 'json'],
        capture_output=True, text=True)
    if result.returncode == 0:
        enc = json.loads(result.stdout)
        disks = enc.get('disks', [{}])
        status = disks[0].get('statuses', [{}])[0].get('message', 'unknown')
        print(f\"{vm['name']}: {status}\")
    else:
        print(f\"{vm['name']}: encryption status not available\")
"
```

### AWS (for reference)

```bash
# Check EBS volume encryption
aws ec2 describe-volumes \
    --query "Volumes[*].{id:VolumeId, encrypted:Encrypted, kmsKey:KmsKeyId}" \
    --output table
# PASS: encrypted = True for all volumes with sensitive data

# Check S3 bucket encryption
aws s3api list-buckets --query "Buckets[*].Name" --output text \
    | tr '\t' '\n' \
    | while read bucket; do
        STATUS=$(aws s3api get-bucket-encryption --bucket "$bucket" 2>/dev/null \
            | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['ServerSideEncryptionConfiguration']['Rules'][0]['ApplyServerSideEncryptionByDefault']['SSEAlgorithm'])" \
            2>/dev/null || echo "NOT_SET")
        echo "$bucket: $STATUS"
    done
```

---

## Evidence Archive Structure

```
/tmp/jsa-evidence/encryption-audit-YYYYMMDD/
├── etcd/
│   ├── apiserver-flags.json      ← kube-apiserver command flags
│   ├── encryption-config.yaml    ← EncryptionConfiguration contents
│   └── etcd-spot-check.txt       ← hexdump of a sample secret in etcd
├── database/
│   ├── postgres-ssl-settings.txt ← SSL configuration values
│   └── data-directory.txt        ← path for LUKS coverage check
├── disk/
│   ├── lsblk-output.json         ← block device listing
│   ├── luks-dump.txt             ← cryptsetup luksDump output
│   └── bitlocker-status.txt      ← manage-bde or Get-BitLockerVolume
└── cloud/
    ├── azure-storage-accounts.json
    └── azure-vm-encryption.json
```

Save all evidence to this structure for auditor review.
