# 02-fix-SC28-encryption.md — Enable Encryption at Rest (SC-28)

| Field | Value |
|---|---|
| **NIST Controls** | SC-28 (protection of information at rest), SC-28(1) (cryptographic protection) |
| **Prerequisite** | `01a-encryption-audit.md` completed — specific gaps identified |
| **Scripts** | `02-fixers/fix-etcd-encryption.sh`, `02-fixers/fix-bitlocker-enforcement.md` |
| **Time** | 30 min (etcd) to 2 hours (full disk encryption rollout) |
| **Rank** | D for etcd (scripted), C for disk encryption rollout (fleet decision) |

---

## Fix 1: Enable K8s etcd Encryption at Rest

**Risk:** K8s Secrets stored as readable base64 in etcd. Anyone with etcd access reads all credentials.

**Fix:** Deploy EncryptionConfiguration with aescbc provider.

```bash
# Dry-run first — verify what will change
./02-fixers/fix-etcd-encryption.sh --dry-run
# Review the preview at /tmp/jsa-evidence/etcd-encryption-fix-*/encryption-config-preview.yaml

# Apply on control plane node
sudo ./02-fixers/fix-etcd-encryption.sh

# Wait for API server restart (60-90 seconds)
kubectl wait --for=condition=Ready pod -l component=kube-apiserver -n kube-system --timeout=120s

# Re-encrypt all existing secrets
kubectl get secrets --all-namespaces -o json | kubectl replace -f -

# Verify: check etcd directly (on control plane)
ETCDCTL_API=3 etcdctl get /registry/secrets/default/<any-secret-name> \
    --endpoints=https://127.0.0.1:2379 \
    --cacert=/etc/kubernetes/pki/etcd/ca.crt \
    --cert=/etc/kubernetes/pki/etcd/server.crt \
    --key=/etc/kubernetes/pki/etcd/server.key \
    | hexdump -C | head -2
# PASS: 6b 38 73 3a 65 6e 63 3a ('k8s:enc:')
```

**Use the template:**

```bash
# The template at 03-templates/k8s/encryption-config.yaml shows the structure.
# Replace REPLACE_WITH_BASE64_32BYTE_KEY with your generated key:
openssl rand -base64 32
# Store the key in HashiCorp Vault or Azure Key Vault — not in git
```

**Post-fix: Remove identity fallback**

After all secrets are re-encrypted, remove the `identity: {}` provider from encryption-config.yaml. This prevents unencrypted reads of secrets if the encryption layer is bypassed.

```bash
# Verify all secrets are re-encrypted before removing identity{}
# Check: no secrets in etcd start with 'k8s:' without 'enc:' prefix
ETCDCTL_API=3 etcdctl get /registry/secrets/ --prefix --keys-only \
    --endpoints=https://127.0.0.1:2379 \
    --cacert=/etc/kubernetes/pki/etcd/ca.crt \
    --cert=/etc/kubernetes/pki/etcd/server.crt \
    --key=/etc/kubernetes/pki/etcd/server.key \
    | while read key; do
        RAW=$(ETCDCTL_API=3 etcdctl get "$key" \
            --endpoints=https://127.0.0.1:2379 \
            --cacert=/etc/kubernetes/pki/etcd/ca.crt \
            --cert=/etc/kubernetes/pki/etcd/server.crt \
            --key=/etc/kubernetes/pki/etcd/server.key 2>/dev/null | head -1)
        if ! echo "$RAW" | grep -q "k8s:enc:"; then
            echo "NOT ENCRYPTED: $key"
        fi
    done
# If output is empty: all secrets are encrypted. Safe to remove identity{}.
```

---

## Fix 2: Enable Disk Encryption (Linux)

**Risk:** Physical access to server = access to all data on disk.

**Fix:** Enable LUKS on data volumes.

```bash
# IMPORTANT: LUKS encrypts the device. Data must be backed up first.
# Never run luksFormat on a volume with live data — it destroys existing content.

# Step 1: Identify unencrypted volumes
lsblk -o NAME,TYPE,FSTYPE,MOUNTPOINT,SIZE

# Step 2: For a NEW data disk (no existing data):
sudo cryptsetup luksFormat \
    --type luks2 \
    --cipher aes-xts-plain64 \
    --key-size 512 \
    --hash sha256 \
    /dev/sdX
# Passphrase is the primary key — store in HashiCorp Vault or Azure Key Vault

# Step 3: Open and format
sudo cryptsetup luksOpen /dev/sdX data_encrypted
sudo mkfs.ext4 -L data /dev/mapper/data_encrypted
sudo mount /dev/mapper/data_encrypted /mnt/data

# Step 4: Add recovery key slot (SC-12 compliance — backup key)
sudo cryptsetup luksAddKey /dev/sdX
# New passphrase = recovery key stored separately

# Step 5: Auto-mount on boot via /etc/crypttab
echo "data_encrypted /dev/sdX none luks" | sudo tee -a /etc/crypttab
echo "/dev/mapper/data_encrypted /mnt/data ext4 defaults 0 2" | sudo tee -a /etc/fstab

# Verify
sudo cryptsetup status data_encrypted
# cipher: aes-xts-plain64, keysize: 512 bits — SC-13 compliant
```

**For existing data volumes (migrate in place):**

Encryption cannot be added to a live volume without data migration. Process:
1. Create new encrypted volume
2. `rsync -a --delete /data/ /mnt/data_new/` (with services stopped)
3. Verify data integrity with checksums
4. Switch mount points
5. Erase old volume with `shred -u`

---

## Fix 3: Enable Disk Encryption (Windows / BitLocker)

See `02-fixers/fix-bitlocker-enforcement.md` for full instructions including PowerShell, GPO, Intune, and Azure Disk Encryption methods.

**Quick path for a single machine:**

```powershell
# Enable with XTS-AES-256 + TPM + recovery key
Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAes256 -TpmProtector -UsedSpaceOnly
Add-BitLockerKeyProtector -MountPoint "C:" -RecoveryPasswordProtector
BackupToAAD-BitLockerKeyProtector -MountPoint "C:" `
    -KeyProtectorId (Get-BitLockerVolume -MountPoint "C:").KeyProtector[0].KeyProtectorId

# Verify
Get-BitLockerVolume -MountPoint "C:" | Select-Object ProtectionStatus, EncryptionMethod
```

---

## Fix 4: Migrate ConfigMap Secrets to K8s Secrets

**Risk:** ConfigMaps are plaintext in etcd. Even with etcd encryption enabled for `secrets`, ConfigMaps are not encrypted by default.

```bash
# Dry-run: see what would be migrated
./02-fixers/fix-plaintext-secrets.sh --dry-run

# Apply to a specific namespace
./02-fixers/fix-plaintext-secrets.sh --namespace production

# Apply cluster-wide
./02-fixers/fix-plaintext-secrets.sh

# After script runs, update Deployment envFrom:
# REMOVE: configMapRef: { name: app-config }
# ADD:    secretRef:    { name: app-config-secrets }
```

---

## Dual-Stack Reference

| Scenario | Microsoft Stack | Open-Source Stack |
|---|---|---|
| K8s secret encryption | AKS built-in KMS (Azure Key Vault) | EncryptionConfiguration + aescbc/KMS |
| Disk encryption | BitLocker (XTS-AES-256) | LUKS2 (aes-xts-plain64) |
| Database | Azure SQL TDE | PostgreSQL SSL + LUKS on data dir |
| Cloud storage | Azure Storage encryption + BYOK | MinIO + LUKS |
| Secret lifecycle | Azure Key Vault + ESO | HashiCorp Vault + ESO |
| Key management | Azure Key Vault (HSM-backed) | HashiCorp Vault Enterprise or PKCS#11 HSM |

---

## Verification

After applying fixes, re-run the encryption auditor:

```bash
./01-auditors/audit-encryption-at-rest.sh
# All previous [FAIL] items should now be [PASS]

# Save evidence
ls /tmp/jsa-evidence/encryption-at-rest-*/
```

Move to `03-validate.md` to run the full validation suite.
