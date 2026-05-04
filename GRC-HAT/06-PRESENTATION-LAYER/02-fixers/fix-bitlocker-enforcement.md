# fix-bitlocker-enforcement.md — BitLocker Encryption Enforcement

| Field | Value |
|---|---|
| **NIST Controls** | SC-28 (protection of information at rest), SC-28(1) (cryptographic protection) |
| **CySA+ Domain** | Identity and Access Management / Security Architecture |
| **Severity** | FAIL — unencrypted disk violates SC-28 |
| **Fix Time** | 30 minutes (PowerShell/Intune) to 24 hours (GPO rollout) |
| **Enterprise Equiv** | Microsoft BitLocker (included with Windows Pro/Enterprise), Azure Disk Encryption |

---

## Why This Matters

An unencrypted disk is a physical access vulnerability. If a laptop is lost or stolen, all data is readable without credentials. BitLocker ties encryption to the TPM chip and requires the correct hardware, PIN, or recovery key to decrypt.

**NIST SC-28(1):** Cryptographic protection must be implemented for data at rest. BitLocker with XTS-AES-256 satisfies this control. BitLocker with AES-128 does not meet FedRAMP Moderate requirements.

---

## Method 1: PowerShell (Manual, Single Machine)

```powershell
# WHY: XtsAes256 is required for FedRAMP Moderate/High (SC-28(1))
# AES-128 is insufficient for federal systems.
# -UsedSpaceOnly: encrypts only used space (faster initial encryption)
# -RecoveryPasswordProtector: creates 48-digit recovery key (required for SC-12)

# Check current BitLocker status first
Get-BitLockerVolume -MountPoint "C:"

# Enable BitLocker with XTS-AES-256 and TPM + recovery key
Enable-BitLocker `
    -MountPoint "C:" `
    -EncryptionMethod XtsAes256 `
    -UsedSpaceOnly `
    -TpmProtector

# Add recovery password (required — audit evidence)
Add-BitLockerKeyProtector `
    -MountPoint "C:" `
    -RecoveryPasswordProtector

# Get the recovery key (SAVE THIS — store in Azure AD, Intune, or print for safe storage)
(Get-BitLockerVolume -MountPoint "C:").KeyProtector | Where-Object {$_.KeyProtectorType -eq "RecoveryPassword"}

# Back up recovery key to Azure AD (if Azure AD joined)
BackupToAAD-BitLockerKeyProtector `
    -MountPoint "C:" `
    -KeyProtectorId (Get-BitLockerVolume -MountPoint "C:").KeyProtector[0].KeyProtectorId

# Verify status
Get-BitLockerVolume -MountPoint "C:" | Select-Object -Property EncryptionMethod, VolumeStatus, ProtectionStatus
# Expected: EncryptionMethod=XtsAes256, ProtectionStatus=On
```

**NIST annotation:** This procedure satisfies SC-28(1) (cryptographic protection of information at rest) using FIPS 140-3 validated AES-256. Recovery key backup satisfies SC-12 (cryptographic key management).

---

## Method 2: Group Policy (GPO — Domain-Joined Fleet)

**Path:** `Computer Configuration > Administrative Templates > Windows Components > BitLocker Drive Encryption > Operating System Drives`

### Required policy settings

| Policy | Setting | WHY |
|---|---|---|
| Require additional authentication at startup | Enabled | SC-28 — forces TPM verification |
| Allow BitLocker without a compatible TPM | Disabled | SC-28 — TPM required for hardware binding |
| Choose drive encryption method and cipher strength (Windows 10+) | XTS-AES 256-bit | SC-28(1) — AES-256 required |
| Choose how BitLocker-protected OS drives can be recovered | Enabled: AD recovery, 48-digit password | SC-12 — key management |
| Do not enable BitLocker until recovery information is stored to AD DS | Enabled | SC-12 — ensures recovery key exists before encryption |

### Recovery key storage

```
Computer Configuration > Admin Templates > Windows Components >
  BitLocker Drive Encryption > Store BitLocker recovery information in AD DS
```
- Enable: Store recovery passwords and key packages
- WHY: Recovery keys in AD = SC-12 compliance + audit trail

### Enforce via startup script

```powershell
# GPO Startup Script: enforce-bitlocker.ps1
# Runs at machine startup via GPO Computer Configuration > Scripts
$volume = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
if ($volume.ProtectionStatus -ne "On") {
    Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAes256 -TpmProtector -UsedSpaceOnly
    # Event log entry for SIEM
    Write-EventLog -LogName Security -Source "BitLockerEnforcement" -EventId 4688 `
        -Message "BitLocker enabled on C: — SC-28 compliance action"
}
```

---

## Method 3: Microsoft Intune (MDM — Modern Management)

### Create a Disk Encryption Policy

1. **Intune portal** → Endpoint Security → Disk Encryption → Create Policy
2. Platform: **Windows 10 and later**
3. Profile: **BitLocker**

### Key settings

```json
{
  "requireDeviceEncryption": true,
  "bitLockerFixedDrivePolicy": {
    "encryptionMethod": "xtsAes256",
    "requireEncryptionForWriteAccess": true,
    "recoveryOptions": {
      "recoveryPasswordUsage": "required",
      "recoveryKeyUsage": "allowed",
      "hideRecoveryOptions": false,
      "saveRecoveryInformationToAzureAD": true,
      "recoveryInformationToAzureAD": "backupRecoveryPasswordsAndKeyPackages",
      "blockDataRecoveryAgent": false
    }
  },
  "bitLockerSystemDrivePolicy": {
    "encryptionMethod": "xtsAes256",
    "startupAuthenticationRequired": true,
    "startupAuthenticationTpmUsage": "required",
    "startupAuthenticationTpmPinUsage": "allowed"
  }
}
```

### Monitor compliance

Intune → Reports → Endpoint Analytics → Device Compliance → BitLocker status

**NIST annotation:** Intune policy satisfies SC-28 (encryption at rest) and SC-12 (key management via Azure AD key escrow).

---

## Method 4: Azure Disk Encryption (IaaS VMs)

For Azure virtual machines (not physical endpoints):

```bash
# WHY: Azure Disk Encryption uses BitLocker (Windows) or DM-Crypt (Linux)
# with keys stored in Azure Key Vault — satisfies SC-28 + SC-12.

# Enable for Windows VM
az vm encryption enable \
    --resource-group <rg> \
    --name <vm-name> \
    --disk-encryption-keyvault <key-vault-name> \
    --volume-type All

# Verify
az vm encryption show \
    --resource-group <rg> \
    --name <vm-name> \
    --query "disks[].{name:name,status:statuses[0].message}"

# Expected: "EncryptionState": "Encrypted"
```

**NIST annotation:** Azure Disk Encryption with Key Vault key management satisfies SC-28 (encryption at rest) and SC-12 (FIPS 140-2 validated keys in HSM-backed Key Vault Premium).

---

## Recovery Key Management (SC-12 Compliance)

**Never** store recovery keys only on the encrypted drive. Options in priority order:

| Method | Use Case | SC-12 |
|---|---|---|
| Azure AD / Intune escrow | Cloud-joined Windows devices | Satisfies SC-12 — auditable, recoverable |
| Azure Key Vault | Server/VM recovery keys | Satisfies SC-12 — HSM-backed, access-controlled |
| AD DS escrow (GPO) | Domain-joined on-prem fleet | Satisfies SC-12 — AD access controls apply |
| Printed + locked safe | Air-gap / offline systems | Satisfies SC-12 — physical control required |

**Never:** email, Teams messages, sticky notes, unencrypted files, or shared network drives.

---

## Audit Commands

```powershell
# Check ALL drives on all domain computers (PowerShell remoting)
Invoke-Command -ComputerName (Get-ADComputer -Filter *).Name -ScriptBlock {
    Get-BitLockerVolume | Select-Object ComputerName, MountPoint,
        EncryptionMethod, VolumeStatus, ProtectionStatus
} | Export-Csv bitlocker-fleet-audit.csv -NoTypeInformation

# Check specific machine
manage-bde -status C:
manage-bde -protectors -get C:

# SIEM query (for Splunk — BitLocker events)
# index=windows EventCode=4616 OR EventCode=4688
# | search "BitLocker" OR "encryption enabled"
```

---

## LUKS Equivalent (Linux / Open Source)

```bash
# WHY: LUKS (Linux Unified Key Setup) is the Linux equivalent of BitLocker.
# dm-crypt + LUKS provides AES-256-XTS disk encryption.

# Create encrypted partition
sudo cryptsetup luksFormat --type luks2 --cipher aes-xts-plain64 \
    --key-size 512 --hash sha256 /dev/sdX

# Open (unlock) encrypted device
sudo cryptsetup luksOpen /dev/sdX encrypted_data

# Format and mount
sudo mkfs.ext4 /dev/mapper/encrypted_data
sudo mount /dev/mapper/encrypted_data /mnt/secure

# Add backup key slot (SC-12 — recovery key)
sudo cryptsetup luksAddKey /dev/sdX
# Enter new passphrase when prompted — store in Vault

# Verify encryption
sudo cryptsetup luksDump /dev/sdX
# Look for: Cipher: aes-xts-plain64, Key size: 512
```
