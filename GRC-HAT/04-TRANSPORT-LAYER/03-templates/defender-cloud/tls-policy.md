# tls-policy.md — Microsoft Defender for Cloud TLS Recommendations

**NIST Controls:** SC-8, SC-13, IA-5
**Platform:** Azure (App Service, SQL, Storage, AKS)
**Tools:** Azure Portal, az CLI, PowerShell Az module

---

## Overview

Defender for Cloud surfaces TLS misconfigurations as Security Recommendations. This guide covers the
standard Azure TLS enforcement settings and the CLI commands to apply them at scale. These settings
map to the same NIST controls as the open-source TLS hardening — SC-8 (confidentiality in transit)
and SC-13 (cryptographic mechanisms).

---

## 1. Azure App Service — Minimum TLS Version

**Defender for Cloud Recommendation:** "App Service apps should use the latest TLS version"

### Why
App Services default to TLS 1.0 for backwards compatibility. SC-8 requires TLS 1.2 minimum.
Older TLS versions have known vulnerabilities (POODLE, BEAST) that break transmission confidentiality.

### Azure Portal
1. App Service → Configuration → General settings
2. Set **Minimum TLS Version** to **1.2**
3. Enable **HTTPS Only** toggle
4. Save

### az CLI (single app)
```bash
az webapp config set \
  --name myapp \
  --resource-group myRG \
  --min-tls-version 1.2 \
  --ftps-state Disabled \
  --https-only true
```

### az CLI (all apps in subscription)
```bash
az webapp list --query "[].{name:name, rg:resourceGroup}" -o tsv | \
while IFS=$'\t' read -r APP_NAME RG; do
    az webapp config set \
        --name "$APP_NAME" \
        --resource-group "$RG" \
        --min-tls-version 1.2 \
        --ftps-state Disabled \
        --https-only true
    echo "Updated: $APP_NAME"
done
```

### PowerShell
```powershell
$apps = Get-AzWebApp
foreach ($app in $apps) {
    $config = Get-AzWebAppConfiguration -ResourceGroupName $app.ResourceGroup -Name $app.Name
    $config.MinTlsVersion = "1.2"
    $config.HttpsOnly = $true
    Set-AzWebAppConfiguration -ResourceGroupName $app.ResourceGroup -Name $app.Name -WebAppConfiguration $config
    Write-Host "[PASS] $($app.Name): TLS 1.2 minimum enforced"
}
```

---

## 2. Azure SQL Database — Encrypted Connections

**Defender for Cloud Recommendation:** "SQL databases should have an Azure Defender for SQL enabled"
**Relevant Setting:** "Minimal TLS Version" and "Require Secure Connection"

### Why
SQL over unencrypted connections exposes query data and credentials in transit. SC-8 requires
encryption for all sensitive data in transit, including database connections.

### az CLI
```bash
# Set minimum TLS 1.2 on SQL Server
az sql server update \
  --name mySqlServer \
  --resource-group myRG \
  --minimal-tls-version "1.2"

# Verify
az sql server show \
  --name mySqlServer \
  --resource-group myRG \
  --query "minimalTlsVersion"
```

### PowerShell
```powershell
# Get all SQL servers and enforce TLS 1.2
$sqlServers = Get-AzSqlServer
foreach ($server in $sqlServers) {
    Set-AzSqlServer `
        -ServerName $server.ServerName `
        -ResourceGroupName $server.ResourceGroupName `
        -MinimalTlsVersion "1.2"
    Write-Host "[PASS] SQL Server $($server.ServerName): TLS 1.2 minimum enforced"
}
```

### Verify connection encryption (from SQL client)
```sql
SELECT session_id, encrypt_option, auth_scheme
FROM sys.dm_exec_connections
WHERE session_id = @@SPID;
-- encrypt_option should be TRUE
```

---

## 3. Azure Storage — Require Secure Transfer

**Defender for Cloud Recommendation:** "Secure transfer to storage accounts should be enabled"

### Why
Storage accounts accept HTTP and HTTPS by default. SC-8 requires all data in transit to be encrypted.
Enabling "Secure Transfer Required" blocks all HTTP requests to the storage account.

### Azure Portal
1. Storage Account → Configuration
2. Set **Secure transfer required** to **Enabled**
3. Set **Minimum TLS version** to **TLS 1.2**
4. Save

### az CLI
```bash
# Enable secure transfer and set minimum TLS
az storage account update \
  --name mystorageaccount \
  --resource-group myRG \
  --https-only true \
  --min-tls-version TLS1_2

# Bulk enforcement across subscription
az storage account list --query "[].{name:name, rg:resourceGroup}" -o tsv | \
while IFS=$'\t' read -r ACCT RG; do
    az storage account update \
        --name "$ACCT" \
        --resource-group "$RG" \
        --https-only true \
        --min-tls-version TLS1_2
    echo "[PASS] $ACCT: secure transfer + TLS 1.2 enforced"
done
```

### PowerShell
```powershell
$accounts = Get-AzStorageAccount
foreach ($acct in $accounts) {
    Set-AzStorageAccount `
        -Name $acct.StorageAccountName `
        -ResourceGroupName $acct.ResourceGroupName `
        -EnableHttpsTrafficOnly $true `
        -MinimumTlsVersion TLS1_2
    Write-Host "[PASS] $($acct.StorageAccountName): HTTPS-only + TLS 1.2"
}
```

---

## 4. Defender for Cloud — Reviewing TLS Recommendations

### Find all TLS-related recommendations
```bash
# List all active recommendations related to TLS/SSL
az security assessment list \
  --query "[?contains(displayName,'TLS') || contains(displayName,'SSL') || contains(displayName,'secure transfer')].{name:displayName, status:status.code, severity:metadata.severity}" \
  -o table
```

### Get recommendation details
```bash
# Drill into a specific recommendation
az security assessment show \
  --name "AppServiceHttps" \
  --query "{status:status, description:metadata.description, remediationDescription:metadata.remediationDescription}"
```

### Export TLS findings for evidence
```bash
# Export all HIGH severity TLS findings for audit evidence
az security assessment list \
  --query "[?metadata.severity=='High' && (contains(displayName,'TLS') || contains(displayName,'SSL'))].{resource:resourceDetails.id, recommendation:displayName, status:status.code}" \
  -o json > /tmp/jsa-evidence/defender-tls-findings-$(date +%Y%m%d).json

echo "Defender TLS findings exported for audit evidence"
```

---

## 5. AKS — TLS for Ingress and API Server

### AKS API Server TLS (managed by Azure)
The AKS API server enforces TLS 1.2+ by default. Verify via:
```bash
az aks show --name myCluster --resource-group myRG \
  --query "apiServerAccessProfile"
```

### AKS Ingress TLS
For applications deployed on AKS, use cert-manager for automatic TLS:
- See `03-templates/cert-manager/clusterissuer.yaml`
- See `03-templates/cert-manager/certificate.yaml`

### AKS + Defender for Containers
```bash
# Enable Defender for Containers (includes TLS/network policy recommendations)
az aks update \
  --name myCluster \
  --resource-group myRG \
  --enable-defender
```

---

## 6. Azure Policy — Enforce TLS at Scale

Deploy Azure Policy to prevent non-compliant resources from being created:

```bash
# Assign built-in policy: "App Service apps should use the latest TLS version"
az policy assignment create \
  --name "require-tls12-appservice" \
  --scope "/subscriptions/$(az account show --query id -o tsv)" \
  --policy "/providers/Microsoft.Authorization/policyDefinitions/f0e6e85b-9b9f-4a4b-b67b-f730d42f1b0b" \
  --enforcement-mode Default

# Assign built-in policy: "Secure transfer to storage accounts should be enabled"
az policy assignment create \
  --name "require-secure-transfer-storage" \
  --scope "/subscriptions/$(az account show --query id -o tsv)" \
  --policy "/providers/Microsoft.Authorization/policyDefinitions/404c3081-a854-4457-ae30-26a93ef643f9" \
  --enforcement-mode Default
```

---

## Open Source vs Defender for Cloud Comparison

| Capability | Open Source | Defender for Cloud |
|---|---|---|
| TLS cipher check | testssl.sh (free) | Not built-in |
| Cert expiry alert | cert-manager (free) | Limited (App Service only) |
| Azure resource TLS | az CLI (free) | Built-in recommendations |
| CSPM TLS posture | Manual | Full (all Azure resources) |
| Cost | Free | Included in Defender for Cloud pricing |

**When to use Defender for Cloud:** Full Azure estate TLS posture management, Azure Policy enforcement, compliance reporting against CIS/NIST benchmarks.

**When to use open source:** Deep TLS cipher analysis, Kubernetes/on-prem cert management, CI gate integration, air-gapped environments.
