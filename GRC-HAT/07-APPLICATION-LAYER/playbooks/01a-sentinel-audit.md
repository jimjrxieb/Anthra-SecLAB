# 01a-sentinel-audit.md — Microsoft Sentinel Deep-Dive Audit

| Field | Value |
|---|---|
| **NIST Controls** | AU-6 (audit review), SI-4 (monitoring), AU-2 (event logging), AU-11 (audit retention) |
| **Tools** | az CLI / Microsoft Sentinel / KQL |
| **Enterprise Equiv** | Splunk ES ($500K+) / IBM QRadar ($400K+) |
| **CySA+ Note** | DEFAULT SIEM audit for Microsoft-stack environments |
| **Time** | 45 minutes |
| **Rank** | D (read-only audit — no changes) |

---

## Purpose

This is the CySA+ default SIEM audit playbook for Microsoft environments. If the client runs Azure, M365, or has Azure AD — this is your SIEM. Sentinel integrates natively with Azure AD, Office 365, Defender, and Azure resources. You get 90 days free retention on most tables.

Run this before `02-fix-AU6-alert-rules.md`. Establish what exists before you add to it.

---

## Pre-Requisites

```bash
# Set environment variables before running any commands
export SENTINEL_WORKSPACE="your-workspace-name"
export SENTINEL_RG="your-resource-group"
export AZURE_SUBSCRIPTION_ID="your-subscription-id"

# Verify login
az account show --query '{subscription:id, user:user.name}'
```

Required permissions: **Microsoft Sentinel Reader** at minimum (Contributor to create rules)

---

## 1. Workspace Health and Data Ingestion

```bash
# Workspace status
az monitor log-analytics workspace show \
  --workspace-name "$SENTINEL_WORKSPACE" \
  --resource-group "$SENTINEL_RG" \
  --query '{state:provisioningState, retention:retentionInDays, sku:sku.name, dailyCap:workspaceCapping.dailyQuotaGb}'

# Top data tables by volume (last 24 hours)
az monitor log-analytics query \
  --workspace-name "$SENTINEL_WORKSPACE" \
  --resource-group "$SENTINEL_RG" \
  --analytics-query "
union withsource=TableName *
| where TimeGenerated > ago(24h)
| summarize RecordCount=count(), SizeMB=round(sum(_BilledSize)/1048576, 2)
    by TableName
| top 15 by RecordCount desc
"
```

**What to look for:**
- Tables with 0 records = missing connectors
- SigninLogs, SecurityEvent, AuditLogs — these must be present for basic coverage
- Total daily ingest approaching cap = retention/cost risk

---

## 2. Data Connector Status

```bash
# List all data connectors
az rest \
  --method GET \
  --url "https://management.azure.com/subscriptions/${AZURE_SUBSCRIPTION_ID}/resourceGroups/${SENTINEL_RG}/providers/Microsoft.OperationalInsights/workspaces/${SENTINEL_WORKSPACE}/providers/Microsoft.SecurityInsights/dataConnectors?api-version=2022-11-01" \
  --query "value[].{Kind:kind, Status:properties.dataTypes.alerts.state}" \
  --output table
```

**Required connectors for minimum coverage:**

| Connector | Tables Populated | Required? |
|---|---|---|
| Azure Active Directory | SigninLogs, AuditLogs | Yes — all environments |
| Azure Activity | AzureActivity | Yes — any Azure resource |
| Microsoft 365 | OfficeActivity | Yes — M365 environments |
| Microsoft Defender for Endpoint | SecurityAlert, DeviceEvents | Yes — if MDE deployed |
| Windows Security Events via AMA | SecurityEvent | Yes — Windows hosts |
| Syslog via AMA | Syslog | Yes — Linux hosts |

```bash
# Check specifically for AAD connector (most important)
az monitor log-analytics query \
  --workspace-name "$SENTINEL_WORKSPACE" \
  --resource-group "$SENTINEL_RG" \
  --analytics-query "
SigninLogs
| where TimeGenerated > ago(1h)
| take 1
| project TimeGenerated, UserPrincipalName, ResultType, IPAddress
"
# If this returns 0 rows → AAD connector not connected or no sign-ins in last hour
```

---

## 3. Analytics Rule Review

```bash
# Count active vs disabled rules
az rest \
  --method GET \
  --url "https://management.azure.com/subscriptions/${AZURE_SUBSCRIPTION_ID}/resourceGroups/${SENTINEL_RG}/providers/Microsoft.OperationalInsights/workspaces/${SENTINEL_WORKSPACE}/providers/Microsoft.SecurityInsights/alertRules?api-version=2022-11-01" \
  --query "value[].{Name:properties.displayName, Enabled:properties.enabled, Severity:properties.severity, Kind:kind}" \
  --output table
```

**Coverage gap check — run this KQL:**

```kql
// Coverage: which MITRE tactics have detection rules?
// AU-6 requirement: detection across key threat categories
SecurityAlert
| where TimeGenerated > ago(7d)
| extend Tactics = parse_json(tostring(Entities))
| summarize AlertCount = count(), UniqueRules = dcount(AlertName)
    by bin(TimeGenerated, 1d)
| render timechart
```

**Required detection categories (minimum viable coverage):**
- Credential Access (T1110 brute force, T1078 valid accounts)
- Privilege Escalation (T1548 role assignment, T1098 account manipulation)
- Discovery (T1069 permission groups, T1082 system info)
- Lateral Movement (T1021 remote services)
- Exfiltration (T1048 exfil over alternative protocol)

---

## 4. Incident Queue Health

```bash
# Open incidents by severity
az rest \
  --method GET \
  --url "https://management.azure.com/subscriptions/${AZURE_SUBSCRIPTION_ID}/resourceGroups/${SENTINEL_RG}/providers/Microsoft.OperationalInsights/workspaces/${SENTINEL_WORKSPACE}/providers/Microsoft.SecurityInsights/incidents?api-version=2022-11-01&\$filter=properties/status ne 'Closed'" \
  --query "value[].{Title:properties.title, Severity:properties.severity, Status:properties.status, Created:properties.createdTimeUtc, Owner:properties.owner.assignedTo}" \
  --output table
```

```kql
// MTTD and MTTR calculation
// AU-6: Audit review effectiveness metric
SecurityIncident
| where TimeGenerated > ago(30d)
| where Status == "Closed"
| extend
    MTTD_hours = datetime_diff('hour', CreatedTime, FirstActivityTime),
    MTTR_hours = datetime_diff('hour', ClosedTime, CreatedTime)
| summarize
    Avg_MTTD  = avg(MTTD_hours),
    Avg_MTTR  = avg(MTTR_hours),
    P90_MTTD  = percentile(MTTD_hours, 90),
    Total     = count()
```

**MTTD benchmarks:**
- < 1 hour = Excellent
- 1–8 hours = Good
- 8–24 hours = Acceptable
- > 24 hours = Finding

---

## 5. Workbook and Dashboard Availability

```bash
# List deployed workbooks
az rest \
  --method GET \
  --url "https://management.azure.com/subscriptions/${AZURE_SUBSCRIPTION_ID}/resourceGroups/${SENTINEL_RG}/providers/microsoft.insights/workbooks?api-version=2022-04-01&category=sentinel" \
  --query "value[].{Name:name, DisplayName:properties.displayName}" \
  --output table
```

**Required workbooks for SOC operations:**
- Azure Activity — cloud control plane visibility
- Azure AD Audit Logs — identity events
- Security Alerts — alert triage view
- SOC Overview (custom — see `03-templates/sentinel/workbook-soc-overview.json`)

---

## 6. Retention Policy Compliance Check

```bash
# Current retention setting
az monitor log-analytics workspace show \
  --workspace-name "$SENTINEL_WORKSPACE" \
  --resource-group "$SENTINEL_RG" \
  --query '{retentionInDays:retentionInDays, sku:sku.name}'

# Compliance requirements:
# HIPAA: 2190 days (6 years)
# FedRAMP: 1095 days (3 years)  
# PCI-DSS: 365 days (1 year)
# SOC 2: 365 days (1 year)
# NIST AU-11 baseline: 365 days

# Update retention (example: set to 365 days)
# az monitor log-analytics workspace update \
#   --workspace-name "$SENTINEL_WORKSPACE" \
#   --resource-group "$SENTINEL_RG" \
#   --retention-time 365
```

---

## Audit Checklist Summary

| Check | Tool | Pass Criteria |
|---|---|---|
| Workspace health | az CLI | provisioningState = Succeeded |
| Active data connectors | az REST | SigninLogs, SecurityEvent, AuditLogs populated |
| Analytics rules > 10 | az REST | ≥10 enabled rules |
| Critical detections present | KQL | Brute force + priv escalation rules exist |
| Open High/Critical incidents | az REST | < 5 unassigned High incidents |
| MTTD < 24 hours | KQL | Average MTTD under 24 hours |
| Retention ≥ 90 days | az CLI | retentionInDays ≥ 90 (365 for compliance) |

---

## Run Automated Audit

```bash
./01-auditors/audit-siem-ingest.sh --sentinel-only
./01-auditors/audit-alert-rules.sh --sentinel-only
./01-auditors/audit-log-retention.sh --sentinel-only
```

---

## If You Find Gaps

- Missing connectors → `02-fixers/fix-missing-log-source.sh --sentinel`
- Missing alert rules → `02-fixers/fix-sentinel-analytics-rule.md`
- Low retention → Update workspace retention setting (az CLI command above)
- No incidents created → Check Analytics > Active rules for scheduling issues
