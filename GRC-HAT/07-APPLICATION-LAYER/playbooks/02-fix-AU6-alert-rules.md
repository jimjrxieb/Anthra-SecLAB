# 02-fix-AU6-alert-rules.md — Deploy Detection Rules (Dual SIEM)

| Field | Value |
|---|---|
| **NIST Controls** | AU-6 (audit review and analysis), SI-4 (information system monitoring) |
| **Tools** | az CLI + KQL (Sentinel) / Splunk REST API + SPL (Splunk) |
| **Fixes** | Missing alert rules, insufficient detection coverage, disabled correlation searches |
| **Time** | 30 minutes |
| **Rank** | D (deploy pre-validated templates — no custom decisions) |

---

## Purpose

`audit-alert-rules.sh` found missing detection coverage. This playbook deploys baseline detection rules using the templates in `03-templates/`. Pick your SIEM path — both cover the same threat categories.

---

## Dual SIEM Approach

| Capability | Sentinel Path | Splunk Path |
|---|---|---|
| Brute force detection | analytics-rule-brute-force.json | JSA-Failed-Login-Threshold (savedsearches.conf) |
| Privilege escalation | analytics-rule-priv-escalation.json | JSA-Privilege-Escalation |
| FIM alerts | Wazuh connector → Sentinel | JSA-File-Integrity-Change |
| Rare connections | Custom KQL rule | JSA-Rare-Outbound-Connection |
| K8s exec | Custom KQL rule | JSA-K8s-Exec-Production |

---

## Path A: Microsoft Sentinel

### Prerequisites

```bash
# Set environment
export SENTINEL_WORKSPACE="your-workspace"
export SENTINEL_RG="your-rg"
export AZURE_SUBSCRIPTION_ID="your-sub-id"

# Verify access
az role assignment list \
  --assignee "$(az ad signed-in-user show --query id -o tsv)" \
  --scope "/subscriptions/${AZURE_SUBSCRIPTION_ID}/resourceGroups/${SENTINEL_RG}" \
  --query "[].roleDefinitionName" --output tsv
# Need: Microsoft Sentinel Contributor
```

### Deploy Brute Force Rule

```bash
# Deploy via ARM template
az deployment group create \
  --resource-group "$SENTINEL_RG" \
  --template-file ../03-templates/sentinel/analytics-rule-brute-force.json \
  --parameters workspaceName="$SENTINEL_WORKSPACE" \
  --name "deploy-brute-force-rule-$(date +%Y%m%d)"
```

### Deploy Privilege Escalation Rule

```bash
az deployment group create \
  --resource-group "$SENTINEL_RG" \
  --template-file ../03-templates/sentinel/analytics-rule-priv-escalation.json \
  --parameters workspaceName="$SENTINEL_WORKSPACE" \
  --name "deploy-priv-escalation-rule-$(date +%Y%m%d)"
```

### Deploy SOC Overview Workbook

```bash
az deployment group create \
  --resource-group "$SENTINEL_RG" \
  --template-file ../03-templates/sentinel/workbook-soc-overview.json \
  --parameters workspaceName="$SENTINEL_WORKSPACE" \
  --name "deploy-soc-workbook-$(date +%Y%m%d)" 2>/dev/null || \
# If workbook template needs direct upload:
  echo "Upload workbook manually: Sentinel > Workbooks > Add workbook > Edit > </> > paste content"
```

### Verify Sentinel Deployment

```bash
# List all rules — confirm new ones appear
az rest \
  --method GET \
  --url "https://management.azure.com/subscriptions/${AZURE_SUBSCRIPTION_ID}/resourceGroups/${SENTINEL_RG}/providers/Microsoft.OperationalInsights/workspaces/${SENTINEL_WORKSPACE}/providers/Microsoft.SecurityInsights/alertRules?api-version=2022-11-01" \
  --query "value[?properties.enabled==\`true\`].{Name:properties.displayName, Severity:properties.severity}" \
  --output table

# Re-run audit to confirm findings resolved
../01-auditors/audit-alert-rules.sh --sentinel-only
```

### Manual Step-by-Step (Portal)

If ARM templates fail or you want to practice portal navigation:

1. Azure Portal → Microsoft Sentinel → your workspace
2. Left menu: **Configuration → Analytics → + Create → Scheduled query rule**
3. See detailed steps in `02-fixers/fix-sentinel-analytics-rule.md`

---

## Path B: Splunk

### Deploy via Script

```bash
# Set credentials
export SPLUNK_HOST="localhost"
export SPLUNK_PASS="yourpassword"

# Deploy all JSA searches from template
./02-fixers/fix-splunk-alert-rules.sh

# Verify deployment
./01-auditors/audit-alert-rules.sh --splunk-only
```

### Deploy Manually (REST API)

```bash
# Single search deployment
SPLUNK_HOST="${SPLUNK_HOST:-localhost}"
SPLUNK_PORT="8089"
SPLUNK_USER="admin"
SPLUNK_PASS="${SPLUNK_PASS:-}"

curl -sk -u "${SPLUNK_USER}:${SPLUNK_PASS}" \
  -X POST \
  "https://${SPLUNK_HOST}:${SPLUNK_PORT}/servicesNS/${SPLUNK_USER}/search/saved/searches" \
  --data-urlencode "name=JSA-Failed-Login-Threshold" \
  --data-urlencode "search=index=main (sourcetype=WinEventLog EventCode=4625) OR (sourcetype=linux_secure \"Failed password\") | stats count as FailedAttempts, values(user) as TargetAccounts by src_ip | where FailedAttempts > 5" \
  --data-urlencode "cron_schedule=*/5 * * * *" \
  --data-urlencode "is_scheduled=1" \
  --data-urlencode "disabled=0" \
  --data-urlencode "alert_type=number of events" \
  --data-urlencode "alert_comparator=greater than" \
  --data-urlencode "alert_threshold=0" \
  --data-urlencode "alert.severity=3"
```

### Deploy Full savedsearches.conf

```bash
# Direct file deployment (requires access to Splunk server)
docker cp ../03-templates/splunk/savedsearches.conf \
  splunk:/opt/splunk/etc/apps/search/local/savedsearches.conf

# Reload Splunk saved searches (no restart needed)
docker exec splunk /opt/splunk/bin/splunk reload saved-searches \
  -auth admin:"$SPLUNK_PASS"
```

---

## Evidence

After deployment, capture evidence for compliance:

```bash
# Sentinel
az rest \
  --method GET \
  --url "https://management.azure.com/subscriptions/${AZURE_SUBSCRIPTION_ID}/resourceGroups/${SENTINEL_RG}/providers/Microsoft.OperationalInsights/workspaces/${SENTINEL_WORKSPACE}/providers/Microsoft.SecurityInsights/alertRules?api-version=2022-11-01" \
  --output json > /tmp/jsa-evidence/sentinel-rules-after-$(date +%Y%m%d).json

# Splunk
curl -sk -u "${SPLUNK_USER}:${SPLUNK_PASS}" \
  "https://${SPLUNK_HOST}:8089/services/saved/searches?output_mode=json&count=0" \
  > /tmp/jsa-evidence/splunk-searches-after-$(date +%Y%m%d).json
```

---

## Validation

```bash
./tools/run-all-audits.sh --siem-only
```

Expected: audit-alert-rules.sh finding count should decrease or reach 0.

**Next step:** `03-validate.md`
