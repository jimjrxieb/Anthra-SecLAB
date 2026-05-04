# AU-11: Audit Record Retention
**Family:** Audit and Accountability
**NIST 800-53 Rev 5**
**Layer:** Application (L7)

## Control Statement
The organization retains audit records for a defined period to provide support for after-the-fact investigations of security incidents and to meet regulatory and organizational information retention requirements.

## Why It Matters at L7
Attackers with long dwell times — measured in months — can operate entirely within the gap between when logs are collected and when they are deleted. If retention is 30 days and dwell time is 45 days, the pre-breach activity is gone before the investigation starts. AU-11 establishes the minimum retention floor: 90 days hot (immediately queryable), one year cold (archive), and extended tiers for regulated environments. Retention is also a direct auditor ask — every FedRAMP, HIPAA, and PCI assessment will request a retention policy document and a configuration screenshot.

---

## GRC Analyst Perspective
> **No code access.** Tools: interviews, documentation review, SIEM dashboards, audit reports, evidence packages.

### Audit Questions
- Does the organization have a documented log retention policy, and does it differentiate retention requirements by data classification or regulatory framework?
- What is the current hot retention period (immediately queryable logs) in the primary SIEM, and how was that number determined?
- Does the organization maintain a cold or archive tier for logs beyond the hot retention window, and how long are archived logs retained?
- How are regulated data types (PHI for HIPAA, cardholder data for PCI, federal data for FedRAMP) mapped to specific retention requirements in the policy?
- Is the retention configuration reviewed periodically, and is there a process to detect if retention settings are changed without authorization?
- When the organization moves to a new SIEM platform or log management tool, how is retention continuity ensured for historical records?
- Has retention adequacy ever been tested — for example, by attempting to retrieve a log record from 90 days, 180 days, and 365 days ago?

### Evidence to Request
| Evidence Item | Source | Acceptable Format |
|---|---|---|
| Log retention policy document | Information Security or Legal | PDF or Word document with approval date and version |
| SIEM retention configuration screenshot or export | SIEM admin | Screenshot of Log Analytics workspace settings or Splunk index settings |
| Data classification matrix mapping data types to retention tiers | Information Security or Data Governance | Spreadsheet or policy document |
| Archive/cold storage configuration (S3, Azure Archive, or equivalent) | Cloud or Infrastructure team | Console screenshot or IaC configuration |
| Retention compliance check report (showing configured vs required days) | Security Engineering or SIEM admin | Script output, dashboard screenshot, or audit report |
| Evidence of log retrieval from archive tier (retention test result) | SOC or Security Engineering | Test report showing successful retrieval of aged records |

### Gap Documentation Template
**Control:** AU-11
**Finding:** Log Analytics workspace retention is configured to 30 days; NIST AU-11 baseline requires 365 days, and the organization's HIPAA data processing obligations require 2,190 days (6 years).
**Risk:** Audit records will be unavailable for incident investigations involving long dwell times, and the organization cannot meet regulatory retention requirements, exposing it to compliance violations.
**Recommendation:** Increase hot retention in the Log Analytics workspace to 90 days minimum; configure archival to cold storage (Azure Archive or S3 Glacier) with a lifecycle rule retaining records for 365 days (or 2,190 days for HIPAA-scoped data). Document the retention tiers in the formal retention policy.
**Owner:** CISO / Cloud Infrastructure Lead

### CISO Communication
> Our AU-11 review found that current log retention is configured well below both our policy requirements and the regulatory baselines that apply to this environment. In practical terms, if an incident is discovered today that began 60 days ago, the early-stage attacker activity has already been deleted and we cannot reconstruct the initial access vector. For a HIPAA or FedRAMP audit, a retention gap is a direct finding that requires a formal plan of action. The fix is a configuration change in our SIEM and the addition of a cold storage archival policy — this is not a new tool or a major project. The business case is simple: the cost of extending retention is a fraction of the cost of an investigation blocked by missing logs.

---

## Cybersecurity Engineer Perspective
> **Code access available.** Tools: kubectl, SIEM (Sentinel/Splunk), Wazuh, Falco, direct remediation.

### Assessment Commands

```bash
# --- Sentinel: check current workspace retention setting ---
export SENTINEL_WORKSPACE="<your-workspace-name>"
export SENTINEL_RG="<your-resource-group>"
export AZURE_SUBSCRIPTION_ID="<your-subscription-id>"

az monitor log-analytics workspace show \
  --workspace-name "$SENTINEL_WORKSPACE" \
  --resource-group "$SENTINEL_RG" \
  --query '{retentionInDays:retentionInDays, sku:sku.name, state:provisioningState}'

# Compliance retention benchmarks:
# NIST AU-11 baseline: 365 days
# PCI-DSS:            365 days
# SOC 2:              365 days
# FedRAMP:            1095 days (3 years)
# HIPAA:              2190 days (6 years)
```

```bash
# --- Splunk: check retention per index ---
export SPLUNK_HOST="<splunk-host>"
export SPLUNK_MGMT_PORT="8089"
export SPLUNK_USER="admin"
export SPLUNK_PASS="<password>"

curl -sk -u "${SPLUNK_USER}:${SPLUNK_PASS}" \
  "https://${SPLUNK_HOST}:${SPLUNK_MGMT_PORT}/services/data/indexes?output_mode=json&count=0" | \
  python3 -c "
import sys,json
d=json.load(sys.stdin)
requirements = {'NIST':365, 'PCI-DSS':365, 'FedRAMP':1095, 'HIPAA':2190}
for e in d.get('entry',[]):
    name = e['name']
    frozen = int(e['content'].get('frozenTimePeriodInSecs','0') or 0) // 86400
    if name in ['main','security','wineventlog']:
        print(f'Index: {name} — {frozen} days retention')
        for fw,req in requirements.items():
            status = 'PASS' if frozen >= req else 'FAIL'
            print(f'  [{status}] {fw}: {frozen}d configured vs {req}d required')
"
```

```bash
# --- Splunk: full index inventory with event counts and retention ---
curl -sk -u "${SPLUNK_USER}:${SPLUNK_PASS}" \
  "https://${SPLUNK_HOST}:${SPLUNK_MGMT_PORT}/services/data/indexes?output_mode=json&count=0" | \
  python3 -c "
import sys,json
d=json.load(sys.stdin)
print(f\"{'Index':<30} {'Events':>15} {'Size (MB)':>12} {'Retention (days)':>17}\")
print('-' * 77)
for e in d.get('entry',[]):
    c = e['content']
    events = int(c.get('totalEventCount','0') or 0)
    size   = int(c.get('currentDBSizeMB','0') or 0)
    frozen = int(c.get('frozenTimePeriodInSecs','0') or 0) // 86400
    if events > 0:
        print(f\"{e['name']:<30} {events:>15,} {size:>12,} {frozen:>16}d\")
"
```

### Detection / Testing

```bash
# --- Sentinel: verify records exist at retention boundary (90-day test) ---
CUTOFF=$(date -d "90 days ago" +%Y-%m-%d)
# macOS: CUTOFF=$(date -v-90d +%Y-%m-%d)

az monitor log-analytics query \
  --workspace-name "$SENTINEL_WORKSPACE" \
  --resource-group "$SENTINEL_RG" \
  --analytics-query "
SigninLogs
| where TimeGenerated between (datetime('${CUTOFF}') .. datetime('${CUTOFF} 23:59:59'))
| summarize RecordCount=count()
"
# If RecordCount = 0 and retention is configured > 90 days, investigate connector gap
# If RecordCount = 0 because retention < 90 days, this is a finding
```

```bash
# --- Sentinel: confirm retention setting meets minimum (90 days hot) ---
RETENTION=$(az monitor log-analytics workspace show \
  --workspace-name "$SENTINEL_WORKSPACE" \
  --resource-group "$SENTINEL_RG" \
  --query 'retentionInDays' -o tsv)

if [[ "$RETENTION" -ge 365 ]]; then
  echo "[PASS] Retention: ${RETENTION} days (meets NIST 365-day baseline)"
elif [[ "$RETENTION" -ge 90 ]]; then
  echo "[WARN] Retention: ${RETENTION} days (meets 90-day hot minimum, below 365-day NIST baseline)"
else
  echo "[FAIL] Retention: ${RETENTION} days (below 90-day minimum — immediate finding)"
fi
```

### Remediation

```bash
# --- Sentinel: update workspace retention to 365 days (NIST baseline) ---
az monitor log-analytics workspace update \
  --workspace-name "$SENTINEL_WORKSPACE" \
  --resource-group "$SENTINEL_RG" \
  --retention-time 365
# Note: increasing retention may have billing implications; verify workspace SKU supports target days
# PerGB2018 supports up to 730 days; longer requires Azure Monitor Logs Archive tier
```

```bash
# --- Sentinel: enable Azure Monitor Logs Archive for cold retention ---
# Archive tier: low-cost, queryable via restore jobs (for FedRAMP/HIPAA multi-year requirements)
az monitor log-analytics workspace table update \
  --resource-group "$SENTINEL_RG" \
  --workspace-name "$SENTINEL_WORKSPACE" \
  --name "SigninLogs" \
  --total-retention-time 1095
# total-retention-time = hot + archive combined; adjust per regulatory requirement
```

```bash
# --- Splunk: update frozenTimePeriodInSecs for security index (365 days) ---
# 365 days = 31536000 seconds
curl -sk -u "${SPLUNK_USER}:${SPLUNK_PASS}" \
  -X POST \
  "https://${SPLUNK_HOST}:${SPLUNK_MGMT_PORT}/services/data/indexes/<index-name>" \
  --data-urlencode "frozenTimePeriodInSecs=31536000"
# Replace <index-name> with: security, wineventlog, main, etc.
# Verify: re-run the index inventory check above
```

### Validation

```bash
# --- Sentinel: confirm retention update applied ---
az monitor log-analytics workspace show \
  --workspace-name "$SENTINEL_WORKSPACE" \
  --resource-group "$SENTINEL_RG" \
  --query '{retentionInDays:retentionInDays, sku:sku.name}'
# Expected: retentionInDays = 365 (or configured target)
```

```bash
# --- Splunk: verify updated retention for security indexes ---
for IDX in main security wineventlog; do
  FROZEN=$(curl -sk -u "${SPLUNK_USER}:${SPLUNK_PASS}" \
    "https://${SPLUNK_HOST}:${SPLUNK_MGMT_PORT}/services/data/indexes/${IDX}?output_mode=json" 2>/dev/null | \
    python3 -c "import sys,json; d=json.load(sys.stdin)['entry'][0]['content']; print(int(d.get('frozenTimePeriodInSecs','0') or 0) // 86400)" 2>/dev/null || echo "NOT FOUND")
  THRESHOLD=365
  if [[ "$FROZEN" -ge "$THRESHOLD" ]]; then
    echo "[PASS] Index '$IDX': ${FROZEN} days retention (>= ${THRESHOLD})"
  else
    echo "[FAIL] Index '$IDX': ${FROZEN} days retention (< ${THRESHOLD} required)"
  fi
done
# Expected: [PASS] for all security indexes
```

### Evidence Capture

```bash
# --- Export retention configuration as auditor evidence ---
mkdir -p /tmp/jsa-evidence/AU-11

# Sentinel
az monitor log-analytics workspace show \
  --workspace-name "$SENTINEL_WORKSPACE" \
  --resource-group "$SENTINEL_RG" \
  --query '{retentionInDays:retentionInDays, sku:sku.name, state:provisioningState}' \
  --output json > /tmp/jsa-evidence/AU-11/sentinel-retention-$(date +%Y%m%d).json

echo "[EVIDENCE] Saved: /tmp/jsa-evidence/AU-11/sentinel-retention-$(date +%Y%m%d).json"
```

```bash
# Splunk: retention settings for all security indexes
curl -sk -u "${SPLUNK_USER}:${SPLUNK_PASS}" \
  "https://${SPLUNK_HOST}:${SPLUNK_MGMT_PORT}/services/data/indexes?output_mode=json&count=0" | \
  python3 -c "
import sys,json,datetime
d=json.load(sys.stdin)
result = []
for e in d.get('entry',[]):
    name = e['name']
    frozen = int(e['content'].get('frozenTimePeriodInSecs','0') or 0) // 86400
    events = int(e['content'].get('totalEventCount','0') or 0)
    if events > 0:
        result.append({'index':name,'retention_days':frozen,'total_events':events})
print(json.dumps({'captured':datetime.datetime.utcnow().isoformat(),'indexes':result},indent=2))
" > /tmp/jsa-evidence/AU-11/splunk-retention-$(date +%Y%m%d).json

echo "[EVIDENCE] Saved: /tmp/jsa-evidence/AU-11/splunk-retention-$(date +%Y%m%d).json"
```
