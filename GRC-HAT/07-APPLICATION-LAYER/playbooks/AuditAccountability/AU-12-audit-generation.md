# AU-12: Audit Record Generation
**Family:** Audit and Accountability
**NIST 800-53 Rev 5**
**Layer:** Application (L7)

## Control Statement
The system provides audit record generation capability for the event types defined in AU-2, allows designated organizational personnel to select which auditable events are to be logged, and generates audit records for defined events.

## Why It Matters at L7
AU-12 is the end-to-end pipeline test: does an event that occurs in an application actually produce a record in the SIEM within an acceptable time window? It is possible to have correct configuration on paper — AU-2 policy, AU-3 fields, AU-11 retention — and still have a broken pipeline where application events never reach the SIEM due to a misconfigured forwarder, a dropped connector, or a logging library that is silently failing. AU-12 requires closing the loop with synthetic event generation and end-to-end tracing.

---

## GRC Analyst Perspective
> **No code access.** Tools: interviews, documentation review, SIEM dashboards, audit reports, evidence packages.

### Audit Questions
- Can the organization demonstrate that a specific application event — for example, a failed authentication — produces an audit record in the SIEM within five minutes?
- Is there a documented log flow diagram showing the path from application event generation to SIEM ingestion?
- Who is designated as responsible for selecting auditable event types for each system, and is that responsibility documented in a RACI or system security plan?
- How does the organization detect pipeline failures — situations where events are occurring but records are not being generated in the SIEM?
- Is audit record generation tested periodically (at minimum annually) with synthetic events that trace the full pipeline?
- Are there any applications or systems that generate events but are not yet connected to the SIEM, and how are those tracked?
- When system components are updated (OS patches, container image updates, application releases), is logging continuity verified as part of the change validation process?

### Evidence to Request
| Evidence Item | Source | Acceptable Format |
|---|---|---|
| Log flow diagram showing event-to-SIEM pipeline | Architecture or Security Engineering | Network diagram, Confluence page, or draw.io export |
| Audit record generation test result (synthetic event trace) | Security Engineering or SOC | Test report showing event timestamp, SIEM record timestamp, and latency |
| SIEM data connector health report (last 24h event counts) | SIEM admin | Dashboard screenshot or API export with last-event timestamps |
| System Security Plan or equivalent listing auditable event selections | System Owner or GRC team | SSP section or RACI document |
| Evidence of log pipeline monitoring (alert if ingestion drops to zero) | SOC or SIEM admin | Alert rule screenshot or monitoring configuration export |
| Change management ticket showing logging verification on last deployment | Change Advisory Board or engineering team | Ticket with log validation step completed |

### Gap Documentation Template
**Control:** AU-12
**Finding:** Log pipeline end-to-end testing has never been performed; the organization cannot confirm that application authentication events reach the SIEM. One data connector (Azure Active Directory) shows no events in the last 24 hours despite active user sign-in activity.
**Risk:** The organization has a monitoring blind spot of unknown duration. Security events that should trigger detection rules are not reaching the SIEM, and any alerts dependent on those event types have been silently failing.
**Recommendation:** Perform immediate pipeline verification by generating a synthetic authentication event and tracing it to the SIEM within five minutes. Reconnect the AAD data connector and establish a connector health alert to detect future pipeline failures within one hour.
**Owner:** Security Engineering / SOC Lead

### CISO Communication
> Our AU-12 assessment found that the organization has not verified the end-to-end audit record generation pipeline — meaning we have logging infrastructure in place, but we have not confirmed that events from applications are reliably reaching the SIEM. In one specific case, a data connector that should be delivering Azure Active Directory sign-in events shows no records in the last 24 hours, despite known user activity during that period. The business risk is that any detection rules dependent on those events have not been firing, creating an undetected monitoring gap. The fix is a pipeline reconnection and the addition of a connector health alert — a configuration task, not an architecture change. Going forward, pipeline verification should be a standard gate in deployment validation.

---

## Cybersecurity Engineer Perspective
> **Code access available.** Tools: kubectl, SIEM (Sentinel/Splunk), Wazuh, Falco, direct remediation.

### Assessment Commands

```bash
# --- Sentinel: check connector health — events per table in last 24h ---
export SENTINEL_WORKSPACE="<your-workspace-name>"
export SENTINEL_RG="<your-resource-group>"
export AZURE_SUBSCRIPTION_ID="<your-subscription-id>"

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
# Tables with 0 records or absent entirely = pipeline gap
```

```bash
# --- Sentinel: verify AAD connector is delivering events ---
az monitor log-analytics query \
  --workspace-name "$SENTINEL_WORKSPACE" \
  --resource-group "$SENTINEL_RG" \
  --analytics-query "
SigninLogs
| where TimeGenerated > ago(1h)
| take 1
| project TimeGenerated, UserPrincipalName, ResultType, IPAddress
"
# If 0 rows with known user activity in last hour → AAD connector broken or misconfigured
```

```bash
# --- Splunk: verify events are flowing to required indexes ---
export SPLUNK_HOST="<splunk-host>"
export SPLUNK_MGMT_PORT="8089"
export SPLUNK_USER="admin"
export SPLUNK_PASS="<password>"

for IDX in main security wineventlog linux_secure; do
  COUNT=$(curl -sk -u "${SPLUNK_USER}:${SPLUNK_PASS}" \
    "https://${SPLUNK_HOST}:${SPLUNK_MGMT_PORT}/services/data/indexes/${IDX}?output_mode=json" 2>/dev/null | \
    python3 -c "import sys,json; print(json.load(sys.stdin)['entry'][0]['content']['totalEventCount'])" 2>/dev/null || echo "NOT FOUND")
  echo "  Index '$IDX': $COUNT events"
done
```

```bash
# --- Splunk: HEC endpoint health check ---
HEC_STATUS=$(curl -sk \
  "https://${SPLUNK_HOST}:8088/services/collector/health" \
  --max-time 5 -w "%{http_code}" -o /dev/null 2>/dev/null)

if [[ "$HEC_STATUS" == "200" ]]; then
  echo "[PASS] HEC endpoint healthy"
elif [[ "$HEC_STATUS" == "400" ]]; then
  echo "[PASS] HEC reachable (400 = no token sent, endpoint is up)"
else
  echo "[FAIL] HEC returned: $HEC_STATUS — pipeline likely broken"
fi
```

### Detection / Testing

```bash
# --- End-to-end pipeline test: generate a synthetic authentication event ---
# Step 1: Record the current time before generating the event
PIPELINE_TEST_START=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
echo "[TEST] Pipeline test started at: $PIPELINE_TEST_START"

# Step 2: Generate a synthetic failed login (requires kubectl access to an app pod)
# Adjust namespace and pod name to match your environment
kubectl -n <app-namespace> exec -it <app-pod> -- \
  curl -sk -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{"username":"pipeline-test-user","password":"SYNTHETIC_FAILURE_$(date +%s)"}' \
  2>/dev/null || echo "[INFO] Login attempt sent (expected failure)"

echo "[TEST] Synthetic event generated at: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
echo "[TEST] Wait 5 minutes then run the Sentinel/Splunk query below to confirm record appeared"
```

```bash
# --- Sentinel: trace synthetic event to SIEM (run 5 minutes after generation) ---
az monitor log-analytics query \
  --workspace-name "$SENTINEL_WORKSPACE" \
  --resource-group "$SENTINEL_RG" \
  --analytics-query "
SigninLogs
| where TimeGenerated > ago(10m)
| where UserPrincipalName contains 'pipeline-test'
    or ResultDescription contains 'pipeline-test'
| project TimeGenerated, UserPrincipalName, ResultType, IPAddress, AppDisplayName
"
# Expected: record appears within 5 minutes of generation
# If no record: pipeline broken between application and AAD or AAD and Sentinel
```

```bash
# --- Splunk: trace synthetic Windows event (EventCode=4625) ---
# Run in Splunk Web > Search & Reporting, or via API:
CUTOFF=$(date -d "10 minutes ago" +"%Y-%m-%dT%H:%M:%S")
# macOS: CUTOFF=$(date -v-10M +"%Y-%m-%dT%H:%M:%S")

curl -sk -u "${SPLUNK_USER}:${SPLUNK_PASS}" \
  "https://${SPLUNK_HOST}:${SPLUNK_MGMT_PORT}/services/search/jobs/export?output_mode=json" \
  --data "search=search index=wineventlog EventCode=4625 earliest=-10m | head 5 | table _time, Account_Name, Source_Network_Address, host" \
  2>/dev/null | \
  python3 -c "
import sys,json
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    try:
        rec = json.loads(line)
        if rec.get('result'):
            print(json.dumps(rec['result'], indent=2))
    except json.JSONDecodeError:
        pass
"
# Expected: record appears within 5 minutes if Splunk forwarder is healthy
```

### Remediation

```bash
# --- Sentinel: check and reconnect data connectors ---
# List connector status
az rest \
  --method GET \
  --url "https://management.azure.com/subscriptions/${AZURE_SUBSCRIPTION_ID}/resourceGroups/${SENTINEL_RG}/providers/Microsoft.OperationalInsights/workspaces/${SENTINEL_WORKSPACE}/providers/Microsoft.SecurityInsights/dataConnectors?api-version=2022-11-01" \
  --query "value[].{Kind:kind, Status:properties.dataTypes.alerts.state}" \
  --output table

# If AAD connector shows disconnected → reconnect via portal:
# Sentinel > Data connectors > Azure Active Directory > Open connector page > Connect
echo "[ACTION REQUIRED] Reconnect disconnected connectors via Azure Portal"
echo "  Path: Sentinel > Data connectors > [connector name] > Open connector page > Connect"
```

```bash
# --- Splunk: restart Universal Forwarder on a Linux host if pipeline is broken ---
# Run on the host sending logs (requires SSH access)
# systemctl restart SplunkForwarder

# Or via Docker if running Splunk in a container:
docker exec splunk /opt/splunk/bin/splunk restart 2>/dev/null || \
  echo "[ACTION REQUIRED] Restart Splunk forwarder on source host to restore pipeline"
```

```bash
# --- Add a Sentinel connector health alert (KQL scheduled rule) ---
# Fires if a required table receives 0 events in a 2-hour window
# Deploy via portal: Sentinel > Analytics > + Create > Scheduled query rule
# Use this KQL as the rule query:
cat <<'KQL'
let required_tables = datatable(TableName:string)
  ['SigninLogs','SecurityEvent','AuditLogs','AzureActivity'];
required_tables
| join kind=leftouter (
    union withsource=TableName *
    | where TimeGenerated > ago(2h)
    | summarize LastEvent=max(TimeGenerated), Count=count() by TableName
) on TableName
| where isempty(LastEvent) or Count == 0
| project TableName, Status="NO_EVENTS_2H", CheckTime=now()
KQL
echo "[ACTION REQUIRED] Create Sentinel scheduled rule using the KQL above"
echo "  Severity: High | Run every: 1 hour | Lookup: 2 hours"
```

### Validation

```bash
# --- Sentinel: confirm pipeline is generating records end-to-end ---
az monitor log-analytics query \
  --workspace-name "$SENTINEL_WORKSPACE" \
  --resource-group "$SENTINEL_RG" \
  --analytics-query "
let required = datatable(TableName:string)
  ['SigninLogs','SecurityEvent','AuditLogs','AzureActivity'];
required
| join kind=leftouter (
    union withsource=TableName *
    | where TimeGenerated > ago(1h)
    | summarize LastEvent=max(TimeGenerated), RecordCount=count() by TableName
) on TableName
| project
    TableName,
    RecordCount = coalesce(RecordCount, 0),
    LastEvent,
    Status = iif(isnotempty(LastEvent) and RecordCount > 0, 'GENERATING', 'PIPELINE_GAP')
"
# Expected: Status = GENERATING for all required tables
```

```bash
# --- Splunk: validate HEC and index pipeline are functional ---
HEC_STATUS=$(curl -sk \
  "https://${SPLUNK_HOST}:8088/services/collector/health" \
  --max-time 5 -w "%{http_code}" -o /dev/null 2>/dev/null)

[[ "$HEC_STATUS" =~ ^(200|400)$ ]] && echo "[PASS] HEC pipeline: healthy ($HEC_STATUS)" || \
  echo "[FAIL] HEC pipeline: degraded ($HEC_STATUS)"

# Verify last-event recency for required indexes
for IDX in main security wineventlog; do
  LATEST=$(curl -sk -u "${SPLUNK_USER}:${SPLUNK_PASS}" \
    "https://${SPLUNK_HOST}:${SPLUNK_MGMT_PORT}/services/data/indexes/${IDX}?output_mode=json" 2>/dev/null | \
    python3 -c "import sys,json; print(json.load(sys.stdin)['entry'][0]['content'].get('latestTime','N/A'))" 2>/dev/null || echo "N/A")
  echo "  Index '$IDX' latest event: $LATEST"
done
# Expected: latestTime within last 10 minutes for actively monitored indexes
```

### Evidence Capture

```bash
# --- Export pipeline health report as auditor evidence ---
mkdir -p /tmp/jsa-evidence/AU-12

# Sentinel: connector status
az rest \
  --method GET \
  --url "https://management.azure.com/subscriptions/${AZURE_SUBSCRIPTION_ID}/resourceGroups/${SENTINEL_RG}/providers/Microsoft.OperationalInsights/workspaces/${SENTINEL_WORKSPACE}/providers/Microsoft.SecurityInsights/dataConnectors?api-version=2022-11-01" \
  --output json > /tmp/jsa-evidence/AU-12/sentinel-connectors-$(date +%Y%m%d).json

echo "[EVIDENCE] Saved: /tmp/jsa-evidence/AU-12/sentinel-connectors-$(date +%Y%m%d).json"
```

```bash
# Sentinel: table ingestion health (last 24h)
az monitor log-analytics query \
  --workspace-name "$SENTINEL_WORKSPACE" \
  --resource-group "$SENTINEL_RG" \
  --analytics-query "
union withsource=TableName *
| where TimeGenerated > ago(24h)
| summarize RecordCount=count(), LastEvent=max(TimeGenerated)
    by TableName
| top 20 by RecordCount desc
" --output json > /tmp/jsa-evidence/AU-12/sentinel-table-health-$(date +%Y%m%d).json

echo "[EVIDENCE] Saved: /tmp/jsa-evidence/AU-12/sentinel-table-health-$(date +%Y%m%d).json"
```

```bash
# Splunk: index health export
curl -sk -u "${SPLUNK_USER}:${SPLUNK_PASS}" \
  "https://${SPLUNK_HOST}:${SPLUNK_MGMT_PORT}/services/data/indexes?output_mode=json&count=0" | \
  python3 -c "
import sys,json,datetime
d=json.load(sys.stdin)
result=[]
for e in d.get('entry',[]):
    c=e['content']
    result.append({
      'index':e['name'],
      'total_events':int(c.get('totalEventCount','0') or 0),
      'size_mb':int(c.get('currentDBSizeMB','0') or 0),
      'latest_time':c.get('latestTime','N/A'),
      'disabled':c.get('disabled',False)
    })
print(json.dumps({'captured':datetime.datetime.utcnow().isoformat(),'indexes':result},indent=2))
" > /tmp/jsa-evidence/AU-12/splunk-index-health-$(date +%Y%m%d).json

echo "[EVIDENCE] Saved: /tmp/jsa-evidence/AU-12/splunk-index-health-$(date +%Y%m%d).json"
```
