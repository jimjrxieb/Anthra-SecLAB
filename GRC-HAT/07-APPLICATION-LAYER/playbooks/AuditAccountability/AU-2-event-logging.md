# AU-2: Event Logging
**Family:** Audit and Accountability
**NIST 800-53 Rev 5**
**Layer:** Application (L7)

## Control Statement
The organization identifies the types of events that the system is capable of logging in support of the audit function and coordinates the event logging function with other organizations requiring audit-related information.

## Why It Matters at L7
Application-layer events are the primary source of evidence for detecting compromises, insider threats, and compliance violations. Without a defined log inventory, critical events such as authentication failures, privilege use, and data access go unrecorded, creating blind spots that attackers exploit. AU-2 forces the organization to be deliberate about what it captures before an incident forces the question.

---

## GRC Analyst Perspective
> **No code access.** Tools: interviews, documentation review, SIEM dashboards, audit reports, evidence packages.

### Audit Questions
- Does the organization maintain a formal log inventory documenting which event types are captured from each system or application?
- Are authentication successes and failures, authorization failures, and privilege escalation events explicitly listed in the logging policy?
- How does the organization ensure that application teams configure logging in alignment with the enterprise log policy?
- Is the log inventory reviewed and updated when new applications are deployed or existing ones are substantially changed?
- Does the logging policy address data access events (record-level reads on sensitive data) or only authentication events?
- How are logging gaps identified — scheduled audits, SIEM coverage reviews, or reactive discovery after incidents?
- Is the event logging function coordinated with the SOC, incident response team, and compliance owners?

### Evidence to Request
| Evidence Item | Source | Acceptable Format |
|---|---|---|
| Formal logging policy or standard | Information Security Policy repository | PDF, Word, or Confluence page with approval date |
| Log inventory matrix (system-to-event-type mapping) | IT or Security Architecture | Spreadsheet, Confluence table, or SIEM connector list |
| SIEM data connector list showing active sources | Sentinel / Splunk admin | Screenshot or exported table with last-event timestamps |
| Application logging configuration samples | Dev or Platform team | Log4j config, app settings file, or Kubernetes audit policy YAML |
| Log coverage gap report from most recent audit | Internal Audit or SOC | Audit report or SIEM health dashboard export |
| Change management records showing log review on new deployments | Change Advisory Board or ticketing system | Ticket exports showing log configuration as a deployment gate |

### Gap Documentation Template
**Control:** AU-2
**Finding:** No formal log inventory exists; event types captured vary by application team without central governance.
**Risk:** Attackers can operate in gaps between application logs and SIEM coverage, and post-incident forensic reconstruction is incomplete.
**Recommendation:** Develop and publish an AU-2 Log Inventory Matrix defining required event types per system classification; integrate log coverage review into the change management process.
**Owner:** CISO / Security Architecture

### CISO Communication
> Our AU-2 review found that the organization lacks a centrally governed inventory of what events must be logged at the application layer. Different teams are making independent decisions about what to capture, which creates inconsistent coverage across the environment. The business risk is straightforward: if we do not define what we log, we cannot detect what we have not looked for. An attacker who understands our blind spots can operate in them indefinitely. Closing this gap requires a one-time effort to produce a log inventory matrix — a document that maps each system classification to required event types — and then embedding a log coverage review into the change management gate for new deployments.

---

## Cybersecurity Engineer Perspective
> **Code access available.** Tools: kubectl, SIEM (Sentinel/Splunk), Wazuh, Falco, direct remediation.

### Assessment Commands

```bash
# --- Sentinel: check which tables are actively receiving data ---
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
| top 20 by RecordCount desc
"

# Confirm required tables present: SigninLogs, SecurityEvent, AuditLogs, AzureActivity
```

```bash
# --- Splunk: verify required security indexes have events ---
export SPLUNK_HOST="<splunk-host>"
export SPLUNK_MGMT_PORT="8089"
export SPLUNK_USER="admin"
export SPLUNK_PASS="<password>"

for IDX in main security wineventlog linux_secure k8s; do
  COUNT=$(curl -sk -u "${SPLUNK_USER}:${SPLUNK_PASS}" \
    "https://${SPLUNK_HOST}:${SPLUNK_MGMT_PORT}/services/data/indexes/${IDX}?output_mode=json" 2>/dev/null | \
    python3 -c "import sys,json; print(json.load(sys.stdin)['entry'][0]['content']['totalEventCount'])" 2>/dev/null || echo "NOT FOUND")
  echo "  Index '$IDX': $COUNT events"
done
```

```bash
# --- Kubernetes: check API server audit policy coverage ---
kubectl get configmap -n kube-system audit-policy -o yaml 2>/dev/null || \
  echo "[INFO] No cluster-level audit policy configmap found — check kube-apiserver flags"

# Check kube-apiserver audit policy file path (kubeadm clusters)
kubectl get pod -n kube-system -l component=kube-apiserver -o jsonpath='{.items[0].spec.containers[0].command}' 2>/dev/null | \
  tr ',' '\n' | grep audit
```

### Detection / Testing

```bash
# --- Sentinel: verify AAD sign-in events are flowing ---
az monitor log-analytics query \
  --workspace-name "$SENTINEL_WORKSPACE" \
  --resource-group "$SENTINEL_RG" \
  --analytics-query "
SigninLogs
| where TimeGenerated > ago(1h)
| summarize EventCount=count() by ResultType, ResultDescription
| top 10 by EventCount desc
"
# If 0 rows → AAD connector disconnected or no sign-ins — either is a gap
```

```bash
# --- Splunk: coverage gap check — search for required event types ---
for DETECTION in "brute" "login" "authentication" "privilege" "escalation"; do
  COUNT=$(curl -sk -u "${SPLUNK_USER}:${SPLUNK_PASS}" \
    "https://${SPLUNK_HOST}:${SPLUNK_MGMT_PORT}/services/saved/searches?output_mode=json&count=0&search=title%3D*${DETECTION}*" 2>/dev/null | \
    python3 -c "import sys,json; print(len(json.load(sys.stdin)['entry']))" 2>/dev/null || echo "0")
  [[ "$COUNT" -gt 0 ]] && echo "[PRESENT] $DETECTION: $COUNT searches" || echo "[MISSING] No searches matching: $DETECTION"
done
```

### Remediation

```bash
# --- Sentinel: check and enable Azure Active Directory connector ---
az rest \
  --method GET \
  --url "https://management.azure.com/subscriptions/${AZURE_SUBSCRIPTION_ID}/resourceGroups/${SENTINEL_RG}/providers/Microsoft.OperationalInsights/workspaces/${SENTINEL_WORKSPACE}/providers/Microsoft.SecurityInsights/dataConnectors?api-version=2022-11-01" \
  --query "value[].{Kind:kind, Status:properties.dataTypes.alerts.state}" \
  --output table
# If AAD connector missing → Sentinel > Data connectors > Azure Active Directory > Connect
```

```bash
# --- Kubernetes: apply a baseline audit policy covering required L7 events ---
# This is a sample; adjust levels per your environment's risk classification
cat <<'EOF' > /tmp/audit-policy-baseline.yaml
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  - level: RequestResponse
    resources:
    - group: ""
      resources: ["secrets", "configmaps"]
  - level: Metadata
    resources:
    - group: ""
      resources: ["pods", "services"]
  - level: Request
    verbs: ["create", "update", "patch", "delete"]
  - level: None
    users: ["system:kube-proxy"]
    verbs: ["watch"]
    resources:
    - group: ""
      resources: ["endpoints", "services"]
EOF
echo "[ACTION REQUIRED] Copy /tmp/audit-policy-baseline.yaml to kube-apiserver --audit-policy-file path and restart apiserver"
```

### Validation

```bash
# --- Sentinel: confirm all required tables received events in last 24h ---
az monitor log-analytics query \
  --workspace-name "$SENTINEL_WORKSPACE" \
  --resource-group "$SENTINEL_RG" \
  --analytics-query "
let required = datatable(TableName:string)['SigninLogs','SecurityEvent','AuditLogs','AzureActivity'];
required
| join kind=leftouter (
    union withsource=TableName *
    | where TimeGenerated > ago(24h)
    | summarize LastEvent=max(TimeGenerated) by TableName
) on TableName
| project TableName, LastEvent, Status = iif(isnotempty(LastEvent),'PASS','MISSING')
"
# Expected: Status = PASS for all four required tables
```

```bash
# --- Splunk: verify required indexes have events in the last hour ---
for IDX in main security wineventlog; do
  curl -sk -u "${SPLUNK_USER}:${SPLUNK_PASS}" \
    "https://${SPLUNK_HOST}:${SPLUNK_MGMT_PORT}/services/search/jobs/export?output_mode=json" \
    --data "search=search index=${IDX} earliest=-1h | stats count" 2>/dev/null | \
    python3 -c "import sys,json; [print(f'Index ${IDX}:', r.get('result',{}).get('count','0')) for r in (json.loads(l) for l in sys.stdin if l.strip()) if r.get('result')]" 2>/dev/null
done
# Expected: count > 0 for each required index
```

### Evidence Capture

```bash
# --- Sentinel: export active data connectors as evidence ---
mkdir -p /tmp/jsa-evidence/AU-2
az rest \
  --method GET \
  --url "https://management.azure.com/subscriptions/${AZURE_SUBSCRIPTION_ID}/resourceGroups/${SENTINEL_RG}/providers/Microsoft.OperationalInsights/workspaces/${SENTINEL_WORKSPACE}/providers/Microsoft.SecurityInsights/dataConnectors?api-version=2022-11-01" \
  --output json > /tmp/jsa-evidence/AU-2/sentinel-connectors-$(date +%Y%m%d).json

echo "[EVIDENCE] Saved: /tmp/jsa-evidence/AU-2/sentinel-connectors-$(date +%Y%m%d).json"
```

```bash
# --- Splunk: export index inventory as evidence ---
mkdir -p /tmp/jsa-evidence/AU-2
curl -sk -u "${SPLUNK_USER}:${SPLUNK_PASS}" \
  "https://${SPLUNK_HOST}:${SPLUNK_MGMT_PORT}/services/data/indexes?output_mode=json&count=0" \
  > /tmp/jsa-evidence/AU-2/splunk-indexes-$(date +%Y%m%d).json

echo "[EVIDENCE] Saved: /tmp/jsa-evidence/AU-2/splunk-indexes-$(date +%Y%m%d).json"
```
