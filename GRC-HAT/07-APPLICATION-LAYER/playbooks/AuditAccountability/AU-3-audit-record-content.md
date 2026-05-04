# AU-3: Audit Record Content
**Family:** Audit and Accountability
**NIST 800-53 Rev 5**
**Layer:** Application (L7)

## Control Statement
The system generates audit records that contain sufficient information to establish what events occurred, the sources of the events, and the outcomes of the events.

## Why It Matters at L7
A log entry that records only "login failed" is useless for investigation — it tells you something went wrong but not who, from where, or to what resource. AU-3 defines the minimum field set that makes a log record forensically useful: timestamp, identity, source, action, target, result, and session context. Incomplete records force analysts to correlate multiple sources and increase incident response time, and they fail auditor scrutiny during compliance reviews.

---

## GRC Analyst Perspective
> **No code access.** Tools: interviews, documentation review, SIEM dashboards, audit reports, evidence packages.

### Audit Questions
- Does the organization's logging standard define the required fields for every audit record, and are those fields documented in writing?
- Can the team produce a sample log record from each major application and demonstrate that timestamp, user identity, source IP, action, resource, and outcome are all present?
- Are timestamps recorded in UTC across all systems, or do some sources log in local time without offset notation?
- How does the organization validate log record completeness — periodic sampling, SIEM schema validation, or reactive review only?
- Are session identifiers captured in log records to allow correlation of an authentication event with subsequent actions by the same session?
- When applications are updated or replaced, is log schema reviewed to ensure required fields are not dropped?
- Do third-party SaaS applications in scope provide log exports that contain the required AU-3 fields, or are there gaps in identity or source IP attribution?

### Evidence to Request
| Evidence Item | Source | Acceptable Format |
|---|---|---|
| Logging standard or data dictionary defining required fields | Information Security or Architecture team | PDF, Word, Confluence page |
| Sample raw log records from authentication and data access events | Application or Platform team | JSON or text log extract (last 24 hours, PII redacted as appropriate) |
| SIEM ingestion schema mapping for at least two data sources | SIEM admin | Table showing source field to normalized field mapping |
| Log validation test results (field completeness check) | Security Engineering or SOC | Test report or script output |
| Screenshot or export of SIEM record showing all required fields populated | SOC or SIEM admin | Screenshot or JSON export |
| Gap report for any data source failing field completeness checks | Internal Audit or Security team | Audit finding or gap register entry |

### Gap Documentation Template
**Control:** AU-3
**Finding:** Audit records from the customer-facing web application are missing the session ID field; source IP is present but user identity is recorded as a service account rather than the end-user identity.
**Risk:** Incident response cannot correlate authentication events with data access events for the same session, increasing MTTR and reducing forensic completeness for regulatory reporting.
**Recommendation:** Update application logging configuration to include session ID and user identity at the application layer rather than relying on the service account identity passed at the infrastructure layer. Validate with a SIEM schema check after change deployment.
**Owner:** Application Development Lead / Security Engineering

### CISO Communication
> Our AU-3 assessment found that several application log sources do not consistently capture all required fields — specifically session identifiers and end-user identity — in their audit records. What this means in practice is that if an incident occurs, our analysts will be unable to reconstruct a complete timeline of what a specific user did during a session. They can see that a login occurred, but cannot link it to subsequent data access or configuration changes with confidence. For a compliance audit, this creates a gap that regulators will note. The fix is a targeted application configuration change, not a platform redesign. The business ask is a sprint-level engineering task to add session ID and accurate identity attribution to the log output for the affected services.

---

## Cybersecurity Engineer Perspective
> **Code access available.** Tools: kubectl, SIEM (Sentinel/Splunk), Wazuh, Falco, direct remediation.

### Assessment Commands

```bash
# --- Sentinel: pull a sample authentication record and inspect field completeness ---
export SENTINEL_WORKSPACE="<your-workspace-name>"
export SENTINEL_RG="<your-resource-group>"
export AZURE_SUBSCRIPTION_ID="<your-subscription-id>"

az monitor log-analytics query \
  --workspace-name "$SENTINEL_WORKSPACE" \
  --resource-group "$SENTINEL_RG" \
  --analytics-query "
SigninLogs
| where TimeGenerated > ago(1h)
| take 5
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    AppDisplayName,
    ResultType,
    ResultDescription,
    CorrelationId,
    SessionId
"
# Required fields: TimeGenerated (UTC), UserPrincipalName, IPAddress, AppDisplayName,
# ResultType (outcome), CorrelationId/SessionId
```

```bash
# --- Sentinel: check SecurityEvent (Windows) field completeness ---
az monitor log-analytics query \
  --workspace-name "$SENTINEL_WORKSPACE" \
  --resource-group "$SENTINEL_RG" \
  --analytics-query "
SecurityEvent
| where TimeGenerated > ago(1h)
| take 5
| project
    TimeGenerated,
    Account,
    IpAddress,
    Activity,
    EventID,
    LogonType,
    Computer,
    SubjectLogonId
"
```

```bash
# --- Splunk: inspect raw record fields for a sample authentication event ---
export SPLUNK_HOST="<splunk-host>"
export SPLUNK_MGMT_PORT="8089"
export SPLUNK_USER="admin"
export SPLUNK_PASS="<password>"

# Review raw fields present on a Windows EventCode=4624 (logon success)
curl -sk -u "${SPLUNK_USER}:${SPLUNK_PASS}" \
  "https://${SPLUNK_HOST}:${SPLUNK_MGMT_PORT}/services/search/jobs/export?output_mode=json" \
  --data "search=search index=wineventlog EventCode=4624 | head 3 | fields _time, Account_Name, Source_Network_Address, Logon_Type, Logon_ID, host, EventCode" \
  --data "earliest_time=-1h@h" 2>/dev/null | \
  python3 -c "
import sys, json
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
```

### Detection / Testing

```bash
# --- Sentinel: field completeness check across SigninLogs ---
# Flags records missing required fields
az monitor log-analytics query \
  --workspace-name "$SENTINEL_WORKSPACE" \
  --resource-group "$SENTINEL_RG" \
  --analytics-query "
SigninLogs
| where TimeGenerated > ago(24h)
| extend
    HasTimestamp  = isnotempty(TimeGenerated),
    HasIdentity   = isnotempty(UserPrincipalName),
    HasSourceIP   = isnotempty(IPAddress),
    HasApp        = isnotempty(AppDisplayName),
    HasOutcome    = isnotempty(ResultType),
    HasSession    = isnotempty(CorrelationId)
| summarize
    TotalRecords   = count(),
    MissingIdentity = countif(not(HasIdentity)),
    MissingSourceIP = countif(not(HasSourceIP)),
    MissingSession  = countif(not(HasSession)),
    MissingOutcome  = countif(not(HasOutcome))
"
# Expected: all Missing* columns = 0
```

```bash
# --- Splunk: SPL field completeness check on authentication events ---
# Run in Splunk Web > Search & Reporting
cat <<'SPL'
index=wineventlog EventCode=4624 earliest=-24h
| eval MissingFields=mvappend(
    if(isnull(Account_Name) OR Account_Name="","Identity",null()),
    if(isnull(Source_Network_Address) OR Source_Network_Address="","SourceIP",null()),
    if(isnull(Logon_ID) OR Logon_ID="","SessionID",null()),
    if(isnull(Logon_Type) OR Logon_Type="","LogonType",null())
  )
| eval GapCount=mvcount(MissingFields)
| stats count as TotalRecords, sum(GapCount) as TotalMissingFields, values(MissingFields) as MissingFieldTypes by host
| where TotalMissingFields > 0
SPL
```

### Remediation

```bash
# --- If Kubernetes application pods are missing session/user fields, patch the logging env ---
# Example: add structured logging env vars for a deployment in <app-namespace>
kubectl -n <app-namespace> patch deployment <app-deployment> --type=json -p '[
  {
    "op": "add",
    "path": "/spec/template/spec/containers/0/env/-",
    "value": {"name": "LOG_FORMAT", "value": "json"}
  },
  {
    "op": "add",
    "path": "/spec/template/spec/containers/0/env/-",
    "value": {"name": "LOG_INCLUDE_SESSION_ID", "value": "true"}
  }
]'
# Note: exact env vars depend on the application's logging framework
```

```bash
# --- Sentinel: confirm AuditLogs (AAD) includes required operation fields ---
az monitor log-analytics query \
  --workspace-name "$SENTINEL_WORKSPACE" \
  --resource-group "$SENTINEL_RG" \
  --analytics-query "
AuditLogs
| where TimeGenerated > ago(1h)
| take 3
| project
    TimeGenerated,
    OperationName,
    Result,
    InitiatedBy,
    TargetResources,
    CorrelationId
"
# If InitiatedBy or TargetResources is empty, the connector may need reconfiguration
```

### Validation

```bash
# --- Sentinel: confirm field completeness after remediation ---
az monitor log-analytics query \
  --workspace-name "$SENTINEL_WORKSPACE" \
  --resource-group "$SENTINEL_RG" \
  --analytics-query "
SigninLogs
| where TimeGenerated > ago(1h)
| summarize
    TotalRecords    = count(),
    WithIdentity    = countif(isnotempty(UserPrincipalName)),
    WithSourceIP    = countif(isnotempty(IPAddress)),
    WithOutcome     = countif(isnotempty(ResultType)),
    WithSession     = countif(isnotempty(CorrelationId))
| extend
    IdentityPct = round(100.0 * WithIdentity / TotalRecords, 1),
    SourceIPPct = round(100.0 * WithSourceIP / TotalRecords, 1),
    OutcomePct  = round(100.0 * WithOutcome  / TotalRecords, 1),
    SessionPct  = round(100.0 * WithSession  / TotalRecords, 1)
"
# Expected: all Pct fields = 100.0
```

### Evidence Capture

```bash
# --- Export sample records with field completeness check for auditor package ---
mkdir -p /tmp/jsa-evidence/AU-3

# Sentinel
az monitor log-analytics query \
  --workspace-name "$SENTINEL_WORKSPACE" \
  --resource-group "$SENTINEL_RG" \
  --analytics-query "
SigninLogs
| where TimeGenerated > ago(24h)
| summarize
    TotalRecords    = count(),
    MissingIdentity = countif(isempty(UserPrincipalName)),
    MissingSourceIP = countif(isempty(IPAddress)),
    MissingSession  = countif(isempty(CorrelationId)),
    MissingOutcome  = countif(isempty(ResultType))
" --output json > /tmp/jsa-evidence/AU-3/sentinel-field-completeness-$(date +%Y%m%d).json

echo "[EVIDENCE] Saved: /tmp/jsa-evidence/AU-3/sentinel-field-completeness-$(date +%Y%m%d).json"
```

```bash
# Splunk index field coverage export
curl -sk -u "${SPLUNK_USER}:${SPLUNK_PASS}" \
  "https://${SPLUNK_HOST}:${SPLUNK_MGMT_PORT}/services/search/jobs/export?output_mode=json" \
  --data "search=search index=wineventlog EventCode=4624 earliest=-24h | fieldsummary | table field, count, distinct_count, is_exact" \
  2>/dev/null > /tmp/jsa-evidence/AU-3/splunk-field-summary-$(date +%Y%m%d).json

echo "[EVIDENCE] Saved: /tmp/jsa-evidence/AU-3/splunk-field-summary-$(date +%Y%m%d).json"
```
