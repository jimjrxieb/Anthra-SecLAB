# AU-6: Audit Review, Analysis, and Alerting
**Family:** Audit and Accountability
**NIST 800-53 Rev 5**
**Layer:** Application (L7)

## Control Statement
The organization reviews and analyzes system audit records for indications of inappropriate or unusual activity, and reports findings to designated officials.

## Why It Matters at L7
Collecting logs without reviewing them is security theater. AU-6 is what turns a passive log archive into an active detection capability. At the application layer, this means SIEM alert rules firing on brute force attempts, privilege escalation, after-hours access, and new administrative account creation — with defined escalation paths and measurable response time metrics. Without AU-6 controls in place, attackers can operate undetected for months within logged systems.

---

## GRC Analyst Perspective
> **No code access.** Tools: interviews, documentation review, SIEM dashboards, audit reports, evidence packages.

### Audit Questions
- How frequently does the SOC review SIEM alerts, and is that cadence documented in a formal procedure?
- Are there documented alert thresholds for high-risk event categories — authentication failures, privilege escalation, after-hours access, and new admin account creation?
- What is the organization's current Mean Time to Detect (MTTD) and Mean Time to Respond (MTTR), and how are those metrics tracked?
- Is there a documented escalation path from SIEM alert to incident response team to management notification?
- How does the organization handle alert fatigue — are there tuning processes to reduce false positives without suppressing true positives?
- Are audit review findings reported to a designated official (CISO, Risk Committee, or equivalent) on a recurring schedule?
- Does the organization use automated alerting in addition to manual review, and if so, which detection categories are covered by automation?

### Evidence to Request
| Evidence Item | Source | Acceptable Format |
|---|---|---|
| SIEM alert rule inventory with enabled/disabled status | SIEM admin (Sentinel or Splunk) | Exported rule list with enabled flags and last-triggered timestamps |
| SOC review procedure or runbook documenting review cadence | SOC Lead or CISO | Policy document, Confluence page, or SOC playbook |
| MTTD/MTTR metrics from last 30 days | SOC or incident management platform | Dashboard export, JIRA/ServiceNow report, or SIEM query results |
| Incident tickets for last 30 days showing escalation path | SOC or ITSM system | Ticket list with severity, assignee, and resolution timeline |
| Alert tuning log showing false positive reduction actions | SIEM admin or Detection Engineering | Change log or SIEM rule modification history |
| Most recent audit review report submitted to management | CISO or GRC team | Meeting minutes, governance report, or email distribution evidence |

### Gap Documentation Template
**Control:** AU-6
**Finding:** SIEM contains fewer than 10 enabled scheduled detection rules; brute force and privilege escalation detection categories have no active rules.
**Risk:** Authentication-based attacks and insider privilege abuse go undetected, increasing dwell time and potential data exposure.
**Recommendation:** Deploy baseline detection rule set covering at minimum: brute force (T1110), privilege escalation (T1548, T1098), after-hours access, and new admin account creation. Establish weekly SOC review cadence with findings reported to CISO monthly.
**Owner:** Security Operations Manager / Detection Engineering

### CISO Communication
> Our AU-6 review identified that while log collection is operating, the detection layer — the rules that trigger alerts when something suspicious happens — is significantly underpopulated. We have logs, but we are not watching them systematically. The specific risk is that common attack patterns such as password spraying and privilege escalation would currently generate no automated alert; a human analyst would need to manually notice the pattern in raw logs. The remediation is deploying a baseline detection rule set into the existing SIEM, which is a one-time configuration task, not a new tool purchase. Once deployed, we can establish MTTD/MTTR tracking to demonstrate the monitoring program is working, which directly supports our compliance posture.

---

## Cybersecurity Engineer Perspective
> **Code access available.** Tools: kubectl, SIEM (Sentinel/Splunk), Wazuh, Falco, direct remediation.

### Assessment Commands

```bash
# --- Sentinel: count enabled vs disabled analytics rules ---
export SENTINEL_WORKSPACE="<your-workspace-name>"
export SENTINEL_RG="<your-resource-group>"
export AZURE_SUBSCRIPTION_ID="<your-subscription-id>"

az rest \
  --method GET \
  --url "https://management.azure.com/subscriptions/${AZURE_SUBSCRIPTION_ID}/resourceGroups/${SENTINEL_RG}/providers/Microsoft.OperationalInsights/workspaces/${SENTINEL_WORKSPACE}/providers/Microsoft.SecurityInsights/alertRules?api-version=2022-11-01" \
  --query "value[].{Name:properties.displayName, Enabled:properties.enabled, Severity:properties.severity, Kind:kind}" \
  --output table
```

```bash
# --- Splunk: count and categorize scheduled searches ---
export SPLUNK_HOST="<splunk-host>"
export SPLUNK_MGMT_PORT="8089"
export SPLUNK_USER="admin"
export SPLUNK_PASS="<password>"

curl -sk -u "${SPLUNK_USER}:${SPLUNK_PASS}" \
  "https://${SPLUNK_HOST}:${SPLUNK_MGMT_PORT}/services/saved/searches?output_mode=json&count=0&search=is_scheduled=1" | \
  python3 -c "
import sys,json
d=json.load(sys.stdin)
enabled  = [e for e in d.get('entry',[]) if not e['content'].get('disabled',False)]
disabled = [e for e in d.get('entry',[]) if e['content'].get('disabled',False)]
print(f'Total scheduled: {len(d[\"entry\"])} | Enabled: {len(enabled)} | Disabled: {len(disabled)}')
print()
print('Enabled searches:')
for e in enabled:
    print(f\"  [{e['content'].get('alert.severity','N/A')}] {e['name']}\")
"
```

### Detection / Testing

```bash
# --- Sentinel KQL: MTTD and MTTR for last 30 days ---
az monitor log-analytics query \
  --workspace-name "$SENTINEL_WORKSPACE" \
  --resource-group "$SENTINEL_RG" \
  --analytics-query "
SecurityIncident
| where TimeGenerated > ago(30d)
| where Status == 'Closed'
| extend
    MTTD_hours = datetime_diff('hour', CreatedTime, FirstActivityTime),
    MTTR_hours = datetime_diff('hour', ClosedTime, CreatedTime)
| summarize
    Avg_MTTD  = avg(MTTD_hours),
    Avg_MTTR  = avg(MTTR_hours),
    P90_MTTD  = percentile(MTTD_hours, 90),
    Total     = count()
"
# Benchmarks: MTTD < 1h = Excellent | 1-8h = Good | 8-24h = Acceptable | >24h = Finding
```

```bash
# --- Sentinel KQL: Detection coverage across MITRE tactics ---
az monitor log-analytics query \
  --workspace-name "$SENTINEL_WORKSPACE" \
  --resource-group "$SENTINEL_RG" \
  --analytics-query "
SecurityAlert
| where TimeGenerated > ago(7d)
| summarize AlertCount = count(), UniqueRules = dcount(AlertName)
    by bin(TimeGenerated, 1d)
| render timechart
"
```

```bash
# --- Splunk SPL: Brute force detection — 5+ failures from single source IP ---
# Run in Splunk Web > Search & Reporting
cat <<'SPL'
index=wineventlog EventCode=4625
| stats count as FailedAttempts, values(Account_Name) as Targets
    by Source_Network_Address
| where FailedAttempts > 5
| sort -FailedAttempts
SPL
# NIST AC-7 | MITRE T1110
```

```bash
# --- Splunk SPL: Privilege escalation — special privileges and group membership changes ---
cat <<'SPL'
index=wineventlog (EventCode=4672 OR EventCode=4728 OR EventCode=4732)
| stats count by Account_Name, EventCode, host
| sort -count
SPL
# NIST AC-6 | MITRE T1548
```

```bash
# --- Splunk SPL: New admin account created ---
cat <<'SPL'
index=wineventlog EventCode=4720
| table _time, Account_Name, Subject_Account_Name, host
SPL
# NIST AC-2 | MITRE T1136
```

```bash
# --- Splunk SPL: K8s exec into pods ---
cat <<'SPL'
index=k8s sourcetype=kube:apiserver:audit verb=create requestURI=*/exec*
| spath output=User path="user.username"
| spath output=Pod path="objectRef.name"
| spath output=Namespace path="objectRef.namespace"
| table _time, User, Namespace, Pod, sourceIPAddresses{}
SPL
# NIST SI-4 | MITRE T1609
```

### Remediation

```bash
# --- Sentinel: deploy brute force detection rule from template ---
az deployment group create \
  --resource-group "$SENTINEL_RG" \
  --template-file ../03-templates/sentinel/analytics-rule-brute-force.json \
  --parameters workspaceName="$SENTINEL_WORKSPACE" \
  --name "deploy-brute-force-rule-$(date +%Y%m%d)"
```

```bash
# --- Sentinel: deploy privilege escalation detection rule ---
az deployment group create \
  --resource-group "$SENTINEL_RG" \
  --template-file ../03-templates/sentinel/analytics-rule-priv-escalation.json \
  --parameters workspaceName="$SENTINEL_WORKSPACE" \
  --name "deploy-priv-escalation-rule-$(date +%Y%m%d)"
```

```bash
# --- Splunk: deploy JSA-Failed-Login-Threshold via REST API ---
curl -sk -u "${SPLUNK_USER}:${SPLUNK_PASS}" \
  -X POST \
  "https://${SPLUNK_HOST}:${SPLUNK_MGMT_PORT}/servicesNS/${SPLUNK_USER}/search/saved/searches" \
  --data-urlencode "name=JSA-Failed-Login-Threshold" \
  --data-urlencode "search=index=wineventlog EventCode=4625 OR (index=linux_secure \"Failed password\") | stats count as FailedAttempts, values(user) as TargetAccounts by src_ip | where FailedAttempts > 5" \
  --data-urlencode "cron_schedule=*/5 * * * *" \
  --data-urlencode "is_scheduled=1" \
  --data-urlencode "disabled=0" \
  --data-urlencode "alert_type=number of events" \
  --data-urlencode "alert_comparator=greater than" \
  --data-urlencode "alert_threshold=0" \
  --data-urlencode "alert.severity=3"
```

```bash
# --- Splunk: deploy savedsearches.conf directly (requires server access) ---
docker cp ../03-templates/splunk/savedsearches.conf \
  splunk:/opt/splunk/etc/apps/search/local/savedsearches.conf

docker exec splunk /opt/splunk/bin/splunk reload saved-searches \
  -auth admin:"$SPLUNK_PASS"
```

### Validation

```bash
# --- Sentinel: confirm new rules appear in active rule list ---
az rest \
  --method GET \
  --url "https://management.azure.com/subscriptions/${AZURE_SUBSCRIPTION_ID}/resourceGroups/${SENTINEL_RG}/providers/Microsoft.OperationalInsights/workspaces/${SENTINEL_WORKSPACE}/providers/Microsoft.SecurityInsights/alertRules?api-version=2022-11-01" \
  --query "value[?properties.enabled==\`true\`].{Name:properties.displayName, Severity:properties.severity}" \
  --output table
# Expected: brute force and privilege escalation rules appear with enabled=true
```

```bash
# --- Splunk: verify JSA searches are enabled ---
curl -sk -u "${SPLUNK_USER}:${SPLUNK_PASS}" \
  "https://${SPLUNK_HOST}:${SPLUNK_MGMT_PORT}/services/saved/searches?output_mode=json&count=0&search=title%3DJSA-*" | \
  python3 -c "
import sys,json
d=json.load(sys.stdin)
for e in d.get('entry',[]):
    status = 'ENABLED' if not e['content'].get('disabled',False) else 'DISABLED'
    print(f\"  [{status}] {e['name']}\")
"
# Expected: all JSA-* searches show [ENABLED]
```

### Evidence Capture

```bash
# --- Sentinel: export rule inventory post-deployment ---
mkdir -p /tmp/jsa-evidence/AU-6

az rest \
  --method GET \
  --url "https://management.azure.com/subscriptions/${AZURE_SUBSCRIPTION_ID}/resourceGroups/${SENTINEL_RG}/providers/Microsoft.OperationalInsights/workspaces/${SENTINEL_WORKSPACE}/providers/Microsoft.SecurityInsights/alertRules?api-version=2022-11-01" \
  --output json > /tmp/jsa-evidence/AU-6/sentinel-rules-$(date +%Y%m%d).json

echo "[EVIDENCE] Saved: /tmp/jsa-evidence/AU-6/sentinel-rules-$(date +%Y%m%d).json"
```

```bash
# --- Splunk: export saved search inventory post-deployment ---
curl -sk -u "${SPLUNK_USER}:${SPLUNK_PASS}" \
  "https://${SPLUNK_HOST}:${SPLUNK_MGMT_PORT}/services/saved/searches?output_mode=json&count=0" \
  > /tmp/jsa-evidence/AU-6/splunk-searches-$(date +%Y%m%d).json

echo "[EVIDENCE] Saved: /tmp/jsa-evidence/AU-6/splunk-searches-$(date +%Y%m%d).json"
```

```bash
# --- Sentinel: export MTTD/MTTR metrics as evidence ---
az monitor log-analytics query \
  --workspace-name "$SENTINEL_WORKSPACE" \
  --resource-group "$SENTINEL_RG" \
  --analytics-query "
SecurityIncident
| where TimeGenerated > ago(30d)
| where Status == 'Closed'
| extend
    MTTD_hours = datetime_diff('hour', CreatedTime, FirstActivityTime),
    MTTR_hours = datetime_diff('hour', ClosedTime, CreatedTime)
| summarize
    Avg_MTTD = avg(MTTD_hours),
    Avg_MTTR = avg(MTTR_hours),
    P90_MTTD = percentile(MTTD_hours, 90),
    Total    = count()
" --output json > /tmp/jsa-evidence/AU-6/sentinel-mttd-mttr-$(date +%Y%m%d).json

echo "[EVIDENCE] Saved: /tmp/jsa-evidence/AU-6/sentinel-mttd-mttr-$(date +%Y%m%d).json"
```
