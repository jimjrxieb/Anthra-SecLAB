# IR-5: Incident Monitoring
**Family:** Incident Response  
**NIST 800-53 Rev 5**  
**Layer:** Application (L7)

## Control Statement
The organization monitors and documents information system security incidents on an ongoing basis to support timely detection, analysis, and response.

## Why It Matters at L7
Continuous monitoring at the application layer is what separates organizations that discover breaches in hours from those that discover them in months. SIEM health, alert backlog management, and MTTD/MTTR tracking are not optional metrics — they are the operational evidence that detection controls are actually working. A disconnected log connector or a growing alert queue left untriaged is functionally equivalent to no monitoring at all. K8s exec events and API authentication failures at L7 are among the highest-signal detections available; if those aren't reaching the SOC in real time, the monitoring program has a gap regardless of what the policy says.

---

## GRC Analyst Perspective
> **No code access.** Tools: interviews, documentation review, SIEM dashboards, audit reports, evidence packages.

### Audit Questions
- Does the organization maintain a written monitoring coverage map that identifies which systems, applications, and log sources are ingested into the SIEM? When was it last reviewed?
- What is the current mean time to detect (MTTD) and mean time to respond (MTTR) for application-layer incidents? Are these measured and reported to leadership on a defined cadence?
- Are SIEM connector health and log ingestion gaps monitored automatically? What alert fires when a critical log source goes silent?
- What is the SOC's documented procedure for managing alert queue backlog? Is there an SLA for how long a High-severity alert may remain open before escalation?
- How is SOC staffing coverage maintained outside business hours? Is there a documented on-call rotation and a defined handoff procedure between shifts?
- Are escalation SLAs defined per severity tier and tracked as compliance metrics? What happens when an SLA is missed?
- How frequently are detection rules reviewed and tuned? Is there a process for retiring rules with high false-positive rates?
- What application-layer log sources are currently not covered by the SIEM? Is there a roadmap to close those gaps?

### Evidence to Request
| Evidence Item | Source | Acceptable Format |
|---|---|---|
| SIEM monitoring coverage map (log sources, connector status) | SIEM Admin / Security Architecture | Diagram or spreadsheet — source name, connector type, health status, last event timestamp |
| MTTD/MTTR report — last 90 days | SOC Manager / SIEM Dashboard export | Chart or table with values by severity tier, exported from SIEM |
| Alert queue aging report (open incidents by age and severity) | Ticketing System / SIEM | CSV or dashboard screenshot, dated |
| SOC on-call rotation schedule and escalation SLA documentation | SOC Manager | Document showing coverage hours, named contacts, SLA thresholds |
| Evidence of detection rule tuning (false-positive reduction log) | SIEM Admin | Change log or ticket history showing rule modifications and rationale |
| Falco or runtime alert log — last 30 days | K8s Security / SOC | Log export or dashboard screenshot showing alert volume and categories |

### Gap Documentation Template
**Control:** IR-5  
**Finding:** No automated alerting exists for SIEM connector failures; a critical log source (K8s audit log) was silent for 72 hours before a manual review discovered the gap.  
**Risk:** Attacker activity during connector outage periods goes undetected; the organization cannot demonstrate continuous monitoring coverage required by NIST IR-5.  
**Recommendation:** Implement a data connector health monitor that fires a High-severity alert when any critical source has not ingested events within a defined threshold (e.g., 30 minutes). Assign ownership for connector health to the SIEM admin role with a documented SLA for resolution.  
**Owner:** SIEM Administrator / SOC Manager  

### CISO Communication
> Our monitoring program is only as good as the data flowing into it. Right now, we have detection rules and analyst procedures, but we do not have a reliable answer to the question: "Is every critical system actually sending logs to the SIEM today?" A connector that stops working silently is the same as no monitoring for that system. Beyond connector health, we need to be reporting MTTD and MTTR against defined targets — not because auditors ask for it, but because it tells us whether our SOC investment is actually working. Establishing connector health monitoring, publishing MTTD/MTTR targets for each severity tier, and formalizing the alert aging SLA will close the gap between having a monitoring program on paper and having one that functions in practice.

---

## Cybersecurity Engineer Perspective
> **Code access available.** Tools: kubectl, cloud CLI, SIEM (Sentinel/Splunk), direct remediation.

### Assessment Commands

```bash
# Check Sentinel workspace connectivity and recent ingestion
# Run in Azure Portal → Log Analytics workspace → Logs
```

```kql
// SIEM health: data connector ingestion status — last 2 hours
// Flag any source with no data in last 60 minutes
union withsource=TableName *
| where TimeGenerated > ago(2h)
| summarize LastEvent = max(TimeGenerated), EventCount = count() by TableName
| where LastEvent < ago(60m)
| project TableName, LastEvent, EventCount, GapMinutes = datetime_diff('minute', now(), LastEvent)
| sort by GapMinutes desc
// Expected: critical tables (SecurityEvent, Syslog, CommonSecurityLog) show < 10 min gap
```

```kql
// SIEM health: Sentinel data connector status
_SentinelHealth
| where TimeGenerated > ago(24h)
| summarize LastEvent = max(TimeGenerated), Status = any(SentinelResourceName) by DataConnectorName = SentinelResourceName
| project DataConnectorName, LastEvent, GapMinutes = datetime_diff('minute', now(), LastEvent)
| sort by GapMinutes desc
```

```bash
# Splunk: check forwarder connectivity and input health
# Paste into Splunk Search
```

```spl
/* Splunk forwarder health — sources silent in last 30 min */
| rest /services/data/inputs/all
| search disabled=0
| table title, sourcetype, status, eai:acl.app
| where status != "enabled"
```

```spl
/* Alert queue: triggered correlation searches last 24 hours */
index=main OR index=security earliest=-24h
| search _type=alert OR sourcetype=stash
| stats count by savedsearch_name, alert_severity
| sort -count
```

```bash
# Check Falco alert volume (K8s runtime monitoring)
kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=100 2>/dev/null | \
  grep -E "Warning|Error|Critical" | \
  awk '{print $1, $2, $3}' | sort | uniq -c | sort -rn | head -20

# Check Falco is running on all nodes
kubectl get pods -n falco -o wide
# Expected: one pod per node, all STATUS=Running
```

### Detection / Testing

```kql
// MTTD/MTTR tracking — last 7 days (Sentinel)
SecurityIncident
| where TimeGenerated > ago(7d)
| where Status == "Closed"
| extend
    MTTD_min = datetime_diff('minute', CreatedTime, FirstActivityTime),
    MTTR_min = datetime_diff('minute', ClosedTime, CreatedTime)
| summarize
    AvgMTTD_min   = avg(MTTD_min),
    AvgMTTR_min   = avg(MTTR_min),
    MedianMTTD    = percentile(MTTD_min, 50),
    MedianMTTR    = percentile(MTTR_min, 50),
    P90MTTD       = percentile(MTTD_min, 90),
    P90MTTR       = percentile(MTTR_min, 90),
    TotalClosed   = count()
    by Severity
| sort by Severity asc
```

```kql
// Alert queue aging — open incidents by age bucket
SecurityIncident
| where Status != "Closed"
| extend AgeHours = datetime_diff('hour', now(), CreatedTime)
| extend AgeBucket = case(
    AgeHours < 4,    "< 4h",
    AgeHours < 24,   "4-24h",
    AgeHours < 72,   "1-3 days",
    AgeHours < 168,  "3-7 days",
    "> 7 days")
| summarize Count = count() by Severity, AgeBucket
| sort by Severity asc, AgeBucket asc
// Alert: any High severity in "> 7 days" bucket is an SLA breach
```

```kql
// K8s exec monitoring — high-value L7 detection (Sentinel)
AzureDiagnostics
| where TimeGenerated > ago(24h)
| where Category == "kube-audit"
| where requestVerb_s == "create"
| where requestURI_s contains "/exec"
| project TimeGenerated,
          User = user_username_s,
          Pod  = requestURI_s,
          SourceIP = sourceIPs_s
| sort by TimeGenerated desc
```

```spl
/* MTTD/MTTR approximation (Splunk) */
index=_audit action=search info=completed savedsearch_name=JSA-*
| eval trigger_time=_time
| stats min(trigger_time) as first_alert, max(trigger_time) as last_alert,
    count as alert_count by savedsearch_name
| eval MTTD_min = round((last_alert - first_alert) / 60, 1)
| table savedsearch_name, alert_count, MTTD_min
| sort -MTTD_min
```

```spl
/* K8s exec events — Splunk (kube:apiserver:audit) */
index=k8s sourcetype=kube:apiserver:audit verb=create earliest=-24h
| rex field=requestURI "\/api\/v1\/namespaces\/(?<Namespace>[^\/]+)\/pods\/(?<PodName>[^\/]+)\/(?<Action>exec|log|portforward)"
| where isnotnull(Action)
| spath output=Username path="user.username"
| table _time, Username, Namespace, PodName, Action, sourceIPAddresses{}
| sort -_time
// B-rank if production namespace; S-rank if sensitive pod (secrets store, database)
```

```bash
# Test detection pipeline end-to-end — trigger a known-benign event and verify it lands in SIEM
# Generate a test K8s exec event (non-production namespace only)
kubectl run test-monitoring --image=busybox:1.36 -n <test-namespace> \
  --restart=Never -- sleep 30 2>/dev/null

kubectl exec test-monitoring -n <test-namespace> -- ls /tmp 2>/dev/null

# Then verify the exec event appeared in SIEM within SLA window
# Clean up
kubectl delete pod test-monitoring -n <test-namespace> 2>/dev/null
```

### Remediation

```bash
# --- Fix: Restart a failed Sentinel connector (Azure Monitor Agent) ---
# Check agent status on Arc-enabled or Azure VM
az connectedmachine extension list \
  --resource-group "<rg-name>" \
  --machine-name "<vm-name>" \
  --query "[?name=='AzureMonitorLinuxAgent'].{State:provisioningState,Status:properties.instanceView.status}" \
  --output table

# Restart agent on Linux host (if SSH access available)
sudo systemctl restart azuremonitoragent
sudo systemctl status azuremonitoragent
```

```bash
# --- Fix: Restart Splunk Universal Forwarder ---
# On Linux host
sudo /opt/splunkforwarder/bin/splunk restart

# Verify connection back to indexer
sudo /opt/splunkforwarder/bin/splunk list forward-server

# Check inputs are active
sudo /opt/splunkforwarder/bin/splunk list monitor
```

```bash
# --- Fix: Restart Falco on a failing node ---
FAILING_NODE="<node-name>"
FALCO_POD=$(kubectl get pods -n falco -o wide | grep "$FAILING_NODE" | awk '{print $1}')

kubectl delete pod "$FALCO_POD" -n falco
# DaemonSet will automatically recreate it

# Wait for new pod
kubectl rollout status daemonset/falco -n falco --timeout=120s

# Verify all nodes have Falco running
kubectl get pods -n falco -o wide | grep -v Running
# Expected: no output (all pods Running)
```

### Validation

```bash
# Verify SIEM data ingestion resumed after connector fix
# Run in Log Analytics workspace
```

```kql
// Confirm ingestion resumed — check last event time for previously-silent table
union withsource=TableName *
| where TimeGenerated > ago(30m)
| summarize LastEvent = max(TimeGenerated), EventCount = count() by TableName
| where TableName in ("SecurityEvent", "Syslog", "CommonSecurityLog", "AzureDiagnostics")
| project TableName, LastEvent, GapMinutes = datetime_diff('minute', now(), LastEvent)
// Expected: all critical tables show LastEvent within last 10 minutes
```

```bash
# Verify MTTD/MTTR are within target thresholds (run weekly)
# Target example: MTTD < 60 min for High, MTTR < 4 hours for High
```

```kql
// MTTD/MTTR compliance check against targets
let MTTD_Target_High = 60;   // minutes
let MTTR_Target_High = 240;  // minutes
SecurityIncident
| where TimeGenerated > ago(30d)
| where Status == "Closed"
| where Severity == "High"
| extend
    MTTD_min = datetime_diff('minute', CreatedTime, FirstActivityTime),
    MTTR_min = datetime_diff('minute', ClosedTime, CreatedTime)
| summarize
    TotalHigh      = count(),
    MetMTTD        = countif(MTTD_min <= MTTD_Target_High),
    MetMTTR        = countif(MTTR_min <= MTTR_Target_High),
    AvgMTTD_min    = avg(MTTD_min),
    AvgMTTR_min    = avg(MTTR_min)
| extend
    MTTD_Compliance = round(100.0 * MetMTTD / TotalHigh, 1),
    MTTR_Compliance = round(100.0 * MetMTTR / TotalHigh, 1)
// Expected: MTTD_Compliance >= 80%, MTTR_Compliance >= 80%
```

### Evidence Capture

```bash
# Create evidence directory
mkdir -p /tmp/jsa-evidence/IR-5/$(date +%Y%m%d)

# Export connector health snapshot
# Save output from the connector health KQL query as JSON
# Run in Log Analytics and download as: connector-health-$(date +%Y%m%d).json

# Export Falco alert summary
kubectl logs -n falco -l app.kubernetes.io/name=falco --since=24h 2>/dev/null | \
  grep -E "Warning|Error|Critical" | \
  tee /tmp/jsa-evidence/IR-5/$(date +%Y%m%d)/falco-alerts-24h.txt

# Export Falco pod status (shows DaemonSet coverage)
kubectl get pods -n falco -o wide -o json \
  > /tmp/jsa-evidence/IR-5/$(date +%Y%m%d)/falco-pod-status.json

# Export alert queue aging snapshot
# Save output from the alert queue aging KQL query as: alert-queue-aging-$(date +%Y%m%d).csv

# Export MTTD/MTTR report for last 90 days
# Save output from the MTTD/MTTR KQL query as: mttd-mttr-90d-$(date +%Y%m%d).json
```

```kql
// Evidence: 90-day MTTD/MTTR report — save as mttd-mttr-90d.json
SecurityIncident
| where TimeGenerated > ago(90d)
| where Status == "Closed"
| extend
    MTTD_min = datetime_diff('minute', CreatedTime, FirstActivityTime),
    MTTR_min = datetime_diff('minute', ClosedTime, CreatedTime)
| project TimeGenerated, IncidentNumber, Title, Severity,
          MTTD_min, MTTR_min,
          Owner = tostring(Owner.assignedTo)
| sort by TimeGenerated desc
```

```bash
# Hash all evidence files for chain of custody
sha256sum /tmp/jsa-evidence/IR-5/$(date +%Y%m%d)/* \
  > /tmp/jsa-evidence/IR-5/$(date +%Y%m%d)/sha256sums.txt

echo "[DONE] IR-5 evidence package: /tmp/jsa-evidence/IR-5/$(date +%Y%m%d)/"
ls -lh /tmp/jsa-evidence/IR-5/$(date +%Y%m%d)/
```
