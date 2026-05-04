# 04-triage-alerts.md — Daily SOC Alert Triage (Dual SIEM)

| Field | Value |
|---|---|
| **NIST Controls** | AU-6 (audit review and analysis), IR-4 (incident handling), IR-5 (incident monitoring) |
| **Tools** | Microsoft Sentinel (portal + KQL) / Splunk (portal + SPL) |
| **Time** | 30–60 minutes daily |
| **Rank** | C (analyst classification decisions required) |

---

## Purpose

This is the daily SOC workflow. You have alerts — now what? This playbook covers how to triage alerts in both Sentinel and Splunk, classify them (TP/FP/Uncertain), determine the right escalation rank, and track MTTD/MTTR.

---

## Morning Triage Routine (Both SIEMs)

Start each day with:
1. Check open incident count (target: no High incidents > 24 hours old)
2. Review new alerts from overnight
3. Classify each alert: True Positive / False Positive / Uncertain
4. Assign rank (E/D/C/B/S) using the rank system
5. Route: E/D → auto-handle, C → analyst decides, B/S → escalate

---

## Path A: Microsoft Sentinel

### Step 1: Incident Queue

**Portal:** security.microsoft.com → Incidents & alerts → Incidents

```kql
// Morning review: all open incidents from last 24 hours
SecurityIncident
| where TimeGenerated > ago(24h)
| where Status != "Closed"
| project TimeGenerated, Title, Severity, Status,
          Owner = tostring(Owner.assignedTo),
          AlertCount, IncidentNumber
| sort by Severity asc, TimeGenerated desc
// Severity sorts: High=1, Medium=2, Low=3, Informational=4
```

### Step 2: Investigation Graph

For each High incident:
1. Open incident → click **Investigate**
2. Review the entity graph: which accounts, IPs, and machines are connected?
3. Timeline: what happened first?
4. Related alerts: is this isolated or part of a pattern?

### Step 3: KQL Hunt Queries

Use these to investigate specific scenarios:

```kql
// Hunt: brute force source — find all activity from attacking IP
let SuspiciousIP = "192.168.1.100";  // Replace with actual IP
union SigninLogs, SecurityEvent, AzureActivity
| where TimeGenerated > ago(24h)
| where SourceIPAddress == SuspiciousIP or IPAddress == SuspiciousIP
| project TimeGenerated, Type, Account, Activity, IPAddress, Location
| sort by TimeGenerated asc
```

```kql
// Hunt: impossible travel — full account timeline
let SuspiciousUser = "user@company.com";  // Replace with UPN
SigninLogs
| where TimeGenerated > ago(48h)
| where UserPrincipalName == SuspiciousUser
| project TimeGenerated, ResultType, AppDisplayName, IPAddress,
          City  = tostring(LocationDetails.city),
          Country = tostring(LocationDetails.countryOrRegion)
| sort by TimeGenerated asc
```

```kql
// Hunt: new admin — investigate role assignment context
let SuspiciousAdmin = "user@company.com";
AuditLogs
| where TimeGenerated > ago(24h)
| where OperationName contains "role" or OperationName contains "member"
| where TargetResources[0].userPrincipalName == SuspiciousAdmin
    or InitiatedBy.user.userPrincipalName == SuspiciousAdmin
| project TimeGenerated, OperationName, Result, InitiatedBy = InitiatedBy.user.userPrincipalName,
          Target = TargetResources[0].userPrincipalName, Role = TargetResources[1].displayName
```

```kql
// Hunt: data exfiltration signals — large downloads or unusual network
// Requires AzureNetworkAnalytics or Syslog depending on connector
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DeviceAction !in ("Deny", "Drop", "Reset")
| where SentBytes > 104857600  // 100MB threshold
| project TimeGenerated, SourceIP, DestinationIP, DestinationPort, SentBytes, ReceivedBytes, ApplicationProtocol
| sort by SentBytes desc
```

### Step 4: Close or Escalate

For each alert:
- **False Positive**: Close with reason. Create tuning note to reduce recurrence.
- **True Positive (E/D rank)**: Auto-remediate, document, close.
- **True Positive (C rank)**: Analyst fixes, document steps, close.
- **True Positive (B/S rank)**: Escalate to senior analyst or management. Do not close alone.

---

## Path B: Splunk

### Step 1: Notable Events (ES) / Saved Search Results

```spl
/* Morning review: triggered correlation searches in last 24 hours */
index=main OR index=security earliest=-24h
| search _type=alert OR sourcetype=stash
| stats count by savedsearch_name, alert_severity
| sort -count
```

```spl
/* Open all brute force detections */
index=wineventlog EventCode=4625 earliest=-24h
| stats count as FailedAttempts, values(Account_Name) as Targets
    by Source_Network_Address, host
| where FailedAttempts > 5
| eval Risk = case(FailedAttempts > 50, "CRITICAL", FailedAttempts > 20, "HIGH", true(), "MEDIUM")
| sort -FailedAttempts
| table Source_Network_Address, host, FailedAttempts, Targets, Risk
```

### Step 2: Investigation Dashboard

1. Navigate to SOC Overview dashboard (`03-templates/splunk/dashboard-soc-overview.xml`)
2. Review: alert volume chart, critical alerts table, FIM changes
3. Click any row to drilldown

### Step 3: SPL Hunt Queries

```spl
/* Hunt: all activity from suspicious IP */
| tstats count where index=* by _time, host, source
  | search source=*192.168.1.100*

/* Full SPL version */
index=* "192.168.1.100" earliest=-24h
| eval EventType=if(sourcetype="WinEventLog", "Windows", if(sourcetype="linux_secure", "Linux", sourcetype))
| table _time, host, EventType, user, src_ip, EventCode, message
| sort -_time
```

```spl
/* Hunt: impossible travel — same user, two countries */
index=main sourcetype=WinEventLog EventCode=4624 earliest=-48h
| stats values(Source_Network_Address) as IPs, values(Workstation_Name) as Hosts
    by Account_Name
| eval IP_Count=mvcount(IPs)
| where IP_Count > 3
| table Account_Name, IPs, Hosts, IP_Count
```

```spl
/* Hunt: lateral movement — pass-the-hash/pass-the-ticket signals */
index=wineventlog (EventCode=4648 OR EventCode=4769) earliest=-24h
| eval EventType=case(EventCode=4648, "ExplicitLogon", EventCode=4769, "KerberosTGS")
| stats count by Account_Name, Target_Server_Name, EventType
| where count > 3
| sort -count
```

```spl
/* Hunt: K8s exec events */
index=k8s sourcetype=kube:apiserver:audit verb=create earliest=-24h
| rex field=requestURI "\/api\/v1\/namespaces\/(?<Namespace>[^\/]+)\/pods\/(?<PodName>[^\/]+)\/(?<Action>exec|log|portforward)"
| where isnotnull(Action)
| spath output=Username path="user.username"
| table _time, Username, Namespace, PodName, Action, sourceIPAddresses{}
| sort -_time
```

---

## Alert Classification Framework

For each alert, answer these questions:

### 1. Is it technically valid?
- Does the source data actually show what the alert claims?
- Check: source logs, related events, timeline

### 2. Is it in context?
- Known change window? Authorized penetration test? Legitimate admin task?
- Check: change management, IT helpdesk, calendar

### 3. What is the blast radius?
- Privileged account? Production system? Data store?
- Low: workstation / non-privileged user
- Medium: server / service account
- High: domain controller / cloud admin / database

### 4. Rank Assignment

| Rank | Criteria | Action |
|---|---|---|
| E | Known pattern, no context needed (e.g., automated port scan from known scanner) | Auto-dismiss with note |
| D | Low-risk, no sensitive context (e.g., scheduled task change in dev) | Document and close |
| C | Moderate risk, analyst-confirmable (e.g., 5 failed logins, user confirms locked out) | Analyst verifies, resolves |
| B | High risk or ambiguous (e.g., new admin in prod, no change ticket found) | Senior analyst reviews |
| S | Critical — data breach, ransomware, supply chain (e.g., LSASS dump in prod) | Incident response team |

---

## MTTD / MTTR Tracking

Track daily for continuous monitoring posture:

```kql
// Sentinel MTTD/MTTR — last 7 days
SecurityIncident
| where TimeGenerated > ago(7d)
| where Status == "Closed"
| extend
    MTTD = datetime_diff('minute', CreatedTime, FirstActivityTime),
    MTTR = datetime_diff('minute', ClosedTime, CreatedTime)
| summarize
    AvgMTTD_min = avg(MTTD),
    AvgMTTR_min = avg(MTTR),
    MedianMTTD  = percentile(MTTD, 50),
    MedianMTTR  = percentile(MTTR, 50),
    Closed      = count()
```

```spl
/* Splunk MTTD/MTTR approximation */
index=_audit action=search info=completed savedsearch_name=JSA-*
| eval trigger_time=_time
| stats min(trigger_time) as first_alert, max(trigger_time) as last_alert,
    count as alert_count by savedsearch_name
| eval MTTD_min=(last_alert-first_alert)/60
| table savedsearch_name, alert_count, MTTD_min
```

---

## Top Investigation Scenarios

| Scenario | SIEM | Hunt Query | Escalation |
|---|---|---|---|
| Brute force > 50 attempts | Both | Failed login hunt | C-rank if no success found; B-rank if succeeded |
| Impossible travel | Sentinel | SigninLogs timeline | B-rank — human verification required |
| New Global Admin | Sentinel | AuditLogs role check | B-rank — may be S-rank if unauthorized |
| kubectl exec in prod | Splunk/Sentinel | K8s audit hunt | B-rank — S-rank if sensitive pod |
| Mass file deletion | Wazuh/Sentinel | FIM + audit correlation | S-rank — potential ransomware precursor |
| Outbound to unusual port | Splunk | Rare outbound hunt | C-rank if first occurrence; B-rank if recurring |
