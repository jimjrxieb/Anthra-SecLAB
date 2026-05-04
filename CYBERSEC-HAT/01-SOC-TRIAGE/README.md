# 01 — SOC Triage

## What This Function Covers

Alert intake, SIEM triage, escalation decisions. This is the L1/L2 analyst workflow: receive an alert, determine if it is real, determine severity, investigate enough to decide — close, escalate, or open an incident.

A 3-5 year analyst owns this function without supervision. They know what a true positive looks like versus alert fatigue noise. They know what questions to answer before escalating. They document as they go.

## Why It Matters

Alert fatigue kills security programs. Organizations average 500-1000 alerts per day. An analyst who cannot triage fast and accurately either misses real attacks or cries wolf until leadership ignores them. Triage is the core competency.

## NIST 800-53 Controls

| Control ID | Control Name | What It Requires |
|-----------|-------------|-----------------|
| SI-4 | Information System Monitoring | Real-time monitoring, alert generation, analysis |
| AU-6 | Audit Review, Analysis, Reporting | Review audit logs, investigate findings, report |
| IR-6 | Incident Reporting | Report incidents to proper authorities within timeframes |
| AU-12 | Audit Record Generation | Systems generate audit records for defined events |

## Tools

| Tool | Type | Cost | Purpose |
|------|------|------|---------|
| Splunk | Commercial/Free tier | Free (dev license) | SIEM, search, dashboards |
| Elastic/ELK Stack | Open source | Free | Log aggregation, alerting, SIEM |
| Microsoft Sentinel | Commercial | Pay-per-use | Cloud-native SIEM |
| Wazuh | Open source | Free | SIEM, IDS, log analysis |
| TheHive | Open source | Free | Incident case management |
| VirusTotal | Free/API | Free tier | IOC enrichment, file/URL analysis |

## Scenarios

| Scenario | ATT&CK | What It Tests |
|----------|--------|---------------|
| [T1566.001 Phishing Email](scenarios/T1566.001-phishing-email/) | T1566.001 | Email alert triage, header analysis, sandbox verdict |
| [T1078 Valid Account Abuse](scenarios/T1078-valid-account-abuse/) | T1078 | Impossible travel, off-hours login, MFA bypass |
| [T1110 Brute Force Lockout](scenarios/T1110-brute-force-lockout/) | T1110 | Failed login spike, threshold analysis, lockout review |
| [T1059.001 Malicious PowerShell](scenarios/T1059.001-malicious-powershell/) | T1059.001 | Encoded command, suspicious parent process, EDR alert |
