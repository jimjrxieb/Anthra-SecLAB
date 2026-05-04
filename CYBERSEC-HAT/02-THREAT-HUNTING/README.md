# 02 — Threat Hunting

## What This Function Covers

Proactive, hypothesis-driven investigation. No alert required. The analyst forms a hypothesis — "I think there is credential dumping happening" — then goes looking for evidence to confirm or deny it. If confirmed, it becomes an incident. If denied, the hunt produces a documented negative (which itself is evidence of monitoring).

A 3-5 year analyst runs hunts independently. They know how to form a testable hypothesis, pull the right data, and document findings whether positive or negative.

## Why It Matters

Attackers with dwell time — average 21 days before detection (Mandiant 2024) — are not generating obvious alerts. They use living-off-the-land techniques, valid credentials, and slow movement. Reactive monitoring catches the noisy ones. Threat hunting catches the quiet ones.

## NIST 800-53 Controls

| Control ID | Control Name | What It Requires |
|-----------|-------------|-----------------|
| SI-4 | Information System Monitoring | Monitoring for indicators of attack, not just known signatures |
| CA-7 | Continuous Monitoring | Ongoing assessment of security posture beyond automated alerts |
| RA-3 | Risk Assessment | Understanding of threats relevant to the environment |
| IR-4 | Incident Handling | Hunt findings that confirm an incident trigger IR procedures |

## Tools

| Tool | Type | Cost | Purpose |
|------|------|------|---------|
| Velociraptor | Open source | Free | Endpoint interrogation, live forensics, hunt at scale |
| OSQuery | Open source | Free | SQL-based endpoint telemetry, fleet-wide queries |
| Zeek | Open source | Free | Network traffic analysis, connection logs |
| Elastic/ELK | Open source | Free | Log search and aggregation for hunting |
| Sigma | Open source | Free | Detection rule format, hunt query library |
| MITRE ATT&CK Navigator | Free | Free | Hunt coverage mapping |

## Scenarios

| Scenario | ATT&CK | What It Tests |
|----------|--------|---------------|
| [T1003 Credential Dumping](scenarios/T1003-credential-dumping/) | T1003 | Hunt for LSASS access, unusual process memory reads |
| [T1055 Process Injection](scenarios/T1055-process-injection/) | T1055 | Unusual parent-child relationships, hollowing indicators |
| [T1021.001 RDP Lateral Movement](scenarios/T1021.001-rdp-lateral-movement/) | T1021.001 | Internal RDP spikes, new src→dst pairs, odd-hours activity |
| [T1053 Scheduled Task Persistence](scenarios/T1053-persistence-scheduled-task/) | T1053 | New scheduled tasks, unusual authors/paths |
