# T1053 Scheduled Task Persistence — Governance

## NIST 800-53 Control Mapping

| Control | Name | How This Scenario Demonstrates Compliance |
|---------|------|------------------------------------------|
| SI-4 | Information System Monitoring | Hunt detects persistence mechanisms beyond automated coverage |
| CA-7 | Continuous Monitoring | Documented hunt satisfies continuous monitoring requirements |
| CM-3 | Configuration Change Control | Cron file monitoring detects unauthorized configuration changes |
| CM-7 | Least Functionality | Audit of scheduled tasks enforces minimal scheduled task footprint |

## MITRE ATT&CK

- **Tactic:** Persistence / Privilege Escalation / Execution
- **Technique:** T1053 — Scheduled Task/Job

## Audit Narrative

"The organization conducts proactive threat hunting for persistence via scheduled tasks aligned to ATT&CK T1053. Hunts enumerate all crontabs, system cron directories, systemd timers, and at jobs, comparing against documented baselines to identify new or modified entries. Suspicious content (encoded commands, external callbacks) triggers immediate investigation. Confirmed persistence triggers removal, C2 blocking, and fleet-wide scope assessment. auditd rules monitor cron and systemd directories for future unauthorized modifications. Documentation satisfies CA-7 and CM-3 evidence requirements."
