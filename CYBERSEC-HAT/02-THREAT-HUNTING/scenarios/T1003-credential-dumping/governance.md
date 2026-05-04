# T1003 Credential Dumping — Governance

## NIST 800-53 Control Mapping

| Control | Name | How This Scenario Demonstrates Compliance |
|---------|------|------------------------------------------|
| SI-4 | Information System Monitoring | Hunt surfaces credential file access beyond automated alert coverage |
| CA-7 | Continuous Monitoring | Documented hunt (positive or negative) satisfies continuous monitoring evidence requirement |
| AU-9 | Protection of Audit Information | Credential file monitoring via auditd protects integrity of audit records |
| IA-5 | Authenticator Management | Credential rotation procedure demonstrates authenticator lifecycle management |

## MITRE ATT&CK

- **Tactic:** Credential Access
- **Technique:** T1003 — OS Credential Dumping

## Audit Narrative

"The organization conducts proactive threat hunting for credential dumping techniques aligned to ATT&CK T1003. Hunts are hypothesis-driven and documented regardless of outcome. Telemetry sources include auditd file access monitoring for /etc/shadow and /etc/passwd, process memory analysis for RWX segments, and tool detection via filesystem search. Negative findings are retained as CA-7 continuous monitoring evidence. Positive findings trigger immediate credential rotation and IR escalation per documented procedures."
