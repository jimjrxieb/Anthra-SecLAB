# T1021.001 Lateral Movement — Governance

## NIST 800-53 Control Mapping

| Control | Name | How This Scenario Demonstrates Compliance |
|---------|------|------------------------------------------|
| SI-4 | Information System Monitoring | Hunt detects lateral movement patterns beyond automated alert thresholds |
| CA-7 | Continuous Monitoring | Documented hunt provides CA-7 continuous monitoring evidence |
| AC-17 | Remote Access | Remote access monitoring and restriction demonstrate AC-17 implementation |
| SC-7 | Boundary Protection | Network segmentation remediation demonstrates SC-7 internal boundary controls |

## MITRE ATT&CK

- **Tactic:** Lateral Movement
- **Technique:** T1021.001 — Remote Services: Remote Desktop Protocol

## Audit Narrative

"The organization conducts proactive threat hunting for lateral movement via remote services aligned to ATT&CK T1021.001. Hunts analyze internal SSH and RDP authentication patterns against a documented baseline to identify new source-destination pairs, off-hours activity, and rapid multi-host access by single accounts. Positive findings trigger account lockout, session termination, and network segmentation remediation. Hunt documentation satisfies CA-7 requirements and demonstrates active monitoring of remote access per AC-17."
