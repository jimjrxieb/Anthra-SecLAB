# T1055 Process Injection — Governance

## NIST 800-53 Control Mapping

| Control | Name | How This Scenario Demonstrates Compliance |
|---------|------|------------------------------------------|
| SI-4 | Information System Monitoring | Memory analysis hunt detects injection beyond signature-based coverage |
| CA-7 | Continuous Monitoring | Documented hunt satisfies continuous monitoring evidence |
| SI-7 | Software, Firmware, and Information Integrity | Process integrity checking (deleted exe detection) demonstrates SI-7 |
| SC-39 | Process Isolation | ptrace_scope hardening demonstrates process isolation controls |

## MITRE ATT&CK

- **Tactic:** Defense Evasion / Privilege Escalation
- **Technique:** T1055 — Process Injection

## Audit Narrative

"The organization conducts proactive threat hunting for process injection techniques aligned to ATT&CK T1055. Hunts analyze process memory maps for anonymous executable segments, review parent-child process relationships for unusual spawning patterns, and detect deleted-executable processes indicative of anti-forensic behavior. Positive findings trigger immediate host isolation and memory preservation. The ptrace_scope kernel parameter is hardened to restrict cross-process memory inspection. Hunt documentation satisfies CA-7 continuous monitoring requirements."
