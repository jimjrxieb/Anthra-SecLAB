# T1059.001 Malicious Scripting — Governance

## NIST 800-53 Control Mapping

| Control | Name | How This Scenario Demonstrates Compliance |
|---------|------|------------------------------------------|
| SI-4 | Information System Monitoring | Detection of encoded commands and script execution demonstrates monitoring |
| AU-12 | Audit Record Generation | auditd execve coverage demonstrates process execution auditing |
| CM-7 | Least Functionality | Script execution controls and noexec mounts demonstrate functionality restriction |
| SI-3 | Malicious Code Protection | Detection and remediation of malicious scripts demonstrates SI-3 coverage |

## MITRE ATT&CK

- **Tactic:** Execution
- **Technique:** T1059.001 — Command and Scripting Interpreter

## Audit Narrative

"The organization monitors for malicious script execution through auditd-based process execution logging and SIEM detection rules that surface encoded commands and unusual interpreter invocations. Analysts follow a documented triage procedure that includes script decoding, process tree analysis, network activity review, and persistence checking. Confirmed malicious execution triggers isolation, artifact preservation, C2 blocking, and persistence cleanup. Evidence collected per the checklist supports audit trail requirements under SI-4, AU-12, and IR-6."
