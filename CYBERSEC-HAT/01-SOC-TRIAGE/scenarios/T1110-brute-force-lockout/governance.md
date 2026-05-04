# T1110 Brute Force — Governance

## NIST 800-53 Control Mapping

| Control | Name | How This Scenario Demonstrates Compliance |
|---------|------|------------------------------------------|
| AC-7 | Unsuccessful Logon Attempts | Lockout policy and brute force detection demonstrate AC-7 implementation |
| SI-4 | Information System Monitoring | Detection of failure spikes demonstrates active monitoring |
| SC-5 | Denial of Service Protection | Rate limiting and IP blocking demonstrate DoS-adjacent control |
| IA-5 | Authenticator Management | Password-based brute force highlights authentication hardening requirements |

## MITRE ATT&CK

- **Tactic:** Credential Access
- **Technique:** T1110 — Brute Force

## Audit Narrative

"The organization monitors for brute force activity through SIEM detection rules that alert on failed login volume thresholds. Analysts follow a documented triage procedure to identify attacking sources, assess whether any accounts were successfully compromised, and implement IP-based blocks and account lockout enforcement. Evidence collected per the checklist supports audit trail requirements under AC-7, SI-4, and IR-6."
