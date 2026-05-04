# T1078 Valid Account Abuse — Governance

## NIST 800-53 Control Mapping

| Control | Name | How This Scenario Demonstrates Compliance |
|---------|------|------------------------------------------|
| IA-4 | Identifier Management | Account review and session management demonstrate identifier lifecycle controls |
| AC-2 | Account Management | Account disable/reset procedure demonstrates account management controls |
| SI-4 | Information System Monitoring | Detection of off-hours and multi-location logins demonstrates active monitoring |
| AC-17 | Remote Access | Login pattern analysis covers remote access monitoring requirements |

## MITRE ATT&CK

- **Tactic:** Initial Access / Defense Evasion / Persistence
- **Technique:** T1078 — Valid Accounts

## Audit Narrative

"The organization monitors for valid account abuse through SIEM detection rules that identify impossible travel, off-hours access, and multi-location logins. Analysts follow a documented triage procedure that includes account history review, user verification, and post-login activity analysis. Confirmed account compromise triggers immediate session termination, password reset, MFA revocation, and re-enrollment. Evidence collected per the checklist supports audit trail requirements under AC-2, IA-4, and IR-6."
