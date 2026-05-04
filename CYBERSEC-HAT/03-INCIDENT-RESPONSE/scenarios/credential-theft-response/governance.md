# Credential Theft Response — Governance

## NIST 800-53 Control Mapping

| Control | Name | How This Scenario Demonstrates Compliance |
|---------|------|------------------------------------------|
| IR-4 | Incident Handling | Full credential theft response lifecycle documented and followed |
| IA-5 | Authenticator Management | Credential rotation, MFA re-enrollment demonstrate authenticator lifecycle |
| AC-2 | Account Management | Account lockout and session termination demonstrate account management |
| AU-9 | Protection of Audit Information | auditd credential file monitoring supports audit record protection |

## MITRE ATT&CK

- **Tactics:** Credential Access, Lateral Movement
- **Techniques:** T1003 (OS Credential Dumping), T1550 (Use Alternate Authentication Material)

## Audit Narrative

"The organization maintains a documented credential theft response procedure. Detection relies on auditd monitoring of credential file access and SIEM-based detection of unusual authentication patterns. Response includes simultaneous credential rotation for all affected accounts, session termination, SSH key revocation, and API token rotation. Scope is assessed before rotation to prevent attacker escalation. Evidence collected per the checklist supports IR-4, IA-5, and AC-2 audit requirements."
