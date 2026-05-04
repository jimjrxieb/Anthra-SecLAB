# Phishing Compromise — Governance

## NIST 800-53 Control Mapping

| Control | Name | How This Scenario Demonstrates Compliance |
|---------|------|------------------------------------------|
| IR-4 | Incident Handling | Full response lifecycle documented and followed |
| AT-2 | Awareness and Training | Phishing compromise response includes user notification and training touchpoint |
| IA-2 | Identification and Authentication | MFA re-enrollment and credential reset demonstrate authenticator management |
| SI-4 | Information System Monitoring | Detection of post-click activity demonstrates active monitoring |

## MITRE ATT&CK

- **Tactics:** Initial Access, Defense Evasion
- **Techniques:** T1566 (Phishing), T1078 (Valid Accounts)

## Audit Narrative

"The organization maintains a documented phishing compromise response procedure. Upon confirmed click, analysts immediately lock the account, terminate sessions, and assess scope. Evidence collection covers email artifacts, process tree analysis, account activity review, and persistence checks. Remediation includes credential rotation, MFA re-enrollment, IOC blocking, and user awareness notification. Evidence collected per the checklist supports IR-4, IA-2, and AT-2 audit requirements."
