# Ransomware Response — Governance

## NIST 800-53 Control Mapping

| Control | Name | How This Scenario Demonstrates Compliance |
|---------|------|------------------------------------------|
| IR-4 | Incident Handling | Full lifecycle response procedure (contain, investigate, eradicate, recover, review) |
| IR-5 | Incident Monitoring | Detection script and evidence collection demonstrate ongoing incident monitoring |
| IR-6 | Incident Reporting | Communication steps and notification triggers demonstrate reporting compliance |
| CP-9 | Information System Backup | Backup verification step in recovery demonstrates backup controls |
| CP-10 | Information System Recovery | Recovery procedure demonstrates restoration capability |

## MITRE ATT&CK

- **Tactic:** Impact
- **Techniques:** T1486 (Data Encrypted for Impact), T1490 (Inhibit System Recovery)

## Regulatory Considerations

- **HIPAA:** PHI encrypted by ransomware = presumptive breach. 60-day notification to HHS.
- **PCI DSS:** Cardholder data environment affected = mandatory breach notification.
- **GDPR:** Personal data affected = 72-hour notification to supervisory authority.
- **State Laws:** Many US states have breach notification requirements (California, New York).

Engage Legal immediately for P1 ransomware incidents.

## Audit Narrative

"The organization maintains a documented ransomware incident response procedure aligned to ATT&CK T1486 and T1490. The procedure covers immediate detection, host isolation, scope assessment, evidence preservation, eradication, backup-based recovery, and hardening. Communication and escalation procedures are defined for P1 incidents including legal notification triggers. Evidence artifacts collected per the checklist support IR-4, IR-5, and CP-9 audit requirements."
