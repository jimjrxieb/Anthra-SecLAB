# Missing MFA Enforcement — Governance

## NIST 800-53 Control Mapping

| Control | Name | How This Scenario Demonstrates Compliance |
|---------|------|------------------------------------------|
| IA-2 | Identification and Authentication | MFA enforcement for privileged and remote access users directly satisfies IA-2(1) and IA-2(2) |
| AC-7 | Unsuccessful Logon Attempts | Account lockout and MFA together prevent brute force credential attacks |
| IA-5 | Authenticator Management | TOTP enrollment procedure and key management demonstrate IA-5 |
| AC-2 | Account Management | Scoping MFA enforcement to privileged accounts demonstrates account risk classification |

## Regulatory Alignment

- **PCI DSS 8.4:** MFA required for all access to cardholder data environment
- **HIPAA:** MFA is a recognized safeguard for electronic PHI access
- **FedRAMP:** MFA required for all privileged user accounts (IA-2 HIGH baseline)
- **CMMC Level 2:** MFA required for all accounts with access to CUI

## Audit Narrative

"The organization enforces multi-factor authentication for all privileged accounts and all accounts with remote access capability per IA-2. PAM-based TOTP enforcement ensures MFA is required for SSH sessions. NOPASSWD sudo rules have been reviewed and removed. All privileged accounts have completed MFA enrollment. Evidence per the checklist demonstrates compliance with IA-2(1), IA-2(2), and AC-7."
