# Exposed Management Ports — Governance

## NIST 800-53 Control Mapping

| Control | Name | How This Scenario Demonstrates Compliance |
|---------|------|------------------------------------------|
| SC-7 | Boundary Protection | Firewall restriction of management ports demonstrates boundary protection |
| CM-7 | Least Functionality | Disabling Telnet, restricting services demonstrates minimal functionality |
| AC-17 | Remote Access | SSH hardening (key-only, no root, MFA) demonstrates remote access controls |
| SI-4 | Information System Monitoring | fail2ban and auth.log monitoring demonstrate active monitoring |

## MITRE ATT&CK

- **Tactics:** Initial Access
- **Techniques:** T1190 (Exploit Public-Facing Application), T1021.004 (SSH)

## Audit Narrative

"The organization detects and remediates exposed management ports through regular vulnerability scanning (RA-5) and network exposure assessments. SSH is hardened per CIS Benchmark L1 requirements: no root login, key-based authentication only, source IP restriction via iptables, and brute-force protection via fail2ban. Telnet is permanently disabled and masked. Evidence collected per the checklist demonstrates SC-7 boundary protection and CM-7 least functionality compliance."
