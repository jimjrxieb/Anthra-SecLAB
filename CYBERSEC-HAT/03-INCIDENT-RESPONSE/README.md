# 03 — Incident Response

## What This Function Covers

Full lifecycle incident response: declaration, containment, investigation, eradication, recovery, and post-incident review. A 3-5 year analyst runs the first three phases independently and coordinates the last three with senior staff and management.

IR is not improvised. Every step follows a playbook. Evidence is preserved before remediation. The timeline is reconstructed before anything is deleted.

## Why It Matters

How you respond to an incident determines whether you contain the damage or extend it. Rebooting before memory capture destroys forensic evidence. Resetting passwords before scoping lateral movement tips off an attacker who then escalates. The order of operations matters.

## NIST 800-53 Controls

| Control ID | Control Name | What It Requires |
|-----------|-------------|-----------------|
| IR-4 | Incident Handling | Documented incident handling capability covering preparation through lessons learned |
| IR-5 | Incident Monitoring | Track and document security incidents |
| IR-6 | Incident Reporting | Report incidents to appropriate authorities within defined timeframes |
| IR-8 | Incident Response Plan | Maintain a tested incident response plan |

## Tools

| Tool | Type | Cost | Purpose |
|------|------|------|---------|
| TheHive | Open source | Free | Incident case management, evidence tracking |
| Velociraptor | Open source | Free | Live forensics, evidence collection at scale |
| Volatility | Open source | Free | Memory forensics |
| Autopsy / Sleuth Kit | Open source | Free | Disk forensics |
| IRIS | Open source | Free | Collaborative IR platform |
| Wireshark / tcpdump | Open source | Free | Network packet capture |

## Scenarios

| Scenario | ATT&CK Coverage | What It Tests |
|----------|----------------|---------------|
| [Ransomware Response](scenarios/ransomware-response/) | T1486, T1490 | Contain → isolate → preserve → eradicate → recover |
| [Phishing Compromise](scenarios/phishing-compromise/) | T1566, T1078 | Account reset → scope blast radius → MFA enforce |
| [Credential Theft Response](scenarios/credential-theft-response/) | T1003, T1550 | Credential rotation → session kill → lateral movement audit |
