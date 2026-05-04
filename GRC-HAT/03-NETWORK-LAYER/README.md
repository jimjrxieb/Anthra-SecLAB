# Layer 3 — Network

## What This Layer Covers

IP segmentation, firewall rules, routing security, intrusion detection and prevention. This is where traffic gets routed between networks and where firewalls enforce boundaries.

## Why It Matters

A single misconfigured firewall rule — 0.0.0.0/0 inbound on RDP — is how most ransomware attacks start. A flat network with no segmentation means one compromised host gives access to everything. These are the misconfigurations that appear in every post-breach report.

## NIST 800-53 Controls

| Control ID | Control Name | What It Requires |
|-----------|-------------|-----------------|
| SC-7 | Boundary Protection | Firewall rules, perimeter defense, DMZ |
| AC-4 | Information Flow Enforcement | Network segmentation between zones |
| SI-3 | Malicious Code Protection | IPS/IDS for network-level threats |
| SI-4 | Information System Monitoring | Network traffic analysis, alerting |

## Tools

| Tool | Type | Cost | Purpose |
|------|------|------|---------|
| Azure NSGs | Microsoft | Free with Azure account | Cloud network security groups |
| Windows Defender Firewall | Microsoft | Free with Windows | Host-based firewall |
| pfSense | Open source | Free | Network firewall/router |
| Suricata | Open source | Free | IDS/IPS, network traffic analysis |
| Nmap | Open source | Free | Network scanning, port discovery |

## Scenarios

| Scenario | Control | Format |
|----------|---------|--------|
| [SC-7 Firewall Misconfiguration](scenarios/SC-7-firewall-misconfig/) | SC-7 | Scripts (.sh) |
| [AC-4 Flat Network](scenarios/AC-4-flat-network/) | AC-4 | Scripts (.sh) |
