# Layer 3 Network — Control Map

| NIST Control | Control Name | Tool | Enterprise Equivalent | What Misconfiguration Looks Like |
|-------------|-------------|------|----------------------|--------------------------------|
| SC-7 | Boundary Protection | Azure NSGs, Windows Firewall, pfSense | Palo Alto, Fortinet, Cisco ASA | Inbound 0.0.0.0/0 on management ports, no egress filtering |
| AC-4 | Information Flow Enforcement | Suricata, pfSense | Palo Alto segmentation, Illumio | Flat network, all subnets can reach all subnets, no DMZ |
| SI-3 | Malicious Code Protection | Suricata (IPS mode) | CrowdStrike Falcon, Palo Alto WildFire | No IPS signatures, outdated rules, IDS in passive-only mode |
| SI-4 | Information System Monitoring | Suricata, Azure NSG flow logs | Splunk ES, Sentinel, Darktrace | No flow logging, no alerting on suspicious traffic patterns |
