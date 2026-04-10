# Layer 2 Data Link — Assess Current State

## Purpose

Document the current data link layer security posture before implementing any controls. This assessment establishes the baseline for measuring improvement. Layer 2 is where network segmentation lives — if these controls are missing, every network security control above them is built on sand.

## Assessment Checklist

### SC-7 ARP Protection

- [ ] Is Dynamic ARP Inspection (DAI) enabled? On which VLANs?
- [ ] Is DHCP snooping enabled? (Required for DAI to function)
- [ ] Are DHCP snooping trusted ports correctly configured? (Uplinks, DHCP servers only)
- [ ] Are static ARP entries configured for critical systems? (Gateways, DNS, DCs)
- [ ] Is ARP rate limiting configured on access ports?
- [ ] Is arpwatch or equivalent ARP monitoring deployed?
- [ ] When was the last test for ARP spoofing susceptibility?

### AC-3 VLAN Segmentation and Access Enforcement

- [ ] What VLANs exist? Map them (ID, name, purpose, subnet)
- [ ] Are all access ports explicitly set to `switchport mode access`?
- [ ] Is DTP disabled on all access ports? (`switchport nonegotiate`)
- [ ] What is the native VLAN on trunk ports? (Should NOT be VLAN 1)
- [ ] Is native VLAN tagging enabled? (`vlan dot1q tag native`)
- [ ] Are unused VLANs pruned from trunk ports?
- [ ] Are unused switch ports shut down and assigned to a black-hole VLAN?
- [ ] Is port security enabled on access ports? What are the MAC limits?
- [ ] Is 802.1X deployed? On which ports? What authentication method?

### SI-4 Layer 2 Monitoring

- [ ] Is there any L2-specific monitoring in place? (arpwatch, NDR, SPAN)
- [ ] Are switch logs forwarded to a SIEM?
- [ ] Are MAC address table changes monitored?
- [ ] Are trunk port state changes alerted on?
- [ ] Is there a SPAN/mirror port configured for network analysis?
- [ ] Are 802.1Q anomalies (double-tagged frames) detectable?

### Switch Configuration Baseline

- [ ] Export running configuration from all managed switches
- [ ] Document firmware versions — are they current?
- [ ] Are management interfaces on a dedicated management VLAN?
- [ ] Is SSH enabled and Telnet disabled for switch management?
- [ ] Are SNMP community strings changed from defaults?
- [ ] Are switch management ACLs configured?

## Output

Complete the checklist above and produce:
1. VLAN inventory spreadsheet (ID, name, purpose, subnet, ports)
2. Switch configuration audit (DTP status, native VLAN, port security per port)
3. Gap analysis: which SC-7, AC-3, and SI-4 controls have findings?
4. Risk ranking of findings using 5x5 matrix
