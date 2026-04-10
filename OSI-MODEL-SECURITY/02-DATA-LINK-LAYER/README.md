# Layer 2 — Data Link

## What This Layer Covers

MAC address security, switch port security, ARP protection, VLAN segmentation, 802.1X network access control. This is where devices identify each other on a local network segment.

## Why It Matters

ARP spoofing lets an attacker intercept all traffic between two hosts without either knowing. VLAN hopping breaks network segmentation that the entire security architecture relies on. These are not theoretical attacks — they are the first thing a penetration tester runs after getting on a network.

## NIST 800-53 Controls

| Control ID | Control Name | What It Requires |
|-----------|-------------|-----------------|
| SC-7 | Boundary Protection (L2) | Network segmentation at the switch level |
| AC-3 | Access Enforcement | Port-level access control (802.1X, MAC filtering) |
| SI-4 | Information System Monitoring | L2 anomaly detection (ARP changes, MAC floods) |

## Tools

| Tool | Type | Cost | Purpose |
|------|------|------|---------|
| Wireshark | Open source | Free | Packet capture, ARP analysis, 802.1Q inspection |
| Microsoft Defender for IoT | Microsoft | Free tier | OT/IoT network monitoring, L2 anomaly detection |
| arpwatch | Open source | Free | ARP change detection and alerting |
| macchanger | Open source | Free | MAC spoofing for break scenarios |

## Scenarios

| Scenario | Control | Format |
|----------|---------|--------|
| [SC-7 ARP Spoofing](scenarios/SC-7-arp-spoofing/) | SC-7 | Scripts (.sh) |
| [AC-3 VLAN Hopping](scenarios/AC-3-vlan-hopping/) | AC-3 | Tabletop (.md) |
