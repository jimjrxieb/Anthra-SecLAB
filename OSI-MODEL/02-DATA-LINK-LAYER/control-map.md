# Layer 2 Data Link — Control Map

| NIST Control | Control Name | Tool | Enterprise Equivalent | What Misconfiguration Looks Like |
|-------------|-------------|------|----------------------|--------------------------------|
| SC-7 | Boundary Protection (L2) | Wireshark, arpwatch | Cisco ISE, Aruba ClearPass | No Dynamic ARP Inspection, static ARP not set for critical systems |
| AC-3 | Access Enforcement | 802.1X, Defender for IoT | Cisco ISE NAC, ForeScout | DTP enabled on access ports, native VLAN not isolated, no 802.1X |
| SI-4 | Information System Monitoring | Wireshark, arpwatch | Darktrace, ExtraHop | No L2 monitoring, ARP changes undetected, MAC floods unalerted |
