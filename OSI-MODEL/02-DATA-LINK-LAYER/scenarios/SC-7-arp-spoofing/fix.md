# SC-7 ARP Spoofing — Fix

## Remediation Steps

### Immediate (0-30 days)

1. **Deploy Dynamic ARP Inspection (DAI)** on all managed switches
   - DAI validates ARP packets against the DHCP snooping binding table
   - Drops ARP packets with invalid IP-to-MAC bindings
   - Cisco IOS example:
     ```
     ip dhcp snooping
     ip dhcp snooping vlan 10,20,30
     ip arp inspection vlan 10,20,30
     ip arp inspection validate src-mac dst-mac ip
     ```
   - Configure trusted ports (uplinks, DHCP servers):
     ```
     interface GigabitEthernet0/1
      ip arp inspection trust
      ip dhcp snooping trust
     ```

2. **Enable DHCP snooping** (required for DAI to function)
   - DHCP snooping builds the binding table that DAI validates against
   - Without it, DAI has no reference for legitimate IP-to-MAC pairs
   - Cisco IOS example:
     ```
     ip dhcp snooping
     ip dhcp snooping vlan 10,20,30
     interface range GigabitEthernet0/1-48
      ip dhcp snooping limit rate 15
     ```

3. **Set static ARP entries for critical infrastructure**
   - Gateway routers, DNS servers, domain controllers, management interfaces
   - These should never change and static entries prevent poisoning
   - Linux:
     ```bash
     arp -s 192.168.1.1 aa:bb:cc:dd:ee:ff
     ```
   - Windows:
     ```powershell
     netsh interface ip add neighbors "Ethernet" 192.168.1.1 aa-bb-cc-dd-ee-ff
     ```
   - Cisco IOS:
     ```
     arp 192.168.1.100 aabb.ccdd.eeff ARPA
     ```

### Short-term (30-90 days)

1. **Deploy arpwatch on critical network segments**
   - Monitors all ARP traffic and alerts on changes
   - Detects new stations, flip-flops, and MAC changes
   - Configure email alerts for real-time notification:
     ```bash
     arpwatch -i eth0 -m security-alerts@company.com
     ```

2. **Implement ARP rate limiting**
   - Prevents ARP flood attacks that overwhelm switch CAM tables
   - Cisco IOS:
     ```
     ip arp inspection limit rate 15 burst interval 1
     ```

3. **Segment critical systems into dedicated VLANs**
   - Reduce the blast radius of any successful ARP spoofing
   - Management, databases, and user workstations on separate VLANs
   - Apply DAI per-VLAN so each segment is independently protected

### Long-term (90+ days)

1. **Deploy 802.1X port-based NAC**
   - Authenticates every device before granting network access
   - Prevents unauthorized devices from reaching the L2 segment at all
   - Combined with DAI, this creates defense-in-depth at the data link layer

2. **Implement network detection and response (NDR)**
   - Tools like Darktrace, ExtraHop, or Zeek for continuous L2 monitoring
   - Detects ARP anomalies, MAC spoofing, and lateral movement patterns
   - Integrates with SIEM for correlated alerting

3. **Enable MACsec (802.1AE) on switch-to-switch links**
   - Encrypts L2 frames between switches
   - Prevents ARP spoofing on trunk links and mitigates man-in-the-middle even if ARP cache is poisoned

## Implementation Cost Estimate

| Control | One-time Cost | Annual Cost | Notes |
|---------|-------------|-------------|-------|
| DAI + DHCP snooping | $0 (config) | $0 | Built into managed switches, just needs enabling |
| Static ARP entries | $500 | $200/yr | Staff time for documentation and maintenance |
| arpwatch deployment | $0 (open source) | $500/yr | Monitoring and alert tuning |
| ARP rate limiting | $0 (config) | $0 | Built into managed switches |
| 802.1X deployment | $5,000-$15,000 | $2,000/yr | RADIUS server + switch config + enrollment |
| NDR solution | $20,000-$80,000 | $15,000-$40,000/yr | Darktrace/ExtraHop licensing |
| MACsec | $0-$5,000 | $0 | Requires compatible hardware |

## Priority Recommendation

Start with DAI + DHCP snooping. It costs nothing beyond configuration time, it is built into every managed switch, and it eliminates the most common ARP spoofing attack vector immediately. Static ARP entries for critical systems take 30 minutes and add a second layer. Everything after that is hardening an already-protected environment.
