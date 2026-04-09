# Layer 2 Data Link — Implement Controls

## Purpose

Implement data link layer security controls based on assessment findings. Start with highest-risk gaps from the 01-assess output. Layer 2 controls are almost entirely configuration changes on existing switches — the cost is staff time, not product licenses.

## Implementation Order

Priority by risk and cost-efficiency:

### Priority 1: Switch Hardening Baseline (Week 1, ~$0 — config only)

These are zero-cost configuration changes that eliminate both VLAN hopping attack vectors.

1. **Disable DTP on all access ports**
   ```
   interface range GigabitEthernet0/1-48
    switchport mode access
    switchport nonegotiate
   ```
2. **Change native VLAN on all trunk ports from VLAN 1 to unused VLAN**
   ```
   interface GigabitEthernet0/49
    switchport trunk native vlan 999
   ```
3. **Enable native VLAN tagging globally**
   ```
   vlan dot1q tag native
   ```
4. **Shut down unused switch ports and assign to black-hole VLAN**
   ```
   interface range GigabitEthernet0/40-48
    switchport access vlan 998
    shutdown
   ```
5. **Assign all active access ports to their correct VLAN explicitly**
   ```
   interface GigabitEthernet0/1
    switchport access vlan 10
   ```

### Priority 2: ARP Protection (Week 1-2, ~$500 staff time)

1. Enable DHCP snooping on all access VLANs
   ```
   ip dhcp snooping
   ip dhcp snooping vlan 10,20,30
   ```
2. Configure trusted ports (uplinks, DHCP servers)
   ```
   interface GigabitEthernet0/49
    ip dhcp snooping trust
   ```
3. Enable Dynamic ARP Inspection on all access VLANs
   ```
   ip arp inspection vlan 10,20,30
   ip arp inspection validate src-mac dst-mac ip
   ```
4. Configure ARP rate limiting on access ports
   ```
   ip arp inspection limit rate 15 burst interval 1
   ```
5. Set static ARP entries for critical infrastructure (gateways, DNS, DCs)
   ```
   arp 192.168.1.1 aabb.ccdd.eeff ARPA
   ```

### Priority 3: Access Control and Monitoring (Week 2-4, ~$1,000 staff time)

1. Enable port security on access ports
   ```
   interface range GigabitEthernet0/1-24
    switchport port-security
    switchport port-security maximum 2
    switchport port-security violation restrict
   ```
2. Prune unused VLANs from all trunk ports
   ```
   interface GigabitEthernet0/49
    switchport trunk allowed vlan 10,20,30,999
   ```
3. Deploy arpwatch on critical network segments
   ```bash
   apt-get install arpwatch
   arpwatch -i eth0 -m security-alerts@company.com
   ```
4. Forward switch logs to SIEM
5. Configure SPAN port for network analysis on critical segments

### Priority 4: Advanced Controls (Month 2-6, ~$5,000-$15,000)

1. Deploy 802.1X port-based NAC with RADIUS
2. Implement Private VLANs for DMZ and sensitive segments
3. Deploy NDR solution (Zeek, Darktrace, or ExtraHop) for continuous L2 monitoring
4. Enable MACsec (802.1AE) on switch-to-switch links where supported

## Change Management Notes

- **Priority 1 and 2 changes require a maintenance window.** Incorrect DHCP snooping or DAI configuration can block legitimate traffic. Test on a non-production switch first.
- **Native VLAN changes on trunk ports must be coordinated.** Both ends of a trunk must match or traffic will black-hole.
- **Document the before and after configuration for every switch.** Save `show running-config` before and after changes.

## Verification After Each Implementation

After each control is implemented, run the corresponding scenario's `validate.sh` or `validate.md` to confirm it works. Do not proceed to the next priority without validation.
