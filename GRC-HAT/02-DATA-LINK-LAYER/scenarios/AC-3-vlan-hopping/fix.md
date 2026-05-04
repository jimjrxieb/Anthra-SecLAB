# AC-3 VLAN Hopping — Fix

## Remediation Steps

### Immediate (0-30 days)

1. **Disable DTP on all access ports**
   - DTP allows dynamic trunk negotiation, which is the switch spoofing attack vector
   - Set every access port to `switchport mode access` explicitly
   - Cisco IOS:
     ```
     interface range GigabitEthernet0/1-48
      switchport mode access
      switchport nonegotiate
     ```
   - The `nonegotiate` command prevents DTP frames from being sent or processed
   - **This single change eliminates the switch spoofing attack entirely**

2. **Set the native VLAN to an unused VLAN on all trunk ports**
   - The native VLAN is untagged on trunks — this is what double-tagging exploits
   - Change it from VLAN 1 (default) to a dedicated unused VLAN (e.g., VLAN 999)
   - Cisco IOS:
     ```
     interface GigabitEthernet0/49
      switchport trunk native vlan 999
     ```
   - Ensure VLAN 999 has no access ports and no IP interface — it is a black hole
   - **This eliminates the double-tagging attack vector**

3. **Explicitly tag the native VLAN on trunks**
   - Forces the switch to tag native VLAN traffic instead of sending it untagged
   - Cisco IOS (global):
     ```
     vlan dot1q tag native
     ```
   - This provides defense-in-depth: even if native VLAN is misconfigured, double-tagging fails because both tags are preserved

### Short-term (30-90 days)

1. **Prune unused VLANs from all trunk ports**
   - Only allow VLANs that need to traverse each trunk link
   - Cisco IOS:
     ```
     interface GigabitEthernet0/49
      switchport trunk allowed vlan 10,20,30,999
     ```
   - Reduces blast radius if trunk is compromised — attacker can only reach allowed VLANs

2. **Assign all access ports to their correct VLAN explicitly**
   - Do not leave any port on VLAN 1 (the default)
   - Cisco IOS:
     ```
     interface GigabitEthernet0/1
      switchport access vlan 10
     ```
   - Unused ports should be assigned to a black-hole VLAN and shut down:
     ```
     interface range GigabitEthernet0/40-48
      switchport access vlan 998
      shutdown
     ```

3. **Enable port security on access ports**
   - Limits the number of MAC addresses per port
   - Prevents MAC flooding attacks that can force switches into hub mode
   - Cisco IOS:
     ```
     interface GigabitEthernet0/1
      switchport port-security
      switchport port-security maximum 2
      switchport port-security violation restrict
      switchport port-security aging time 60
     ```

### Long-term (90+ days)

1. **Deploy 802.1X port-based network access control**
   - Authenticates devices before granting VLAN access
   - Dynamic VLAN assignment based on device identity
   - Prevents unauthorized devices from connecting at all

2. **Implement Private VLANs (PVLANs) for sensitive segments**
   - PVLANs provide isolation within a VLAN — hosts cannot communicate with each other
   - Useful for DMZ, guest networks, and server farms
   - Cisco IOS:
     ```
     vlan 100
      private-vlan primary
     vlan 101
      private-vlan isolated
     vlan 100
      private-vlan association 101
     ```

3. **Replace VLAN-only segmentation with micro-segmentation**
   - VLANs are a coarse segmentation control — firewall rules between VLANs provide fine-grained enforcement
   - Deploy inter-VLAN routing through a firewall (not a Layer 3 switch) for sensitive segments
   - Consider Zero Trust Network Access (ZTNA) for critical workloads

## Implementation Cost Estimate

| Control | One-time Cost | Annual Cost | Notes |
|---------|-------------|-------------|-------|
| Disable DTP / set access mode | $0 (config) | $0 | Switch configuration change only |
| Native VLAN change | $0 (config) | $0 | Requires change window for trunk ports |
| VLAN pruning | $0 (config) | $0 | Requires VLAN inventory first |
| Port security | $0 (config) | $0 | Built into managed switches |
| Unused port shutdown | $0 (config) | $0 | Requires port inventory |
| 802.1X deployment | $5,000-$15,000 | $2,000/yr | RADIUS server + supplicant config |
| Private VLANs | $0 (config) | $0 | Requires supported switch models |
| Micro-segmentation | $15,000-$50,000 | $5,000-$15,000/yr | Firewall + policy management |

## Priority Recommendation

Start with disabling DTP and changing the native VLAN. These two configuration changes take 30 minutes per switch, cost nothing, and eliminate both VLAN hopping attack vectors completely. There is no reason for DTP to be enabled on access ports in any production environment. Every switch should have `switchport mode access` and `switchport nonegotiate` on every access port as a baseline configuration standard.
