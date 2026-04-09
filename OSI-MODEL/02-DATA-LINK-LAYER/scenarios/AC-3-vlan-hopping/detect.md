# AC-3 VLAN Hopping — Detect

## Detection Methods

### 1. Wireshark 802.1Q Analysis

Capture traffic on a trunk port or SPAN/mirror port and analyze for VLAN hopping indicators.

**Double-tagging detection:**
```
# Wireshark display filter: frames with double 802.1Q tags
vlan.id && vlan.id
```

```
# tshark CLI: capture and filter for double-tagged frames
tshark -i eth0 -Y "vlan && vlan" -T fields -e eth.src -e vlan.id
```

**What to look for:**
- Frames with two 802.1Q headers (double-tagged)
- Traffic from an access port appearing on a VLAN it should not be on
- Frames with the native VLAN as the outer tag and a different VLAN as the inner tag

### 2. Switch Log Review

**DTP negotiation detection:**
```
# Cisco IOS: check for DTP negotiation events
show interface trunk
show dtp interface <interface>

# Look for:
# - Access ports that have negotiated trunk mode
# - Unexpected trunk links
# - DTP frames on ports that should be access-only
```

**Port status audit:**
```
# Cisco IOS: verify all access ports are in access mode (not dynamic)
show interface status

# Look for ports in "desirable" or "auto" mode — these can negotiate trunks
show interface switchport | include Name|Administrative Mode|Operational Mode
```

### 3. MAC Address Table Anomalies

```
# Cisco IOS: check for MAC addresses appearing on unexpected VLANs
show mac address-table

# Look for:
# - A MAC address appearing on multiple VLANs simultaneously
# - MAC addresses on VLANs they are not assigned to
# - Rapid changes in MAC-to-VLAN mapping
```

### 4. SPAN/Mirror Port Monitoring

Configure a SPAN session to mirror trunk traffic to a monitoring host:

```
# Cisco IOS: mirror trunk port to monitoring port
monitor session 1 source interface GigabitEthernet0/1
monitor session 1 destination interface GigabitEthernet0/48
```

Then capture on the monitoring host:
```bash
# Capture all 802.1Q tagged traffic
tshark -i eth0 -Y "vlan" -T fields \
    -e frame.number -e eth.src -e eth.dst -e vlan.id -e ip.src -e ip.dst
```

## Evidence to Collect

| Evidence | Format | Purpose |
|----------|--------|---------|
| `show interface trunk` output | Text | Proves which ports are trunking |
| `show dtp` output | Text | Shows DTP negotiation state per port |
| `show interface switchport` output | Text | Shows admin vs operational mode |
| Double-tagged frame capture | PCAP | Proves double-tagging attack |
| DTP negotiation frame capture | PCAP | Proves switch spoofing attempt |
| MAC address table snapshot | Text | Shows MAC-to-VLAN mapping anomalies |

## Expected Findings

**If DTP is enabled on access ports:** "AC-3 finding — DTP enabled on access ports allows trunk negotiation. Attacker can join all VLANs by spoofing DTP frames."

**If native VLAN is VLAN 1 on trunks:** "SC-7 finding — native VLAN on trunk ports is VLAN 1 (default). Double-tagging attack possible from any port on VLAN 1."

**If unused VLANs are not pruned:** "AC-3 finding — unused VLANs are allowed on trunk ports. Attacker who negotiates a trunk link can reach all VLANs, not just active ones."
