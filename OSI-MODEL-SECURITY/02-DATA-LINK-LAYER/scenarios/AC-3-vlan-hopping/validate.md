# AC-3 VLAN Hopping — Validate

## Validation Steps

### 1. Verify DTP Is Disabled on All Access Ports

```
# On each switch, check every access port
show interface switchport | include Name|Administrative Mode|Operational Mode|Negotiation

# Expected result for every access port:
#   Administrative Mode: static access
#   Operational Mode: static access
#   Negotiation of Trunking: Off
```

**Pass criteria:** No access port shows "dynamic desirable" or "dynamic auto". All show "static access" with negotiation "Off".

### 2. Verify Native VLAN Is Changed From Default

```
# Check native VLAN on all trunk ports
show interface trunk

# Expected result:
#   Native VLAN should NOT be 1
#   Should be an unused VLAN (e.g., 999)
```

```
# Verify the native VLAN has no access ports
show vlan brief | include 999

# Expected: VLAN 999 exists but has no ports assigned
```

**Pass criteria:** Native VLAN on all trunk ports is not VLAN 1. The designated native VLAN has no access ports and no IP interface.

### 3. Verify Native VLAN Tagging

```
# Check if dot1q native tagging is enabled globally
show running-config | include vlan dot1q tag native

# Expected: "vlan dot1q tag native" is present
```

**Pass criteria:** Global native VLAN tagging is enabled.

### 4. Verify VLAN Pruning

```
# Check allowed VLANs on each trunk port
show interface trunk

# Look at "Vlans allowed on trunk" column
# Expected: only VLANs in active use, not "1-4094" (the default)
```

**Pass criteria:** Each trunk port only allows VLANs that need to traverse it. No trunk allows all 4094 VLANs.

### 5. Verify Unused Ports Are Shut Down

```
# Check for ports that are up but have no connected device
show interface status | include notconnect

# These should be shut down and assigned to a black-hole VLAN
show running-config | section interface.*0/40
# Expected: "shutdown" and "switchport access vlan 998"
```

**Pass criteria:** All unused ports are administratively shut down and assigned to an unused VLAN.

### 6. Re-Test Double Tagging (Tabletop)

Walk through the double-tagging attack path after remediation:

1. Attacker sends a double-tagged frame with outer tag = VLAN 999 (new native VLAN)
2. **Question:** Is the attacker on VLAN 999? **Expected answer:** No — VLAN 999 has no access ports
3. Since the attacker is not on the native VLAN, the first switch will not strip the outer tag
4. **Result:** Double-tagging attack fails because the outer tag does not match the native VLAN

If `vlan dot1q tag native` is also enabled:
1. Even if the outer tag matches the native VLAN, the switch tags it instead of stripping it
2. The frame arrives at the next switch with both tags intact
3. **Result:** Double-tagging attack fails because neither tag is stripped

### 7. Re-Test Switch Spoofing (Tabletop)

Walk through the DTP negotiation attack path after remediation:

1. Attacker sends DTP negotiation frames to an access port
2. **Question:** Is the port in `dynamic auto` or `dynamic desirable` mode? **Expected answer:** No — all ports are `switchport mode access` with `switchport nonegotiate`
3. The switch ignores DTP frames because negotiation is disabled
4. **Result:** Switch spoofing attack fails because trunk negotiation is not possible

## Validation Evidence

| Check | Pass Criteria | Evidence |
|-------|-------------|----------|
| DTP disabled | All access ports: static access, negotiation off | `show interface switchport` output |
| Native VLAN changed | No trunk uses VLAN 1 as native | `show interface trunk` output |
| Native VLAN tagging | `vlan dot1q tag native` present | `show running-config` excerpt |
| VLAN pruning | No trunk allows all VLANs | `show interface trunk` output |
| Unused ports down | All notconnect ports are shutdown | `show interface status` output |
| Double-tagging re-test | Attack fails (tabletop confirmed) | Tabletop walkthrough notes |
| Switch spoofing re-test | Attack fails (tabletop confirmed) | Tabletop walkthrough notes |

## Overall Validation Result

All 7 checks must pass for VLAN hopping to be considered mitigated. Any failure means the segmentation boundary is still bypassable and the remediation is incomplete.
