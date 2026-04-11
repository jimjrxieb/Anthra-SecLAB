# Layer 2 — Fix AC-3: VLAN Segmentation

| Field | Value |
|-------|-------|
| NIST Control | AC-3 (Access Enforcement), AC-4 (Information Flow), SC-7 (Boundary) |
| Tools | ip, bridge, iproute2, ebtables/nftables |
| Enterprise Equivalent | Cisco ISE VLAN Assignment, Aruba ClearPass |
| Time Estimate | 1 hour |
| Rank | D |
| Trigger | FAIL on VLAN checks 10-14 in 01-assess.md |

---

## Objective

Harden VLAN segmentation to enforce information flow boundaries (AC-4) and access enforcement (AC-3). The primary risks addressed: VLAN hopping via double-tagging, unauthorized cross-VLAN traffic, and DTP exploitation.

---

## VLAN Design Principles

Before implementing, document the intended VLAN design:

| VLAN ID | Name | Purpose | Allowed Traffic |
|---------|------|---------|----------------|
| 10 | SERVERS | Production servers | HTTPS, SSH from mgmt only |
| 20 | WORKSTATIONS | End-user devices | HTTP, HTTPS, DNS |
| 30 | MANAGEMENT | Network management | SSH, SNMP, HTTPS |
| 999 | NATIVE | Native/untagged (empty) | None — no devices assigned |
| 1 | DEFAULT | Disabled/unused | Block all |

**Key principle**: VLAN 1 should carry no production traffic. VLAN 999 (or any unused VLAN) should be the native VLAN on all trunks. No devices are assigned to the native VLAN.

---

## Step 1: Change Native VLAN Away from VLAN 1

VLAN hopping via double-tagging exploits the fact that most switches use VLAN 1 as the native (untagged) VLAN on trunks. An attacker on any access port can craft a double-tagged frame with outer tag 1 and inner tag for the target VLAN.

### Cisco IOS

```
Switch# configure terminal
Switch(config)# interface GigabitEthernet0/1
Switch(config-if)# switchport trunk native vlan 999
Switch(config-if)# end

! Verify
Switch# show interfaces trunk
! Confirm: Native vlan column shows 999, not 1
Switch# copy running-config startup-config
```

### Linux Bridge

```bash
# Enable VLAN filtering on the bridge
sudo ip link set br0 type bridge vlan_filtering 1

# Remove VLAN 1 as PVID from all bridge ports
# Set VLAN 999 as the new native VLAN (PVID = Port VLAN ID)
for port in $(bridge link show | awk '{print $2}' | tr -d ':'); do
    # Remove VLAN 1 PVID
    sudo bridge vlan del dev "$port" vid 1 pvid untagged 2>/dev/null || true
    # Add VLAN 999 as native
    sudo bridge vlan add dev "$port" vid 999 pvid untagged
done

# Verify
bridge vlan show
# Confirm: port entries show 999 PVID Egress Untagged, not 1
```

---

## Step 2: Disable DTP (Dynamic Trunking Protocol)

DTP allows switches to automatically negotiate trunk mode. An attacker can send DTP frames to an access port to negotiate a trunk, gaining access to all VLANs.

### Cisco IOS (disable DTP negotiation)

```
Switch(config)# interface GigabitEthernet0/1
Switch(config-if)# switchport nonegotiate
Switch(config-if)# switchport mode access
! OR for a trunk port:
Switch(config-if)# switchport mode trunk
Switch(config-if)# switchport nonegotiate
Switch(config-if)# end
```

### Linux (no DTP equivalent, but prevent LLDP/CDP on untrusted ports)

```bash
# Disable LLDP on access-facing interfaces
# LLDP leaks VLAN info — disable on untrusted ports
if command -v lldpd &>/dev/null; then
    # Configure lldpd to disable on specific interfaces
    echo "configure system interface pattern eth0" >> /etc/lldpd.conf
    # Or disable entirely on untrusted hosts
    systemctl stop lldpd
    systemctl disable lldpd
fi
```

---

## Step 3: Trunk Port Hardening

Restrict trunk ports to carry only the VLANs they need. A trunk carrying all VLANs (default) means a compromised trunk port has full L2 access.

### Cisco IOS

```
Switch(config)# interface GigabitEthernet0/24
Switch(config-if)# switchport mode trunk
Switch(config-if)# switchport trunk allowed vlan 10,20,30,999
! Remove all other VLANs — if a VLAN isn't listed, it's pruned
Switch(config-if)# switchport nonegotiate
Switch(config-if)# end
Switch# show interfaces GigabitEthernet0/24 trunk
! Confirm: VLANs in spanning tree forwarding state = 10,20,30,999 only
```

### Linux Bridge (restrict VLANs per port)

```bash
# After enabling VLAN filtering:
# Remove all VLANs, then add only the required ones

# Example: server port should only be on VLAN 10
sudo bridge vlan del dev veth_server vid 1-4094 2>/dev/null || true
sudo bridge vlan add dev veth_server vid 10 pvid untagged

# Example: trunk port to router carrying VLANs 10, 20, 30
sudo bridge vlan del dev eth_uplink vid 1-4094 2>/dev/null || true
sudo bridge vlan add dev eth_uplink vid 10
sudo bridge vlan add dev eth_uplink vid 20
sudo bridge vlan add dev eth_uplink vid 30
sudo bridge vlan add dev eth_uplink vid 999 pvid untagged

bridge vlan show
```

---

## Step 4: Persist VLAN Configuration

Linux bridge VLAN configuration is lost on reboot. Persist it.

```bash
# Method 1: NetworkManager (if in use)
nmcli connection modify br0 bridge.vlan-filtering yes
nmcli connection modify br0 bridge.vlans "10,20,30,999"

# Method 2: /etc/network/interfaces (Debian)
cat >> /etc/network/interfaces <<'EOF'
auto br0
iface br0 inet static
    address 10.10.30.1/24
    bridge_ports eth0
    bridge_stp off
    bridge_fd 0
    bridge_vlan_aware yes
EOF

# Method 3: systemd-networkd
cat > /etc/systemd/network/20-br0.netdev <<'EOF'
[NetDev]
Name=br0
Kind=bridge

[Bridge]
VLANFiltering=yes
EOF
```

---

## Evidence Requirements

```bash
EVIDENCE_DIR="evidence/$(date +%Y%m%d)-AC3-vlan-fix"
mkdir -p "$EVIDENCE_DIR"

# Linux
bridge vlan show > "$EVIDENCE_DIR/bridge-vlan-after.txt" 2>/dev/null || echo "not applicable" > "$EVIDENCE_DIR/bridge-vlan-after.txt"
ip -d link show > "$EVIDENCE_DIR/ip-link-detail.txt"
cat /sys/class/net/br*/bridge/vlan_filtering > "$EVIDENCE_DIR/vlan-filtering.txt" 2>/dev/null || true

# Cisco (save output of these commands)
# show interfaces trunk > "$EVIDENCE_DIR/trunk-ports.txt"
# show vlan brief > "$EVIDENCE_DIR/vlan-brief.txt"
# show running-config | section interface > "$EVIDENCE_DIR/interface-configs.txt"
```

NIST evidence mapping:
- `bridge-vlan-after.txt` → AC-4 (information flow enforcement — VLANs restricted)
- `trunk-ports.txt` → SC-7 (boundary — only required VLANs on trunk)
- `vlan-brief.txt` → AC-3 (access enforcement — VLAN assignment documented)

---

## Validation

```bash
# Run VLAN auditor after fix
sudo ./01-auditors/audit-vlan-config.sh

# Key checks that should now PASS:
# - Bridge VLAN filtering enabled
# - Native VLAN is not VLAN 1
```

---

## Next Step

`03-validate.md` — Re-run all auditors and test detection with attacker container
