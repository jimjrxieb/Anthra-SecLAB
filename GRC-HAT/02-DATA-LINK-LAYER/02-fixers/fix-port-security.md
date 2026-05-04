# Layer 2 Port Security Fix Guide

| Field | Value |
|-------|-------|
| NIST Controls | SC-7 (boundary), AC-3 (access enforcement), SI-4 (monitoring) |
| Applies To | Cisco IOS, Juniper ELS, Linux bridge (ebtables) |
| Rank | D |
| Evidence Required | Switch config backup, show commands output, MAC table snapshot |

---

## Overview

Port security limits the number of MAC addresses allowed on a switch port and defines behavior when violations occur. Without port security, an attacker can flood the MAC address table (CAM table overflow), forcing the switch into hub mode and allowing passive sniffing of all traffic on the VLAN.

NIST SC-7 requires boundary protection at all network layers, including Layer 2. Port security is the primary L2 boundary enforcement mechanism on access-layer switches.

---

## Cisco IOS — Port Security

### Basic Configuration (access port)

```
! Verify interface is an access port first
Switch# show interfaces GigabitEthernet0/1 switchport
Switch# configure terminal
Switch(config)# interface GigabitEthernet0/1
Switch(config-if)# switchport mode access
Switch(config-if)# switchport port-security
Switch(config-if)# switchport port-security maximum 2
Switch(config-if)# switchport port-security violation restrict
Switch(config-if)# switchport port-security mac-address sticky
Switch(config-if)# end
Switch# copy running-config startup-config
```

### Violation Modes

| Mode | Behavior | Use Case |
|------|----------|----------|
| `protect` | Drop frames, no log | Low-impact, silent |
| `restrict` | Drop frames + increment violation counter + syslog | Recommended for detection |
| `shutdown` | Err-disable port + syslog | High-security, requires manual recovery |

**Recommended**: `restrict` for production (visibility without outage risk); `shutdown` for high-security segments.

### Verify Configuration

```
Switch# show port-security interface GigabitEthernet0/1
Switch# show port-security address
Switch# show port-security
```

Save output as evidence:
```
Switch# show port-security | redirect flash:port-security-$(show clock | awk '{print $1}').txt
```

### Trunk Port Security

On trunk ports, do not use port-security. Instead:
```
! Restrict allowed VLANs to only those required
Switch(config-if)# switchport trunk allowed vlan 10,20,30
! Disable DTP (Dynamic Trunking Protocol) — prevents VLAN hopping
Switch(config-if)# switchport nonegotiate
! Change native VLAN away from VLAN 1
Switch(config-if)# switchport trunk native vlan 999
```

---

## Juniper ELS (Enhanced Layer Software)

### Access Port with MAC Limit

```
set vlans CORP_VLAN vlan-id 10
set interfaces ge-0/0/1 unit 0 family ethernet-switching interface-mode access
set interfaces ge-0/0/1 unit 0 family ethernet-switching vlan members CORP_VLAN
set interfaces ge-0/0/1 mac-limit 2
set interfaces ge-0/0/1 mac-limit action drop
```

### Storm Control (CAM flood mitigation)

```
set forwarding-options storm-control interface ge-0/0/1 bandwidth-percentage 5
set forwarding-options storm-control interface ge-0/0/1 action-shutdown
```

### Verify

```
show ethernet-switching interface ge-0/0/1
show ethernet-switching mac-learning-log
```

---

## Linux Bridge — ebtables

### Limit MACs per port with ebtables

```bash
# Install ebtables
apt-get install -y ebtables  # Debian/Ubuntu
yum install -y ebtables       # RHEL/CentOS

# Limit traffic from unknown MACs on a bridge port (veth0)
# Allow only the known MAC of a VM or container
ebtables -A FORWARD -i veth0 --not --src 00:11:22:33:44:55 -j DROP
ebtables -A FORWARD -o veth0 --not --dst 00:11:22:33:44:55 -j DROP

# Save rules
ebtables-save > /etc/ebtables.rules

# Restore on boot (systemd)
cat > /etc/systemd/system/ebtables-restore.service <<'EOF'
[Unit]
Description=Restore ebtables rules
Before=network.target

[Service]
Type=oneshot
ExecStart=/sbin/ebtables-restore /etc/ebtables.rules
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
systemctl enable ebtables-restore
```

### Using nftables (modern replacement for ebtables)

```bash
# nftables bridge table — MAC flooding protection
nft add table bridge filter
nft add chain bridge filter forward { type filter hook forward priority 0\; }
# Drop frames from unknown source MAC (allow only expected MAC)
nft add rule bridge filter forward iif "veth0" ether saddr != 00:11:22:33:44:55 drop
nft list ruleset > /etc/nftables.conf
```

---

## Creating a Custom Detection Signature

### Detecting MAC Flooding from arpwatch Logs

arpwatch logs to syslog. The following patterns indicate MAC flooding or table manipulation:

**Pattern: High volume of "new station" events in short time**
```bash
# Count new station events in the last 5 minutes
grep "new station" /var/log/arpwatch.log | \
  awk -v ts="$(date -d '5 minutes ago' +%s)" \
  '{cmd="date -d \""$1" "$2"\" +%s"; cmd | getline t; close(cmd); if(t > ts) count++} \
  END {print count " new stations in last 5 minutes"}'
```

**Splunk detection rule (add to inputs.conf or via Splunk Web):**
```spl
index=syslog sourcetype=syslog "arpwatch"
| eval event_type=case(
    like(message, "%new station%"), "new_station",
    like(message, "%flip flop%"), "arp_flipflop",
    like(message, "%changed ethernet address%"), "mac_change",
    true(), "other"
  )
| stats count BY event_type, host
| where count > 10 AND event_type IN ("new_station", "arp_flipflop")
| eval severity=if(event_type=="arp_flipflop", "HIGH", "MEDIUM")
```

**Elastic/SIEM KQL detection rule:**
```
message: "arpwatch" AND (message: "flip flop" OR message: "changed ethernet address")
```

**rsyslog rate-based alerting:**
```
# In /etc/rsyslog.d/10-arpwatch.conf
# Alert when more than 20 arpwatch events occur in 60 seconds
if $programname == 'arpwatch' then {
    action(type="omfile" file="/var/log/arpwatch.log")
    if $msg contains 'new station' or $msg contains 'flip flop' then {
        action(type="omfwd" target="siem.corp.local" port="514" protocol="tcp")
    }
}
```

---

## Evidence Requirements

After implementing port security, collect the following for audit evidence:

| Evidence Item | Command | File Name |
|--------------|---------|-----------|
| Port security config | `show port-security` | `port-security-config.txt` |
| MAC address table snapshot | `show mac address-table` | `mac-table-before.txt` |
| Post-fix MAC table (24h later) | `show mac address-table` | `mac-table-after.txt` |
| Violation counters | `show port-security | include Violation` | `violation-counters.txt` |
| Switch config backup | `show running-config` | `running-config-$(date).txt` |
| arpwatch log sample | `tail -100 /var/log/arpwatch.log` | `arpwatch-log-sample.txt` |

All evidence files should be saved to the engagement evidence directory:
```
evidence/SC-7-port-security-$(date +%Y%m%d)/
```

---

## NIST Control Mapping

| Control | Requirement | This Fix Addresses |
|---------|-------------|-------------------|
| SC-7 | Boundary protection — prevent unauthorized L2 traffic | MAC limit, DTP disable, native VLAN change |
| AC-3 | Access enforcement — restrict access to resources | Port security MAC restriction |
| SI-4 | System monitoring — detect L2 anomalies | arpwatch logs, violation counters |
