# Layer 2 Data Link — Install and Validate

| Field | Value |
|-------|-------|
| NIST Controls | SC-7, AC-3, AC-4, SI-4 |
| Tools | arpwatch, Wireshark/tshark, Defender for IoT |
| Enterprise Equivalent | Darktrace ($200K+/year), Vectra AI, Cisco ISE |
| Time Estimate | 2 hours |
| Rank | D |

---

## Objective

Install and validate the Layer 2 monitoring stack. Every tool must demonstrate it can detect ARP traffic before moving to 01-assess. Incomplete installs create silent blind spots — the lab will not report attacks it cannot see.

---

## Tool 1: arpwatch

arpwatch is the primary open-source ARP monitoring daemon. It maintains a database of MAC-IP pairs and logs anomalies to syslog. Covers what Darktrace does for L2 ARP integrity at zero cost.

### Install

```bash
# Debian/Ubuntu
sudo apt-get update && sudo apt-get install -y arpwatch

# RHEL/CentOS
sudo yum install -y arpwatch  # or dnf
```

Use the automated fixer:
```bash
sudo ./02-fixers/fix-arp-monitoring.sh eth0
```

Or reference the existing setup script:
```bash
# This script also sets up attacker tools for the lab scenarios
sudo ./tools/setup-l2-tools.sh
```

### Validate arpwatch

```bash
# 1. Service is running
systemctl status arpwatch

# 2. arpwatch is listening on the correct interface
pgrep -a arpwatch

# 3. Generate ARP traffic and verify arpwatch captures it
ping -c 3 $(ip route | grep default | awk '{print $3}')
sleep 5
sudo cat /var/lib/arpwatch/arp.dat  # Should show MAC-IP entries

# 4. Check syslog for arpwatch messages
grep arpwatch /var/log/syslog | tail -10
# OR
journalctl -u arpwatch --since "5 minutes ago"
```

**Pass criteria**: At least one MAC-IP entry in arp.dat. arpwatch log lines visible in syslog.

---

## Tool 2: Wireshark / tshark

tshark is the CLI version of Wireshark. Used for manual ARP packet capture, protocol verification, and validating that ARP spoofing test traffic is visible on the wire.

### Install

```bash
sudo apt-get install -y tshark wireshark

# If prompted about non-root capture — select YES to allow non-root Wireshark use
# OR add user to wireshark group:
sudo usermod -aG wireshark $USER
```

### Validate tshark captures ARP

```bash
# Capture ARP packets for 10 seconds on eth0
sudo tshark -i eth0 -f "arp" -a duration:10

# Expected output: ARP request/reply lines like:
#   1 0.000000 VMware_xx:xx:xx -> Broadcast ARP 60 Who has 10.0.0.1? Tell 10.0.0.5
#   2 0.001000 VMware_yy:yy:yy -> VMware_xx:xx:xx ARP 60 10.0.0.1 is at xx:xx:xx:xx:xx:xx
```

**Pass criteria**: ARP packets visible in tshark output within 10 seconds.

If no ARP traffic is seen:
```bash
# Force ARP refresh
sudo arp -d $(ip route | grep default | awk '{print $3}') 2>/dev/null || true
ping -c 1 $(ip route | grep default | awk '{print $3}')
```

---

## Tool 3: Microsoft Defender for IoT (Azure — optional)

Defender for IoT provides passive network monitoring for OT/IoT devices. In cloud-connected lab environments it supplements arpwatch with ML-based detection and Sentinel integration.

### Install Defender for IoT Network Sensor (if Azure-connected)

```bash
# Download sensor software from Azure Portal:
# Defender for IoT > Sites and Sensors > Add Sensor > Download Installer

# Install on the monitoring VM
sudo bash azure-iot-sensor-installer.sh

# Verify agent communication
sudo systemctl status defender-iot-micro-agent
```

### Configure Detection Policy

Import the template:
```
Azure Portal > Defender for IoT > Sites and Sensors > [Your Sensor] > Detection Engine > Import Policy
File: 03-templates/defender-iot/network-detection-policy.json
```

Replace all `<PLACEHOLDER>` values before import:
- `<SENTINEL_WORKSPACE_ID_PLACEHOLDER>` — from Log Analytics Workspace > Agents Management
- `<SYSLOG_HOST_PLACEHOLDER>` — your SIEM/syslog collector IP

### Validate Detection Policy Active

```bash
# Check micro-agent connectivity
sudo defender-iot-micro-agent status

# Confirm alerts flow to Sentinel:
# Azure Portal > Sentinel > Incidents — filter by "Defender for IoT"
```

**Pass criteria**: At minimum one L2-001 (ARP Spoofing) rule shows as "Active" in the portal.

**Note**: Defender for IoT is optional for this lab. All scenarios work with arpwatch + tshark alone. Defender for IoT adds the enterprise dual-stack posture.

---

## Validation Checklist

| Check | Command | Expected Result |
|-------|---------|----------------|
| arpwatch running | `systemctl is-active arpwatch` | `active` |
| arpwatch database exists | `ls /var/lib/arpwatch/arp.dat` | File present |
| arpwatch captures ARP | `grep arpwatch /var/log/syslog` | Log entries present |
| tshark sees ARP | `sudo tshark -i eth0 -f "arp" -a duration:5` | Packets captured |
| Syslog forwarding | `cat /etc/rsyslog.d/10-arpwatch.conf` | Config file present |
| Attacker tools ready | `which arping scapy` | Paths returned |

---

## What These Tools Replace (Cost Context)

| Open Source | Enterprise Equivalent | Enterprise Cost |
|-------------|----------------------|----------------|
| arpwatch | Darktrace L2 module | $200K+/year |
| tshark | NetWitness Packets | $100K+/year |
| ebtables/nftables | Cisco Identity Services Engine (ISE) | $50K+ |
| Defender for IoT (free tier) | Claroty, Nozomi Networks | $150K+/year |

This lab covers the same detection capability as the enterprise stack. The gap is scale, ML enrichment, and enterprise support — not detection fidelity.

---

## Next Step

Proceed to `01-assess.md` to run the full Layer 2 assessment.
