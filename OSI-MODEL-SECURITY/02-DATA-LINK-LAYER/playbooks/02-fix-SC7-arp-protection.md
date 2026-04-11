# Layer 2 — Fix SC-7: ARP Protection (arpwatch + SIEM)

| Field | Value |
|-------|-------|
| NIST Control | SC-7 (Boundary Protection), SI-4 (System Monitoring) |
| Tools | arpwatch, rsyslog |
| Enterprise Equivalent | Darktrace L2 ARP monitoring module |
| Time Estimate | 30 minutes |
| Rank | D |
| Trigger | arpwatch not running, SIEM missing ARP events |

---

## Objective

Deploy arpwatch and configure syslog forwarding so ARP anomalies reach the SIEM. SC-7 requires Layer 2 boundary monitoring. This fix closes the gap.

---

## Step 1: Deploy arpwatch

Use the automated fixer for full deployment:

```bash
# Basic deployment (local syslog only)
sudo ./02-fixers/fix-arp-monitoring.sh eth0

# With SIEM forwarding (recommended)
sudo ./02-fixers/fix-arp-monitoring.sh eth0 siem.corp.local:514
```

The fixer handles: package install, interface config, service enable/start, rsyslog rule creation.

**Manual steps** (if fixer cannot run):

```bash
# 1. Install
sudo apt-get install -y arpwatch

# 2. Configure interface
sudo sed -i 's/^ARGS=.*/ARGS="-i eth0 -u arpwatch"/' /etc/default/arpwatch

# 3. Apply gold-standard config
sudo cp 03-templates/arpwatch/arpwatch.conf /etc/default/arpwatch
# Edit INTERFACES, MAILTO, DATAFILE to match environment

# 4. Enable and start
sudo systemctl enable arpwatch
sudo systemctl start arpwatch
```

---

## Step 2: Configure SIEM Detection Rule for ARP Anomalies

arpwatch logs to syslog with program name `arpwatch`. Add this detection rule to your SIEM.

### Splunk Detection

```spl
index=syslog sourcetype=syslog programname=arpwatch
| eval threat_type=case(
    like(message, "%flip flop%"), "ARP_POISONING",
    like(message, "%changed ethernet address%"), "MAC_CHANGE",
    like(message, "%new station%"), "NEW_DEVICE",
    true(), "ARP_OTHER"
  )
| eval severity=case(
    threat_type="ARP_POISONING", "HIGH",
    threat_type="MAC_CHANGE", "HIGH",
    threat_type="NEW_DEVICE", "MEDIUM",
    true(), "LOW"
  )
| stats count BY threat_type, severity, host
| where severity IN ("HIGH", "MEDIUM")
```

Save as saved search: `L2-ARP-Anomaly-Detection`
Alert threshold: any result = HIGH immediately, MEDIUM if count > 5 in 1 hour.

### Microsoft Sentinel KQL

```kql
Syslog
| where ProcessName == "arpwatch"
| extend ThreatType = case(
    Message contains "flip flop", "ARP_POISONING",
    Message contains "changed ethernet address", "MAC_CHANGE",
    Message contains "new station", "NEW_DEVICE",
    "ARP_OTHER"
  )
| extend Severity = case(
    ThreatType in ("ARP_POISONING", "MAC_CHANGE"), "High",
    ThreatType == "NEW_DEVICE", "Medium",
    "Low"
  )
| where Severity in ("High", "Medium")
| project TimeGenerated, Computer, ThreatType, Severity, Message
| order by TimeGenerated desc
```

Create as Sentinel Scheduled Alert Rule with 5-minute frequency, HIGH severity for flip-flop.

### Elastic/ELK

```json
{
  "query": {
    "bool": {
      "must": [
        {"term": {"program": "arpwatch"}},
        {"terms": {"message": ["flip flop", "changed ethernet address"]}}
      ]
    }
  }
}
```

---

## Step 3: Verify End-to-End Pipeline

```bash
# 1. Generate a test ARP event
logger -t arpwatch "new station 10.0.0.99 00:de:ad:be:ef:01 eth0"
sleep 5

# 2. Verify local log
grep "10.0.0.99" /var/log/arpwatch.log
grep "10.0.0.99" /var/log/syslog

# 3. Verify SIEM received it (Splunk example)
# In Splunk: index=syslog "arpwatch" "new station" "10.0.0.99"
```

---

## Evidence Requirements

After completing this fix:

```bash
EVIDENCE_DIR="evidence/$(date +%Y%m%d)-SC7-arp-fix"
mkdir -p "$EVIDENCE_DIR"

systemctl status arpwatch --no-pager > "$EVIDENCE_DIR/arpwatch-status.txt"
cat /etc/rsyslog.d/10-arpwatch.conf > "$EVIDENCE_DIR/rsyslog-arpwatch-rule.txt"
cat /var/lib/arpwatch/arp.dat > "$EVIDENCE_DIR/arp-database-after.txt" 2>/dev/null || true
grep arpwatch /var/log/syslog | tail -20 > "$EVIDENCE_DIR/syslog-arpwatch-sample.txt"
```

NIST evidence mapping:
- `arpwatch-status.txt` → SC-7 (monitoring deployed)
- `rsyslog-arpwatch-rule.txt` → SI-4 (automated alerting configured)
- `arp-database-after.txt` → SC-7 (known MAC-IP inventory maintained)

---

## Validation

Run the ARP integrity auditor to confirm fix:

```bash
sudo ./01-auditors/audit-arp-integrity.sh eth0
```

Expected result: PASS on arpwatch service, PASS on syslog forwarding.

---

## Next Step

`02a-fix-AC3-vlan-segmentation.md` — VLAN segmentation hardening
