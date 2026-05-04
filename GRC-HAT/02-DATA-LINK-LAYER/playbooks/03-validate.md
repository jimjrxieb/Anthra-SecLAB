# Layer 2 Data Link — Validate

| Field | Value |
|-------|-------|
| NIST Controls | SC-7, AC-3, AC-4, SI-4 |
| Tools | arpwatch, arping, tshark, run-all-audits.sh |
| Time Estimate | 45 minutes |
| Rank | D |

---

## Objective

Re-run all auditors after fix work. Test detection capability with a controlled ARP spoof from the attacker container. Collect before/after evidence to demonstrate the remediation closed the gaps identified in assessment.

---

## Pre-Validation Checklist

Before running validation, confirm:

- [ ] `02-fix-SC7-arp-protection.md` steps completed
- [ ] `02a-fix-AC3-vlan-segmentation.md` steps completed (if VLAN findings existed)
- [ ] arpwatch is running: `systemctl is-active arpwatch`
- [ ] rsyslog forwarding configured: `cat /etc/rsyslog.d/10-arpwatch.conf`
- [ ] Assessment evidence saved to `evidence/$(date +%Y%m%d)-l2-assessment/`

---

## Step 1: Re-Run All Auditors

```bash
sudo ./tools/run-all-audits.sh eth0
```

Compare results against the assessment checklist in `01-assess.md`. Every item that was FAIL in assessment should now be PASS or WARN.

**Expected changes after fix:**

| Check | Before | Expected After |
|-------|--------|---------------|
| arpwatch running | FAIL | PASS |
| arpwatch database exists | FAIL | PASS |
| syslog forwarding configured | FAIL | PASS |
| Bridge VLAN filtering (if applicable) | FAIL | PASS |
| Native VLAN not VLAN 1 (if applicable) | FAIL | PASS |

---

## Step 2: Test Detection with Controlled ARP Spoof

**Lab only. Do not run on production networks.**

This test verifies the full detection pipeline: attacker sends ARP spoof → arpwatch detects → syslog receives → (optional) SIEM alerts.

### 2a: Start the attacker container

```bash
# Launch the attacker container (pre-configured lab tool)
sudo ./tools/attacker-container.sh
```

### 2b: Send a controlled ARP spoof from attacker

From inside the attacker container OR a second terminal:

```bash
# Method 1: arping gratuitous ARP
# Claims that our MAC owns the gateway IP
GATEWAY=$(ip route | grep default | awk '{print $3}')
sudo arping -A -I eth0 -c 5 "$GATEWAY"
# -A = send gratuitous ARP (reply mode, no target)
# This announces our MAC is the gateway — classic ARP spoof setup

# Method 2: scapy (if available in attacker container)
# python3 -c "
# from scapy.all import *
# # Forge ARP reply: claim our MAC is the gateway
# import subprocess
# gw = subprocess.getoutput('ip route | grep default | awk \"{print \$3}\"')
# pkt = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(op=2, psrc=gw)
# sendp(pkt, iface='eth0', count=5, inter=1, verbose=True)
# "
```

### 2c: Verify arpwatch detects the spoof

```bash
# Monitor syslog in real-time (second terminal)
sudo tail -f /var/log/syslog | grep arpwatch

# OR
sudo journalctl -u arpwatch -f

# Within 30-60 seconds, expect to see:
# arpwatch: changed ethernet address <ip> <old-mac> <new-mac>
# OR
# arpwatch: new station <ip> <mac>
# OR
# arpwatch: flip flop <ip> <mac1> <mac2>
```

**Pass criteria**: arpwatch log entry appears within 60 seconds of the test spoof.

### 2d: Verify SIEM received the alert (if configured)

```bash
# Splunk
# index=syslog sourcetype=syslog "arpwatch" | head 5

# Generate and check Defender for IoT (if deployed):
# Azure Portal > Defender for IoT > Alerts > Filter by: ARP Spoofing
```

---

## Step 3: Before/After Evidence Collection

```bash
EVIDENCE_DIR="evidence/$(date +%Y%m%d)-l2-validation"
mkdir -p "$EVIDENCE_DIR"

# After-state: auditor output
sudo ./tools/run-all-audits.sh eth0 2>&1 | tee "$EVIDENCE_DIR/run-all-audits-after.txt"

# arpwatch status
systemctl status arpwatch --no-pager > "$EVIDENCE_DIR/arpwatch-status-after.txt"

# rsyslog forwarding config
cat /etc/rsyslog.d/10-arpwatch.conf > "$EVIDENCE_DIR/rsyslog-arpwatch-rule.txt" 2>/dev/null || echo "not configured" > "$EVIDENCE_DIR/rsyslog-arpwatch-rule.txt"

# arpwatch database
cp /var/lib/arpwatch/arp.dat "$EVIDENCE_DIR/arp-database-after.txt" 2>/dev/null || true

# Detection test result
grep arpwatch /var/log/syslog | tail -20 > "$EVIDENCE_DIR/detection-test-syslog.txt"

# VLAN state (after)
bridge vlan show > "$EVIDENCE_DIR/bridge-vlan-after.txt" 2>/dev/null || echo "no bridges" > "$EVIDENCE_DIR/bridge-vlan-after.txt"
ip -d link show > "$EVIDENCE_DIR/ip-link-after.txt"

echo "Validation evidence saved to $EVIDENCE_DIR"
```

---

## Step 4: Validation Sign-Off

Complete this checklist to sign off validation:

| # | Item | Evidence File | Status |
|---|------|--------------|--------|
| 1 | All auditors PASS or WARN (no FAIL) | run-all-audits-after.txt | |
| 2 | arpwatch service active | arpwatch-status-after.txt | |
| 3 | arpwatch database has entries | arp-database-after.txt | |
| 4 | rsyslog forwarding configured | rsyslog-arpwatch-rule.txt | |
| 5 | Controlled ARP spoof detected in syslog | detection-test-syslog.txt | |
| 6 | VLAN filtering enabled (if applicable) | bridge-vlan-after.txt | |
| 7 | Native VLAN not VLAN 1 (if applicable) | bridge-vlan-after.txt | |

**Signed off by**: ___________  **Date**: ___________

---

## Teardown Attacker Container

```bash
# Clean up lab attacker tools after validation
sudo ./tools/teardown-l2-tools.sh
```

---

## Next Step

`04-triage-alerts.md` — Daily SOC workflow for reviewing L2 alerts
