# Layer 2 — ARP Spoofing Audit (Deep Dive)

| Field | Value |
|-------|-------|
| NIST Controls | SC-7, SI-4, AC-4 |
| Tools | arpwatch, arping, tshark, ip neigh |
| Enterprise Equivalent | Darktrace L2, Vectra AI |
| Time Estimate | 45 minutes |
| Rank | D |
| Trigger | FAIL on checks 1-9 in 01-assess.md, or active incident |

---

## Objective

Deep-dive ARP integrity investigation. Determine whether observed ARP anomalies represent active spoofing, misconfiguration, or benign lab noise. Collect evidence that would support escalation if spoofing is confirmed.

---

## Step 1: Run arpwatch Audit

```bash
sudo ./01-auditors/audit-arp-integrity.sh eth0
```

Review the evidence directory output. Focus on:
- `duplicate-macs.txt` — any content here is immediate escalation
- `failed-arp-entries.txt` — FAILED entries may indicate scanning
- `arp-table-ip-neigh.txt` — full ARP table for manual review

---

## Step 2: Check for Gratuitous ARP Activity

Gratuitous ARP is an unsolicited ARP reply that announces a MAC-IP mapping. Legitimate uses: IP address conflict detection, failover. Attack use: ARP cache poisoning.

```bash
# Capture ARP packets for 30 seconds, filter for gratuitous ARP
# Gratuitous ARP: sender IP == target IP in ARP request
sudo tshark -i eth0 -f "arp" -a duration:30 \
  -T fields -e frame.time -e eth.src -e arp.src.hw_mac \
  -e arp.src.proto_ipv4 -e arp.dst.proto_ipv4 \
  | awk '$4 == $5 {print "GRATUITOUS ARP:", $0}'

# Also check for ARP replies without corresponding requests (unsolicited)
sudo tshark -i eth0 -f "arp" -a duration:30 \
  -T fields -e frame.time -e eth.src -e arp.opcode \
  -e arp.src.proto_ipv4 -e arp.src.hw_mac \
  | awk '$3 == "2" {print "ARP REPLY:", $0}'
```

Save output:
```bash
sudo tshark -i eth0 -f "arp" -a duration:60 \
  > /tmp/jsa-evidence/arp-capture-$(date +%Y%m%d-%H%M%S).txt
```

---

## Step 3: Review arpwatch Database for Flip-Flops

arpwatch logs "flip flop" events when a MAC address oscillates between two IP addresses — the primary signature of ARP poisoning.

```bash
# Check arpwatch syslog for flip-flop events
grep "flip flop\|changed ethernet\|new station" /var/log/syslog | \
  grep arpwatch | tail -50

# Or check dedicated arpwatch log if rsyslog is configured
grep "flip flop\|changed ethernet\|new station" /var/log/arpwatch.log | tail -50

# Count events by type (high count = likely attack, not one-off noise)
grep arpwatch /var/log/syslog | \
  awk '{
    if ($0 ~ /flip flop/) type="flip_flop";
    else if ($0 ~ /changed ethernet/) type="mac_change";
    else if ($0 ~ /new station/) type="new_station";
    else type="other";
    count[type]++
  }
  END {for (t in count) print count[t], t}' | sort -rn
```

**Interpretation:**
| Event | Normal Count | Investigate When |
|-------|-------------|------------------|
| `new station` | 1-5/day | >20/hour |
| `flip flop` | 0 | Any occurrence |
| `changed ethernet address` | 0-1 per device lifetime | >2 for same IP |

---

## Step 4: Verify Syslog Forwarding to SIEM

ARP events are worthless if they never reach the SIEM. Verify the forwarding pipeline is intact.

```bash
# Confirm rsyslog config exists
cat /etc/rsyslog.d/10-arpwatch.conf

# Confirm rsyslog is running
systemctl status rsyslog

# Test syslog forwarding by generating a test message
logger -t arpwatch "test: flip flop 10.0.0.1 00:11:22:33:44:55 vs 00:aa:bb:cc:dd:ee"
sleep 2

# Verify it appears locally
grep "flip flop" /var/log/arpwatch.log | tail -3

# Verify it arrived at SIEM (if configured)
# Check Splunk: index=syslog sourcetype=syslog "arpwatch" "flip flop"
# Check Sentinel: SecurityEvent | where Computer == "$(hostname)" | where EventData contains "arpwatch"
```

---

## Step 5: Test Detection with Controlled ARP Spoof

**Lab only. Do not run on production networks.**

Use the attacker container from the lab setup to simulate ARP spoofing and verify arpwatch detects it.

```bash
# Start attacker container (from lab tools)
sudo ./tools/attacker-container.sh

# From inside the attacker container OR from a second terminal:
# Method 1: arping gratuitous ARP (low impact, single packet)
sudo arping -A -I eth0 -c 3 10.0.0.1
# -A sends gratuitous ARP claiming to be 10.0.0.1 with our MAC

# Method 2: Python scapy (if installed in attacker container)
# python3 -c "
# from scapy.all import *
# # Send ARP reply claiming 10.0.0.1 is at our MAC
# pkt = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(op=2, pdst='10.0.0.1', psrc='10.0.0.1')
# sendp(pkt, iface='eth0', count=5, inter=0.2)
# "
```

After running the spoof:
```bash
# Within 60 seconds, check for arpwatch detection
grep "arpwatch" /var/log/syslog | tail -10
# Expected: "arpwatch: changed ethernet address" or "flip flop"

# If using Defender for IoT: check portal for L2-001 (ARP Spoofing Detected) alert
```

**Pass criteria**: arpwatch logs a MAC change or flip-flop event within 60 seconds of the test spoof.

---

## Evidence Collection

```bash
EVIDENCE_DIR="evidence/$(date +%Y%m%d)-arp-spoofing-audit"
mkdir -p "$EVIDENCE_DIR"

# ARP table at time of investigation
ip neigh show > "$EVIDENCE_DIR/arp-table.txt"

# arpwatch log (last 100 events)
grep arpwatch /var/log/syslog | tail -100 > "$EVIDENCE_DIR/arpwatch-syslog.txt"
cat /var/log/arpwatch.log 2>/dev/null > "$EVIDENCE_DIR/arpwatch-dedicated-log.txt" || true

# arpwatch database
cp /var/lib/arpwatch/arp.dat "$EVIDENCE_DIR/arp.dat" 2>/dev/null || true

# tshark capture (if running)
ls /tmp/jsa-evidence/arp-capture-*.txt 2>/dev/null | xargs -I{} cp {} "$EVIDENCE_DIR/" || true

# Service status
systemctl status arpwatch --no-pager > "$EVIDENCE_DIR/arpwatch-service-status.txt"

echo "Evidence saved to $EVIDENCE_DIR"
```

---

## Escalation Decision

| Finding | Action |
|---------|--------|
| Duplicate MACs active in ARP table | Escalate immediately — isolate suspected port |
| Flip-flop events in last 24 hours | Investigate source IP — run tshark on that IP |
| Gratuitous ARP from unexpected host | Check asset inventory — is this a known device? |
| arpwatch not detecting test spoof | Fix arpwatch configuration before proceeding |
| No syslog forwarding | Fix rsyslog before declaring monitoring complete |

---

## Next Step

- ARP spoofing confirmed: `02-fix-SC7-arp-protection.md`
- Monitoring gaps found: `02-fix-SC7-arp-protection.md`
- VLAN issues found: `02a-fix-AC3-vlan-segmentation.md`
- All clear: `03-validate.md`
