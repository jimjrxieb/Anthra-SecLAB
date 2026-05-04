# Layer 2 Data Link — Alert Triage

| Field | Value |
|-------|-------|
| NIST Controls | SI-4 (monitoring), IR-6 (incident reporting), AC-3 (access enforcement) |
| Tools | arpwatch syslog, Defender for IoT, Microsoft Sentinel |
| Time Estimate | 15-30 minutes daily |
| Rank | D (review) / C (investigation) / B (isolation decision) |

---

## Objective

Daily review workflow for Layer 2 alerts. Covers arpwatch syslog events, Defender for IoT alerts, and Sentinel L2 incidents. Know which events are noise, which require investigation, and which require immediate escalation.

---

## Daily Review — arpwatch Syslog

Run this at the start of each shift or daily review cycle:

```bash
# All arpwatch events in last 24 hours
grep arpwatch /var/log/syslog | \
  grep "$(date --date='1 day ago' +'%b %e')\|$(date +'%b %e')" | \
  sort -k3 | uniq -c | sort -rn | head -30

# OR if using dedicated log
tail -200 /var/log/arpwatch.log

# Event summary by type
grep arpwatch /var/log/syslog | \
  awk '{
    if ($0 ~ /flip flop/) type="FLIP_FLOP [HIGH]";
    else if ($0 ~ /changed ethernet address/) type="MAC_CHANGE [HIGH]";
    else if ($0 ~ /new station/) type="NEW_STATION [MEDIUM]";
    else if ($0 ~ /new activity/) type="NEW_ACTIVITY [LOW]";
    else type="OTHER";
    count[type]++
  } END {for (t in count) print count[t], t}' | sort -rn
```

---

## Event Triage Guide

### "new station" — New MAC/IP pair seen

**What it means**: arpwatch saw a MAC address it has never seen before.

**Normal causes**:
- New device added to the network (approved)
- VM/container started (known asset)
- DHCP lease renewal with new assignment

**Suspicious causes**:
- Rogue device plugged in (insider threat, T1200)
- Attacker gained L2 access (802.1X bypass)
- Unauthorized IoT device

**Triage steps**:
```bash
# 1. Look up the MAC OUI (vendor)
MAC="00:11:22:33:44:55"  # Replace with actual MAC
echo "${MAC:0:8}" | tr '[:lower:]' '[:upper:]'
# Look up at: https://macvendors.com OR
curl -s "https://api.macvendors.com/$MAC" 2>/dev/null || echo "OUI lookup requires internet"

# 2. Check if IP is in CMDB/asset inventory
# Query your asset management system for $IP

# 3. Check DHCP leases
cat /var/lib/dhcp/dhcpd.leases 2>/dev/null | grep -A5 "$MAC" || \
  cat /var/lib/dhcpcd/duid 2>/dev/null || \
  journalctl -u isc-dhcp-server | grep "$MAC" | tail -5

# 4. If unknown — check which switch port the MAC appeared on
# (requires switch access — Cisco: show mac address-table address <MAC>)
```

**Decision**:
- Known asset: Mark as expected, add to approved inventory
- Unknown but matches known vendor: Verify with asset owner
- Unknown vendor or unrecognized: Escalate — potential unauthorized device

---

### "flip flop" — MAC address oscillating between IPs

**What it means**: arpwatch saw the same MAC address claim two different IP addresses, then switch back. This is the primary ARP poisoning signature.

**This is always HIGH severity. Do not dismiss as noise.**

**Normal causes**:
- Almost none. Rare exception: misconfigured HSRP/VRRP failover
- Load balancer with ARP table manipulation (verify with network team)

**Suspicious causes**:
- ARP poisoning in progress (T1557.002) — attacker intercepting traffic
- MitM attack setup — credential theft, session hijack
- Network reconnaissance

**Triage steps**:
```bash
# 1. Identify the two IPs and the MAC
# Log format: "flip flop <ip1> <mac1> <mac2>" or similar
# Extract from log:
grep "flip flop" /var/log/syslog | tail -10

# 2. Capture current ARP table state
ip neigh show | tee /tmp/arp-flipflop-evidence-$(date +%H%M%S).txt

# 3. Capture wire traffic to confirm poisoning
sudo tshark -i eth0 -f "arp" -a duration:30 \
  > /tmp/arp-flipflop-capture-$(date +%H%M%S).pcap

# 4. Identify which MAC is legitimate
# Check CMDB for which MAC should own each IP
# Check DHCP server: which MAC was issued this IP?
```

**Decision**:
- If confirmed spoofing: isolate suspect port immediately (B-rank decision — escalate to senior)
- If HSRP/VRRP: verify with network team that this is expected failover behavior
- Document all evidence before taking action

---

### "changed ethernet address" — Known IP now has different MAC

**What it means**: An IP address that arpwatch previously mapped to MAC-A now appears with MAC-B.

**Normal causes**:
- Network interface replaced (new NIC)
- VM migrated to different hypervisor (MAC changed)
- DHCP lease expired, IP reassigned to different device

**Suspicious causes**:
- ARP spoofing — attacker's MAC claiming a legitimate IP
- Unauthorized device replacing a legitimate host

**Triage steps**:
```bash
# 1. Get both old and new MAC from log
grep "changed ethernet address" /var/log/syslog | tail -5

# 2. Check arpwatch database for history
grep "<ip_in_question>" /var/lib/arpwatch/arp.dat

# 3. Verify the new MAC is a known asset
# Look up MAC OUI, cross-reference with CMDB

# 4. Ping the original device (if separate IP) to verify it still exists
# If original is gone and new MAC appeared — likely device replacement (benign)
# If original still responds — possible ARP spoof in progress
```

---

### "new activity" — Known MAC/IP pair seen after long absence

**What it means**: A MAC-IP pair that was previously known but inactive has reappeared.

**Normal causes**:
- Laptop returned from remote work
- Server rebooted after maintenance

**Suspicious causes**:
- Old/forgotten device reactivated (unauthorized)
- Attacker using a cloned MAC from an inactive device

**Triage**: Verify the device is expected to be active. Check with asset owner if unclear.

---

## Microsoft Defender for IoT Alert Review

If Defender for IoT is deployed, review these alert categories daily:

### Access Azure Sentinel Incidents

```
Azure Portal > Microsoft Sentinel > Incidents
Filter by: Product = "Microsoft Defender for IoT"
Sort by: Severity (High first), Created Time (newest first)
```

### L2 Alert Types to Prioritize

| Alert | Priority | Action |
|-------|----------|--------|
| ARP Spoofing Detected (L2-001) | P1 — Immediate | Isolate source port, investigate |
| New Unauthorized Device (L2-002) | P2 — Same day | Verify asset, block if unauthorized |
| VLAN Hopping Attempt (L2-003) | P1 — Immediate | Block source, review VLAN config |

### Investigate L2-001 (ARP Spoofing)

```
Sentinel > Incidents > [L2-001 incident] > Investigate
- Review: Source MAC, Target IP, Time
- Entities: Map to known assets
- Related alerts: Check for lateral movement above L2
- Run playbook: L2-ARP-Investigation (if configured)
```

---

## Investigation Workflow for Escalation

```
1. Alert received (any flip-flop or L2-001)
   ↓
2. Capture current ARP table: ip neigh show
   ↓
3. Capture wire traffic: tshark -i eth0 -f "arp" -a duration:60
   ↓
4. Identify source MAC (lookup OUI, check CMDB)
   ↓
5. If rogue MAC confirmed:
   → Locate physical switch port (show mac address-table on switch)
   → Disable port: interface shutdown (Cisco) or ip link set down (Linux)
   → Preserve evidence: save pcap + syslog + arp table
   → Escalate to IR team (B-rank decision)
   ↓
6. If legitimate MAC (misconfig or migration):
   → Update arpwatch database: add authorized entry
   → Document exception in CMDB
   → Close alert as false positive
```

---

## Evidence for Audit

After each significant triage decision, save:

```bash
DATE=$(date +%Y%m%d-%H%M%S)
TRIAGE_DIR="evidence/${DATE}-l2-triage"
mkdir -p "$TRIAGE_DIR"

# Current state
ip neigh show > "$TRIAGE_DIR/arp-table.txt"
grep arpwatch /var/log/syslog | tail -50 > "$TRIAGE_DIR/arpwatch-events.txt"
cat /var/lib/arpwatch/arp.dat > "$TRIAGE_DIR/arp-database.txt" 2>/dev/null || true

# Analyst notes
cat > "$TRIAGE_DIR/triage-notes.txt" <<EOF
Date: $DATE
Analyst: $(whoami)
Alert Type:
Source MAC:
Source IP:
Determination: [FALSE POSITIVE / TRUE POSITIVE / ESCALATED]
Action Taken:
EOF
```

---

## Shift Handoff Summary

At end of shift, summarize L2 alert state:

```bash
echo "=== L2 Alert Summary $(date) ==="
echo "arpwatch events (last 8h):"
grep arpwatch /var/log/syslog | grep "$(date +'%b %e')" | \
  awk '{if ($0~/flip flop/) t="FLIP_FLOP"; else if ($0~/changed ethernet/) t="MAC_CHANGE"; else if ($0~/new station/) t="NEW_STATION"; else t="OTHER"; count[t]++} END {for(x in count) print count[x], x}'
echo ""
echo "Open Defender for IoT L2 incidents: [check portal]"
echo "Attacker container status:"
docker ps 2>/dev/null | grep attacker || echo "Not running"
```
