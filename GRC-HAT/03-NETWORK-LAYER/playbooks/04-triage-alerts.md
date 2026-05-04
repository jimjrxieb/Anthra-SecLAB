# Layer 3 Network — Alert Triage

| Field | Value |
|-------|-------|
| NIST Controls | SI-4 (System Monitoring), IR-6 (Incident Reporting), IR-5 (Incident Monitoring) |
| Tools | Suricata eve.json, Zeek conn.log/dns.log, jq, python3 |
| Time Estimate | 1–2 hours/day (SOC daily workflow) |
| Rank | D (review) / C (investigation) / B (isolation decision) |

---

## Objective

Daily SOC analyst workflow for Layer 3 network alerts. Covers Suricata IDS alert review, Zeek flow anomaly investigation, escalation protocol, and MTTD/MTTR tracking. This is what you run every morning before anything else at L3.

---

## Morning Dashboard Review (15 minutes)

### Suricata Alert Volume

```bash
# Alert count by hour — yesterday
grep "$(date -d yesterday +'%Y-%m-%d')" /var/log/suricata/eve.json 2>/dev/null | \
  python3 -c "
import sys, json
from collections import Counter
hours = Counter()
for line in sys.stdin:
    try:
        e = json.loads(line)
        if e.get('event_type') == 'alert':
            hour = e.get('timestamp','')[:13]
            hours[hour] += 1
    except: pass
for h in sorted(hours.keys()):
    print(f'{h}:00  {hours[h]:>6} alerts')
"

# Alert count by severity today
tail -10000 /var/log/suricata/eve.json | python3 -c "
import sys, json
from collections import Counter
sev = Counter()
for line in sys.stdin:
    try:
        e = json.loads(line)
        if e.get('event_type') == 'alert':
            s = e.get('alert',{}).get('severity', 'unknown')
            sev[s] += 1
    except: pass
for s in sorted(sev.keys()):
    print(f'Severity {s}: {sev[s]} alerts')
"
```

### Top Firing Signatures Today

```bash
tail -20000 /var/log/suricata/eve.json | python3 -c "
import sys, json
from collections import Counter
sigs = Counter()
for line in sys.stdin:
    try:
        e = json.loads(line)
        if e.get('event_type') == 'alert':
            sig = e.get('alert',{}).get('signature','unknown')
            sigs[sig] += 1
    except: pass
print('Top 15 signatures:')
for sig, count in sigs.most_common(15):
    print(f'  {count:>6}  {sig[:80]}')
"
```

### Top Source IPs Generating Alerts

```bash
tail -20000 /var/log/suricata/eve.json | python3 -c "
import sys, json
from collections import Counter
srcs = Counter()
for line in sys.stdin:
    try:
        e = json.loads(line)
        if e.get('event_type') == 'alert':
            srcs[e.get('src_ip', '?')] += 1
    except: pass
print('Top 10 alert sources:')
for ip, count in srcs.most_common(10):
    print(f'  {count:>6}  {ip}')
"
```

---

## IDS Alert Investigation (5 Questions)

For each alert that is not immediately recognizable as noise, answer these 5 questions before disposition:

```bash
# Query a specific alert by SID or signature keyword
KEYWORD="SSH Brute"  # replace with your alert
grep -a "alert" /var/log/suricata/eve.json | python3 -c "
import sys, json
events = []
for line in sys.stdin:
    try:
        e = json.loads(line)
        if e.get('event_type') == 'alert' and '${KEYWORD}' in e.get('alert',{}).get('signature',''):
            events.append(e)
    except: pass
for e in events[-5:]:
    print(json.dumps(e, indent=2))
    print('---')
"
```

**Question 1: What is the source IP, and what zone is it in?**
```bash
# Is this IP internal or external? Is it a known host?
src_ip="10.0.0.50"  # replace
host "$src_ip" 2>/dev/null || echo "No PTR record"
grep "$src_ip" /opt/zeek/logs/current/conn.log | zeek-cut id.orig_h id.resp_h id.resp_p | head -10
```

**Question 2: What zone is the destination in?**
- External destination with internal source = potential exfiltration (T1048)
- Internal-to-internal = potential lateral movement (T1021)
- External-to-internal = external attack, brute force, or scan (T1190, T1110)

**Question 3: Is there PCAP evidence? (Payload capture)**
```bash
# Extract payload from EVE JSON alert
tail -100 /var/log/suricata/eve.json | python3 -c "
import sys, json, base64
for line in sys.stdin:
    try:
        e = json.loads(line)
        if e.get('event_type') == 'alert':
            payload = e.get('payload_printable', '')
            if payload:
                print('PAYLOAD:', payload[:200])
    except: pass
"
```

**Question 4: Is there behavioral context from Zeek?**
```bash
# Check Zeek conn.log for same source around the same time
# Replace IP and adjust time
src_ip="10.0.0.50"
grep "$src_ip" /opt/zeek/logs/current/conn.log | zeek-cut ts id.orig_h id.resp_h id.resp_p proto duration orig_bytes | head -20
```

**Question 5: Verdict — Noise, Investigate, or Escalate?**

| Verdict | Criteria | Action |
|---------|----------|--------|
| Noise | Known scanner, test tool, routine operation | Suppress with `threshold` or `suppress` — document justification |
| Investigate | Unknown source, unusual destination, unexpected protocol | Pull PCAP, correlate with Zeek, extend 30-minute investigation window |
| Escalate | Confirmed IOC, data movement to external, admin tool from non-admin source | IR-6 notification, rank B/S decision for human review |

---

## Flow Anomaly Investigation

### Beaconing Detection (Zeek conn.log)

```bash
# Find hosts making repeated connections to same external IP at regular intervals
# Classic C2 beacon pattern (T1071)
cat /opt/zeek/logs/current/conn.log | zeek-cut ts id.orig_h id.resp_h id.resp_p duration orig_bytes \
  | awk '$3 !~ /^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)/' \
  | sort -k2,3 | uniq -c -f1 | sort -rn | head -20
```

Pattern to flag: Same source connecting to same external IP more than 10 times with consistent duration or byte count.

### Long Duration Connections (Potential Tunnel or Persistent Session)

```bash
# Connections lasting > 1 hour (3600 seconds)
cat /opt/zeek/logs/current/conn.log | zeek-cut ts id.orig_h id.resp_h id.resp_p duration proto service \
  | awk '$5 > 3600 {print}' | sort -k5 -rn | head -15
```

Normal: Continuous VPN sessions, database connections with keepalive, long HTTP sessions.
Abnormal: SSH to external IP lasting 8+ hours, HTTP/S connection with multi-hour duration.

### Large Upload Events (Potential Exfiltration)

```bash
# Internal hosts with large outbound transfers today (>10MB)
cat /opt/zeek/logs/current/conn.log | zeek-cut ts id.orig_h id.resp_h orig_bytes \
  | awk '$3 !~ /^(10\.|172\.|192\.168\.)/ && $4 > 10485760 {print $1, $2, $3, $4/1048576 " MB"}' \
  | sort -k4 -rn | head -10
```

Baseline: What is the normal max upload for your environment? Flag anything >2x baseline.

---

## Escalation Protocol

Apply the rank system to every finding before escalating:

| Rank | Criteria | Who Decides | Action |
|------|----------|-------------|--------|
| E/D | Scanner/probe against closed port, known test tools | Automated | Log and suppress |
| C | Brute force attempt from external IP, 1 occurrence | Katie / SOC analyst | Investigate, block source if repeated |
| B | Confirmed credential access, lateral movement indicators | Human review | IR-6 notification, isolation consideration |
| S | Active exfiltration, ransomware indicators, admin tool from attacker IP | Human only (J) | Incident response, isolation, CISO notification |

---

## MTTD / MTTR Tracking

Track these metrics per shift:

```bash
# Log to a simple JSONL file for trending
cat >> /opt/jsa/metrics/l3-mttd.jsonl << EOF
{
  "date": "$(date -I)",
  "shift_start": "$(date +%H:%M)",
  "alerts_reviewed": 0,
  "noise": 0,
  "investigated": 0,
  "escalated": 0,
  "mttd_minutes": 0,
  "mttr_minutes": 0,
  "analyst": "$(whoami)"
}
EOF
```

**MTTD** (Mean Time to Detect): Time from first alert timestamp to SOC acknowledgment.
**MTTR** (Mean Time to Respond): Time from acknowledgment to resolution (suppress/block/escalate).

Target: MTTD < 15 minutes for Severity 1. MTTR < 4 hours for Severity 1.

---

## EVE JSON Filtering Reference

```bash
# All alerts (today)
jq -c 'select(.event_type == "alert")' /var/log/suricata/eve.json | grep "$(date +%Y-%m-%d)"

# Alerts by severity (1 = critical)
jq -c 'select(.event_type == "alert" and .alert.severity == 1)' /var/log/suricata/eve.json | tail -20

# Alerts from specific source
jq -c 'select(.event_type == "alert" and .src_ip == "192.168.1.100")' /var/log/suricata/eve.json

# DNS events
jq -c 'select(.event_type == "dns")' /var/log/suricata/eve.json | tail -10

# TLS events with JA3 hash
jq -c 'select(.event_type == "tls" and .tls.ja3 != null) | {src: .src_ip, sni: .tls.sni, ja3: .tls.ja3.hash}' \
  /var/log/suricata/eve.json | tail -10
```

## Zeek Query Reference

```bash
# Connections to specific port
cat conn.log | zeek-cut ts id.orig_h id.resp_h id.resp_p | awk '$4 == "4444"'

# All external connections from one host
grep "10.0.0.50" conn.log | zeek-cut id.resp_h id.resp_p | grep -v "^10\." | sort | uniq -c | sort -rn

# Notice log (Zeek policy detections)
cat notice.log | zeek-cut ts note msg sub src dst | tail -20

# SSL certificates with self-signed issuer
cat ssl.log | zeek-cut ts id.orig_h id.resp_h subject issuer | \
  awk '$4 == $5 {print "SELF-SIGNED:", $0}' | tail -10
```
