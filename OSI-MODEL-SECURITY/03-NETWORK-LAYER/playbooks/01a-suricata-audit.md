# Layer 3 Network — Suricata Deep-Dive Audit

| Field | Value |
|-------|-------|
| NIST Controls | SI-3 (Malicious Code Protection), SI-4 (System Monitoring), SI-5 (Security Alerts) |
| Tools | audit-suricata-config.sh, suricata-update, jq/python3 |
| Time Estimate | 45–60 minutes |
| Rank | D (review) / C (tuning decisions) |

---

## Objective

Full Suricata operational audit beyond the automated script. A running Suricata with default config is not the same as an effective IDS. This audit verifies: correct config, current signatures, active detection, suppression hygiene, and SIEM integration.

---

## Step 1: Run the Automated Audit Script

```bash
sudo bash 01-auditors/audit-suricata-config.sh
# Review evidence: /tmp/jsa-evidence/suricata-audit-*/
```

Note every FAIL and WARN before proceeding to manual checks.

---

## Step 2: Diff Active Config Against Template

The template represents the gold standard. Any deviation must be intentional and documented.

```bash
# Compare running config against template
diff /etc/suricata/suricata.yaml 03-templates/suricata/suricata.yaml \
  | grep -E "^[<>]" | head -40
```

Key items to verify match the template:
- `eve-log: enabled: yes` — required for SIEM integration
- `dns:` included in EVE output types — required for AU-2
- `tls: extended: yes` — required for JA3 fingerprinting
- `payload: yes` under alert — required for incident forensics
- `HOME_NET` set to actual network CIDR (not template placeholder)
- `local.rules` referenced in `rule-files:` list

---

## Step 3: Check Rule Freshness (Must Be < 7 Days)

```bash
# Check age of the primary rules file
stat /var/lib/suricata/rules/suricata.rules | grep "Modify"
# OR
find /var/lib/suricata/rules -name "*.rules" \
  -printf "%T@ %p\n" | sort -rn | head -5 | \
  while read ts f; do
    AGE=$(( ($(date +%s) - ${ts%.*}) / 86400 ))
    echo "${AGE} days old: $f"
  done
```

Rules >7 days old miss current threat signatures. Rules >30 days old are a compliance finding (SI-3 requires mechanisms for current signature deployment).

```bash
# Check what rule sources are configured
sudo suricata-update list-enabled-sources

# Check last update log
grep "suricata-update" /var/log/syslog | tail -10 2>/dev/null || \
  cat /var/lib/suricata/update/update.log 2>/dev/null | tail -20
```

---

## Step 4: Verify Rule Sources

```bash
# List all enabled sources
sudo suricata-update list-sources | grep "Enabled: true"

# Recommended minimum: et/open (Emerging Threats Open)
# Additional: et/pro (commercial), abuse.ch/sslbl, abuse.ch/urlhaus
# Check if et/open is active
sudo suricata-update list-enabled-sources | grep "et/open"
```

For environments requiring comprehensive coverage:

```bash
# Enable additional free sources
sudo suricata-update enable-source oisf/trafficid
sudo suricata-update enable-source ptresearch/attackdetection
sudo suricata-update enable-source tgreen/hunting
sudo suricata-update update
```

---

## Step 5: Three Live Detection Tests

### Test 1: HTTP-based NIDS test (ET OPEN rule 2100498)

```bash
echo "--- Test 1: NIDS validation test ---"
PRE=$(wc -l < /var/log/suricata/eve.json 2>/dev/null || echo 0)
curl -s http://testmynids.org/uid/index.html > /dev/null
sleep 2
POST=$(wc -l < /var/log/suricata/eve.json 2>/dev/null || echo 0)
echo "New eve.json entries: $((POST - PRE))"

tail -20 /var/log/suricata/eve.json | python3 -c "
import sys, json
for line in sys.stdin:
    try:
        e = json.loads(line)
        if e.get('event_type') == 'alert':
            a = e.get('alert', {})
            print(f'  SID {a.get(\"signature_id\")}: {a.get(\"signature\")}')
    except: pass
"
```

**Expected:** ET POLICY or similar alert. If no alert: Suricata is not inspecting this traffic path.

### Test 2: DNS query to suspicious TLD (local rule SID 1000020)

```bash
echo "--- Test 2: DNS suspicious TLD ---"
PRE=$(wc -l < /var/log/suricata/eve.json 2>/dev/null || echo 0)
dig example.top @8.8.8.8 > /dev/null 2>&1 || nslookup example.top 8.8.8.8 > /dev/null 2>&1
sleep 2
POST=$(wc -l < /var/log/suricata/eve.json 2>/dev/null || echo 0)

# Check for SID 1000020
tail -50 /var/log/suricata/eve.json | python3 -c "
import sys, json
for line in sys.stdin:
    try:
        e = json.loads(line)
        a = e.get('alert', {})
        if a.get('signature_id') == 1000020:
            print('PASS: SID 1000020 fired:', a.get('signature'))
    except: pass
" || echo "SID 1000020 not fired — verify local.rules is loaded"
```

### Test 3: ICMP ping flood (validates traffic is being captured at all)

```bash
echo "--- Test 3: ICMP capture validation ---"
# Send pings and verify flow log records them
ping -c 5 8.8.8.8 > /dev/null 2>&1 &
sleep 3

# Check for ICMP in recent flow entries
tail -100 /var/log/suricata/eve.json | python3 -c "
import sys, json
found = False
for line in sys.stdin:
    try:
        e = json.loads(line)
        if e.get('proto') == 'ICMP' or e.get('event_type') == 'flow' and e.get('proto') == 'ICMP':
            print('PASS: ICMP flow captured')
            found = True
            break
    except: pass
if not found:
    print('WARN: No recent ICMP flow in eve.json — verify interface config')
"
```

---

## Step 6: Review Suppressions for Justification

Suppressions silence alerts permanently. Undocumented suppressions create blind spots.

```bash
# Find all suppress rules
grep -r "suppress\|threshold" /etc/suricata/rules/ 2>/dev/null | grep -v "^#"

# Check suppress list if it exists
cat /etc/suricata/threshold.conf 2>/dev/null | grep -v "^#" | grep -v "^$"
```

For each suppress entry, verify:
- A documented justification exists (Jira ticket, change record, or comment)
- The SID being suppressed is not a high-severity signature
- Time-bounded suppressions have been reviewed recently (>90 days old = review)

---

## Step 7: SIEM Integration Check

```bash
# Verify eve.json is being collected by Splunk/Elastic/Fluentd
# Check for a log shipper targeting eve.json
ps aux | grep -E "splunk|filebeat|fluent|logstash|rsyslog" | grep -v grep

# Check filebeat config for Suricata input
grep -r "eve.json\|suricata" /etc/filebeat/ 2>/dev/null | head -10

# Check Splunk monitors for Suricata
cat /opt/splunkforwarder/etc/system/local/inputs.conf 2>/dev/null | grep -A3 "suricata"
```

If no log shipper is collecting eve.json, alerts exist on the sensor but not in the SOC.

---

## Pass/Fail Summary

| Check | Pass Condition |
|-------|---------------|
| Process running | pgrep suricata returns PID |
| EVE JSON enabled | `enabled: yes` under `eve-log:` in suricata.yaml |
| Rule count | ≥ 30,000 rules loaded |
| Rule freshness | Rules updated within 7 days |
| Custom local.rules | File exists, ≥1 active rule |
| HOME_NET configured | Not template placeholder, matches actual network |
| Test 1 fires | EVE alert on testmynids.org request |
| Test 2 fires | SID 1000020 fires on .top DNS query |
| Suppressions justified | All suppress entries have documented reason |
| SIEM collecting | Log shipper confirmed targeting eve.json |
