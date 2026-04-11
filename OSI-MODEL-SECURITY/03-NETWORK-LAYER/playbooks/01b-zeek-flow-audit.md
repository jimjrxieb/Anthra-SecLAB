# Layer 3 Network — Zeek Flow Audit

| Field | Value |
|-------|-------|
| NIST Controls | AU-2 (Event Logging), SI-4 (System Monitoring), AU-9 (Log Protection) |
| Tools | audit-zeek-config.sh, zeekctl, zeek-cut, jq |
| Time Estimate | 30–45 minutes |
| Rank | D |

---

## Objective

Verify Zeek is producing complete, accurate flow logs. Confirm conn.log health, DNS log coverage, traffic baseline patterns, log rotation, and SIEM integration. Zeek's value is only realized if logs are flowing, retained, and queried.

---

## Step 1: Run the Automated Audit Script

```bash
bash 01-auditors/audit-zeek-config.sh
# Evidence: /tmp/jsa-evidence/zeek-audit-*/
```

Review FAIL items before proceeding.

---

## Step 2: conn.log Health Check

conn.log is Zeek's primary output. A healthy conn.log should show:
- New entries every few seconds (on any active network)
- State codes including SF (successful full connection), S0 (unanswered SYN), REJ (rejected)
- A variety of source/destination IPs (not just one host)

```bash
# Line count (should be growing)
wc -l /opt/zeek/logs/current/conn.log

# Count connections in last 5 minutes (approximate via file mtime)
# Or use zeek-cut for proper field parsing
cat /opt/zeek/logs/current/conn.log | zeek-cut ts id.orig_h id.resp_h id.resp_p proto service \
  | tail -20

# Connection state distribution (SF=success, S0=no response, REJ=rejected)
cat /opt/zeek/logs/current/conn.log | zeek-cut conn_state \
  | sort | uniq -c | sort -rn | head -10
```

Red flags:
- All entries have state S0 (Zeek sees traffic but no responses — mirror port issue)
- conn.log is not being written at all
- Only one source IP appears (not capturing the interface correctly)

---

## Step 3: DNS Log Review

```bash
# Top queried domains in last session
cat /opt/zeek/logs/current/dns.log | zeek-cut query qtype_name answers \
  | grep "A$\|AAAA$" | sort | uniq -c | sort -rn | head -20

# Check for suspicious TLDs
cat /opt/zeek/logs/current/dns.log | zeek-cut query \
  | grep -E "\.(top|xyz|click|tk|pw)$" | sort | uniq -c | sort -rn

# Check for long DNS queries (possible tunneling)
cat /opt/zeek/logs/current/dns.log | zeek-cut query \
  | awk 'length($0) > 50' | sort | uniq -c | sort -rn | head -10

# DNS failure rate (NXDOMAIN = potentially scanning or misconfigured)
cat /opt/zeek/logs/current/dns.log | zeek-cut rcode_name \
  | sort | uniq -c | sort -rn
```

---

## Step 4: Baseline Traffic Patterns

Establish what normal looks like before an incident makes you guess.

```bash
# Top talkers by bytes (potential exfiltration baseline)
cat /opt/zeek/logs/current/conn.log | zeek-cut id.orig_h orig_bytes \
  | awk '{hosts[$1]+=$2} END {for (h in hosts) print hosts[h], h}' \
  | sort -rn | head -10

# Top destination ports (service inventory)
cat /opt/zeek/logs/current/conn.log | zeek-cut id.resp_p proto \
  | sort | uniq -c | sort -rn | head -20

# Top external destinations (potential C2 baseline)
cat /opt/zeek/logs/current/conn.log | zeek-cut id.orig_h id.resp_h id.resp_p \
  | grep -v "^10\.\|^172\.1[6-9]\.\|^172\.2[0-9]\.\|^172\.3[01]\.\|^192\.168\." \
  | awk '{print $2, $3}' | sort | uniq -c | sort -rn | head -20

# Long-duration connections (potential tunnels or persistent C2)
cat /opt/zeek/logs/current/conn.log | zeek-cut id.orig_h id.resp_h duration proto \
  | awk '$4 > 3600' | sort -k4 -rn | head -10
```

Save this output as baseline for the `evidence/` directory.

---

## Step 5: Log Rotation Check

```bash
# Check for archive directories (rotation creates dated subdirs)
ls /opt/zeek/logs/ | head -20
# Expect: 2026-04-08, 2026-04-09, 2026-04-10, current/

# Check zeekctl rotation config
zeekctl config | grep -i "rotat\|archive\|expir"

# Expected rotation interval: 1 hour (default)
# Expected log expiration: ≥7 days

# Check disk usage
du -sh /opt/zeek/logs/
# Plan for 1GB+ per day on moderately busy networks
```

If no archive directories exist, either:
1. Zeek just installed (first rotation hasn't happened)
2. Log rotation is not configured — AU-9 finding
3. Old logs are being deleted before archiving

---

## Step 6: SIEM Integration Verification

```bash
# Check if a log shipper is collecting Zeek logs
ps aux | grep -E "splunk|filebeat|fluent|logstash" | grep -v grep

# Check filebeat Zeek module
cat /etc/filebeat/modules.d/zeek.yml 2>/dev/null | head -20

# Check Splunk forwarder for Zeek input
grep -r "zeek\|/opt/zeek" /opt/splunkforwarder/etc/ 2>/dev/null

# Check Fluentd/Fluent Bit config
grep -r "zeek\|conn.log" /etc/fluent/ /etc/fluent-bit/ 2>/dev/null | head -10
```

If no shipper is found, Zeek logs are only available on the sensor itself. An incident requires direct sensor access to investigate — this is a gap for distributed environments.

---

## Audit Checklist

| Check | Command | Pass Condition |
|-------|---------|---------------|
| Process running | `zeekctl status` or `pgrep zeek` | Running state |
| conn.log active | `wc -l conn.log` | Growing, >10 entries |
| dns.log present | `ls current/dns.log` | Exists, has entries |
| http.log present | `ls current/http.log` | Exists (if HTTP traffic present) |
| ssl.log present | `ls current/ssl.log` | Exists (if TLS traffic present) |
| notice.log present | `ls current/notice.log` | Exists |
| Log rotation working | `ls /opt/zeek/logs/` | Archive directories present |
| DNS protocol loaded | `grep dns local.zeek` | @load protocols/dns found |
| File hashing enabled | `grep hash local.zeek` | @load frameworks/files/hash-all-files found |
| SIEM collecting | `ps aux \| grep filebeat` | Shipper process running |
