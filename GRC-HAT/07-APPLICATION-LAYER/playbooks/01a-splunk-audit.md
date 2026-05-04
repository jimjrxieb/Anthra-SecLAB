# 01a-splunk-audit.md — Splunk Deep-Dive Audit

| Field | Value |
|---|---|
| **NIST Controls** | AU-6 (audit review), SI-4 (monitoring), AU-2 (event logging), AU-11 (audit retention) |
| **Tools** | Splunk CLI / Splunk REST API / SPL (Search Processing Language) |
| **Enterprise Equiv** | Splunk Enterprise Security (ES) $500K+ / IBM QRadar $400K+ |
| **CySA+ Note** | ALTERNATIVE SIEM — use when client runs on-prem Splunk instead of Sentinel |
| **Time** | 45 minutes |
| **Rank** | D (read-only audit — no changes) |

---

## Purpose

This playbook audits an on-premises or hybrid Splunk deployment. Splunk is the dominant SIEM in enterprise environments outside of Azure. If the client has a Splunk forwarder, a Splunk indexer cluster, or Splunk Enterprise Security — this is your audit path.

The SPL queries below mirror the KQL queries in `01a-sentinel-audit.md` — same logic, different language.

---

## Pre-Requisites

```bash
# Set environment variables
export SPLUNK_HOST="localhost"          # or splunk.company.com
export SPLUNK_MGMT_PORT="8089"
export SPLUNK_USER="admin"
export SPLUNK_PASS="yourpassword"

# Verify connectivity
curl -sk -u "${SPLUNK_USER}:${SPLUNK_PASS}" \
  "https://${SPLUNK_HOST}:${SPLUNK_MGMT_PORT}/services/server/info?output_mode=json" | \
  python3 -c "import sys,json; d=json.load(sys.stdin); print(d['entry'][0]['content']['serverName'])"
```

---

## 1. Splunk Health Check

```bash
# Service status
systemctl status splunk 2>/dev/null || \
  /opt/splunk/bin/splunk status

# License usage (500MB/day dev limit)
/opt/splunk/bin/splunk show license-usage 2>/dev/null || \
curl -sk -u "${SPLUNK_USER}:${SPLUNK_PASS}" \
  "https://${SPLUNK_HOST}:${SPLUNK_MGMT_PORT}/services/licenser/usage?output_mode=json" | \
  python3 -c "import sys,json; d=json.load(sys.stdin); print('License used:', d['entry'][0]['content']['quota_used_bytes'] // 1048576, 'MB')"

# Indexer cluster health (if clustered)
curl -sk -u "${SPLUNK_USER}:${SPLUNK_PASS}" \
  "https://${SPLUNK_HOST}:${SPLUNK_MGMT_PORT}/services/cluster/master/info?output_mode=json" 2>/dev/null | \
  python3 -m json.tool | grep -E "label|status|replication_factor" || echo "Not a cluster master"
```

**What to look for:**
- License approaching 500MB/day limit (dev) — ingestion will stop
- Indexer cluster status: not_master or degraded = coverage risk

---

## 2. HEC Endpoint Health

```bash
# HTTP Event Collector health check
HEC_STATUS=$(curl -sk \
  "https://${SPLUNK_HOST}:8088/services/collector/health" \
  --max-time 5 -w "%{http_code}" -o /dev/null 2>/dev/null)

if [[ "$HEC_STATUS" == "200" ]]; then
  echo "[PASS] HEC endpoint healthy"
elif [[ "$HEC_STATUS" == "400" ]]; then
  echo "[PASS] HEC reachable (400 = no token sent, endpoint is up)"
else
  echo "[FAIL] HEC returned: $HEC_STATUS — check configuration"
fi

# List HEC tokens
curl -sk -u "${SPLUNK_USER}:${SPLUNK_PASS}" \
  "https://${SPLUNK_HOST}:${SPLUNK_MGMT_PORT}/services/data/inputs/http?output_mode=json" | \
  python3 -c "
import sys,json
d=json.load(sys.stdin)
for e in d.get('entry',[]):
    print(f\"  Token: {e['name']} | Index: {e['content'].get('index','N/A')} | Disabled: {e['content'].get('disabled','N/A')}\")
"
```

---

## 3. Index Status and Size

```bash
# All indexes with event counts
curl -sk -u "${SPLUNK_USER}:${SPLUNK_PASS}" \
  "https://${SPLUNK_HOST}:${SPLUNK_MGMT_PORT}/services/data/indexes?output_mode=json&count=0" | \
  python3 -c "
import sys,json
d=json.load(sys.stdin)
print(f'{'Index':<30} {'Events':>15} {'Size (MB)':>12} {'Retention':>12}')
print('-' * 72)
for e in d.get('entry',[]):
    c = e['content']
    events = int(c.get('totalEventCount','0') or 0)
    size = int(c.get('currentDBSizeMB','0') or 0)
    frozen = int(c.get('frozenTimePeriodInSecs','0') or 0) // 86400
    if events > 0:
        print(f\"{e['name']:<30} {events:>15,} {size:>12,} {frozen:>11}d\")
"

# Check required security indexes
for IDX in main security wineventlog linux_secure k8s; do
  COUNT=$(curl -sk -u "${SPLUNK_USER}:${SPLUNK_PASS}" \
    "https://${SPLUNK_HOST}:${SPLUNK_MGMT_PORT}/services/data/indexes/${IDX}?output_mode=json" 2>/dev/null | \
    python3 -c "import sys,json; print(json.load(sys.stdin)['entry'][0]['content']['totalEventCount'])" 2>/dev/null || echo "NOT FOUND")
  echo "  Index '$IDX': $COUNT events"
done
```

---

## 4. Saved Search Review

```bash
# List all scheduled searches
curl -sk -u "${SPLUNK_USER}:${SPLUNK_PASS}" \
  "https://${SPLUNK_HOST}:${SPLUNK_MGMT_PORT}/services/saved/searches?output_mode=json&count=0&search=is_scheduled=1" | \
  python3 -c "
import sys,json
d=json.load(sys.stdin)
enabled = [e for e in d.get('entry',[]) if not (e['content'].get('disabled',False))]
disabled = [e for e in d.get('entry',[]) if e['content'].get('disabled',False)]
print(f'Total scheduled: {len(d[\"entry\"])} | Enabled: {len(enabled)} | Disabled: {len(disabled)}')
print()
print('Enabled searches:')
for e in enabled:
    print(f\"  [{e['content'].get('alert.severity','N/A')}] {e['name']}\")
"

# Coverage gap check
for DETECTION in "brute" "privilege" "escalation" "login" "authentication"; do
  COUNT=$(curl -sk -u "${SPLUNK_USER}:${SPLUNK_PASS}" \
    "https://${SPLUNK_HOST}:${SPLUNK_MGMT_PORT}/services/saved/searches?output_mode=json&count=0&search=title%3D*${DETECTION}*" 2>/dev/null | \
    python3 -c "import sys,json; print(len(json.load(sys.stdin)['entry']))" 2>/dev/null || echo "0")
  [[ "$COUNT" -gt 0 ]] && echo "[PRESENT] $DETECTION searches: $COUNT" || echo "[MISSING] No searches matching: $DETECTION"
done
```

---

## 5. Dashboard Health

```bash
# List all dashboards
curl -sk -u "${SPLUNK_USER}:${SPLUNK_PASS}" \
  "https://${SPLUNK_HOST}:${SPLUNK_MGMT_PORT}/services/data/ui/views?output_mode=json&count=0" | \
  python3 -c "
import sys,json
d=json.load(sys.stdin)
dashboards = [e['name'] for e in d.get('entry',[]) if e['content'].get('isDashboard',False)]
print(f'Total dashboards: {len(dashboards)}')
for db in dashboards[:20]:
    print(f'  {db}')
"
```

---

## 6. SPL Hunt Queries

Run these in Splunk Web (http://localhost:8000) > Search & Reporting:

```spl
/* Brute force detection — 5+ failures from single IP */
/* NIST AC-7, MITRE T1110 */
index=wineventlog EventCode=4625
| stats count as FailedAttempts, values(Account_Name) as Targets
    by Source_Network_Address
| where FailedAttempts > 5
| sort -FailedAttempts

/* Privilege escalation — special privileges */
/* NIST AC-6, MITRE T1548 */
index=wineventlog (EventCode=4672 OR EventCode=4728 OR EventCode=4732)
| stats count by Account_Name, EventCode, host
| sort -count

/* New admin account created */
/* NIST AC-2, MITRE T1136 */
index=wineventlog EventCode=4720
| table _time, Account_Name, Subject_Account_Name, host

/* Wazuh FIM alerts — file integrity changes */
/* NIST SI-7, MITRE T1565 */
index=security sourcetype=wazuh rule.level>=10 "syscheck.event"=*
| spath output=FilePath path="syscheck.path"
| spath output=FIMEvent path="syscheck.event"
| spath output=Agent path="agent.name"
| table _time, Agent, FilePath, FIMEvent
| sort -_time

/* K8s exec into pods — immediate investigation */
/* NIST SI-4, MITRE T1609 */
index=k8s sourcetype=kube:apiserver:audit verb=create requestURI=*/exec*
| spath output=User path="user.username"
| spath output=Pod path="objectRef.name"
| spath output=Namespace path="objectRef.namespace"
| table _time, User, Namespace, Pod, sourceIPAddresses{}
```

---

## 7. Retention Policy Compliance Check

```bash
# Check retention per index
curl -sk -u "${SPLUNK_USER}:${SPLUNK_PASS}" \
  "https://${SPLUNK_HOST}:${SPLUNK_MGMT_PORT}/services/data/indexes?output_mode=json&count=0" | \
  python3 -c "
import sys,json
d=json.load(sys.stdin)
requirements = {'HIPAA': 2190, 'FedRAMP': 1095, 'PCI-DSS': 365, 'SOC2': 365}
for e in d.get('entry',[]):
    name = e['name']
    frozen = int(e['content'].get('frozenTimePeriodInSecs','0') or 0) // 86400
    if name in ['main','security','wineventlog']:
        print(f'Index: {name} — {frozen} days retention')
        for fw,req in requirements.items():
            status = 'PASS' if frozen >= req else 'FAIL'
            print(f'  [{status}] {fw}: {frozen}d vs {req}d required')
"
```

---

## Audit Checklist Summary

| Check | Tool | Pass Criteria |
|---|---|---|
| Splunk service running | systemctl / splunk status | Active |
| HEC endpoint healthy | curl | HTTP 200 or 400 |
| Required indexes exist | REST API | main, security, wineventlog present |
| Events flowing (last 1h) | REST API | > 0 events in each required index |
| Scheduled searches > 5 | REST API | ≥5 enabled scheduled searches |
| Critical detections present | REST API | Brute force + priv escalation searches |
| Retention ≥ 90 days | REST API | frozenTimePeriodInSecs ≥ 7776000 |

---

## Run Automated Audit

```bash
./01-auditors/audit-siem-ingest.sh --splunk-only
./01-auditors/audit-alert-rules.sh --splunk-only
./01-auditors/audit-log-retention.sh --splunk-only
```

---

## If You Find Gaps

- Missing log sources → `02-fixers/fix-missing-log-source.sh --splunk`
- Missing alert rules → `02-fixers/fix-splunk-alert-rules.sh`
- Low retention → Update frozenTimePeriodInSecs in indexes.conf
- No dashboards → `03-templates/splunk/dashboard-soc-overview.xml`
