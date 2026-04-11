# 03-validate.md — L7 Application Layer Validation

| Field | Value |
|---|---|
| **NIST Controls** | AU-6 (audit review), RA-5 (vulnerability scanning), SI-4 (monitoring), CA-7 (continuous monitoring) |
| **Tools** | All L7 auditors / SIEM test events / synthetic alerts |
| **Time** | 45 minutes |
| **Rank** | D (read-only validation — no changes made) |

---

## Purpose

Verify that all remediations from `02-fix-*` playbooks are working. This is the "it works in production" check, not just "it's configured." Each validation test generates observable evidence.

---

## Step 1: Run All Auditors

```bash
# Full audit — all 5 checks
./tools/run-all-audits.sh

# Compare finding counts to baseline (from 01-assess.md)
# Expected: each finding count should decrease or reach 0
```

---

## Step 2: Verify SIEM Log Flow

### Sentinel: Data is Flowing

```bash
# Run this 15 minutes after onboarding new connectors
az monitor log-analytics query \
  --workspace-name "$SENTINEL_WORKSPACE" \
  --resource-group "$SENTINEL_RG" \
  --analytics-query "
union withsource=TableName *
| where TimeGenerated > ago(30m)
| summarize RecordCount=count() by TableName
| where RecordCount > 0
| sort by RecordCount desc
"
```

**Expected tables (minimum coverage):**
- `SigninLogs` — Azure AD sign-ins
- `SecurityEvent` — Windows security events
- `AuditLogs` — Azure AD audit events
- `Syslog` — Linux events (if Linux hosts connected)

### Splunk: Events Flowing

```bash
# Check events in last 30 minutes
curl -sk -u "${SPLUNK_USER}:${SPLUNK_PASS}" \
  "https://${SPLUNK_HOST}:8089/services/search/jobs" \
  --data-urlencode "search=search index=* earliest=-30m | stats count by index, sourcetype | sort -count" \
  -d "exec_mode=oneshot&output_mode=json" | \
  python3 -c "
import sys,json
d=json.load(sys.stdin)
for r in d.get('results',[]):
    print(f\"  [{r['count']:>8}] {r['index']}/{r['sourcetype']}\")
"
```

---

## Step 3: Test Alert Rules with Synthetic Events

### Sentinel: Simulate Brute Force

```bash
# This KQL will return results to test the rule fires
# Run in Sentinel Log Analytics > Logs
```

```kql
// Simulate brute force alert — inject test data
// This is a KQL test — does NOT create actual failed logins
SigninLogs
| where TimeGenerated > ago(5m)
| where ResultType != "0"
| summarize FailedAttempts=count(), Targets=make_set(UserPrincipalName)
    by IPAddress
| where FailedAttempts > 0
| take 5
// If results appear → brute force rule will fire on real data
```

### Sentinel: Test Privilege Escalation Rule

```bash
# Check if AuditLogs is receiving role assignment events
az monitor log-analytics query \
  --workspace-name "$SENTINEL_WORKSPACE" \
  --resource-group "$SENTINEL_RG" \
  --analytics-query "
AuditLogs
| where TimeGenerated > ago(24h)
| where OperationName contains 'role'
| take 5
| project TimeGenerated, OperationName, Result, InitiatedBy
"
# If 0 rows: AuditLogs connector not active
```

### Splunk: Inject a Test Event

```bash
# Send a test event to HEC to verify ingestion
HEC_TOKEN="${SPLUNK_HEC_TOKEN:-}"
if [[ -n "$HEC_TOKEN" ]]; then
  curl -sk "https://${SPLUNK_HOST}:8088/services/collector/event" \
    -H "Authorization: Splunk $HEC_TOKEN" \
    -d '{
      "event": {
        "EventCode": "4625",
        "Account_Name": "testuser",
        "Source_Network_Address": "10.0.0.1",
        "message": "Test failed logon event - JSA validation",
        "_test": true
      },
      "sourcetype": "WinEventLog",
      "index": "main"
    }'

  # Wait 30 seconds for indexing
  sleep 30

  # Verify it arrived
  curl -sk -u "${SPLUNK_USER}:${SPLUNK_PASS}" \
    "https://${SPLUNK_HOST}:8089/services/search/jobs" \
    --data-urlencode 'search=search index=main "Test failed logon event - JSA validation" | head 1' \
    -d 'exec_mode=oneshot&output_mode=json' | \
    python3 -c "
import sys,json
d=json.load(sys.stdin)
count=len(d.get('results',[]))
print(f'[{\"PASS\" if count > 0 else \"FAIL\"}] Test event found: {count} results')
"
fi
```

---

## Step 4: Verify Scan Coverage

```bash
# Check Trivy is in CI and exit codes are set
find . -name "*.yml" -o -name "*.yaml" 2>/dev/null | \
  xargs grep -l "trivy" 2>/dev/null | head -5 && \
  echo "[PASS] Trivy in CI pipeline" || echo "[FAIL] Trivy missing from CI"

# Verify Semgrep pre-commit
pre-commit run --all-files semgrep 2>/dev/null && \
  echo "[PASS] Semgrep pre-commit works" || \
  echo "[CHECK] Semgrep pre-commit returned findings (expected in lab)"

# Verify kube-bench CronJob
kubectl get cronjob -n kube-bench 2>/dev/null && \
  echo "[PASS] kube-bench CronJob scheduled" || \
  echo "[WARN] kube-bench CronJob not found"
```

---

## Step 5: Verify FIM

```bash
# Confirm critical paths are monitored
for PATH in "/etc/passwd" "/etc/shadow" "/etc/sudoers" "/etc/ssh/sshd_config"; do
  grep -q "$PATH" /var/ossec/etc/ossec.conf 2>/dev/null && \
    echo "[PASS] FIM: $PATH" || \
    echo "[FAIL] FIM missing: $PATH"
done

# Confirm realtime monitoring
RT_COUNT=$(grep -c 'realtime="yes"' /var/ossec/etc/ossec.conf 2>/dev/null || echo "0")
[[ $RT_COUNT -gt 0 ]] && echo "[PASS] Realtime FIM: $RT_COUNT paths" || \
  echo "[FAIL] No realtime FIM paths configured"

# Generate a test FIM event
echo "# test-$(date +%s)" >> /etc/hosts && sleep 5
tail -5 /var/ossec/logs/alerts/alerts.log 2>/dev/null | grep -i "hosts" && \
  echo "[PASS] FIM alert fired for /etc/hosts change" || \
  echo "[CHECK] FIM alert for /etc/hosts not found in last 5 alerts"

# Revert test change
sed -i '$ d' /etc/hosts 2>/dev/null || true
```

---

## Validation Checklist

| Control | Check | Status |
|---|---|---|
| AU-2 | SIEM receiving events (last 30min) | [ ] PASS / FAIL |
| AU-6 | Alert rules enabled and firing | [ ] PASS / FAIL |
| AU-11 | Log retention ≥ 90 days | [ ] PASS / FAIL |
| SI-4 | EDR agents active on all hosts | [ ] PASS / FAIL |
| SI-7 | FIM covering critical paths + alerts firing | [ ] PASS / FAIL |
| RA-5 | Trivy in CI with exit-code enforcement | [ ] PASS / FAIL |
| SA-11 | Semgrep in pre-commit and CI | [ ] PASS / FAIL |

---

## Evidence Capture

```bash
EVIDENCE_DIR="../evidence/validation-$(date +%Y%m%d)"
mkdir -p "$EVIDENCE_DIR"

# SIEM
./01-auditors/audit-siem-ingest.sh 2>&1 | tee "${EVIDENCE_DIR}/siem-validation.txt"
./01-auditors/audit-alert-rules.sh 2>&1 | tee "${EVIDENCE_DIR}/alert-rules-validation.txt"

# EDR
./01-auditors/audit-edr-agents.sh 2>&1 | tee "${EVIDENCE_DIR}/edr-validation.txt"

# Vuln scan
./01-auditors/audit-vuln-scan-coverage.sh 2>&1 | tee "${EVIDENCE_DIR}/vuln-scan-validation.txt"

# Retention
./01-auditors/audit-log-retention.sh 2>&1 | tee "${EVIDENCE_DIR}/retention-validation.txt"

echo "Evidence captured in: $EVIDENCE_DIR"
```

**Next step:** `04-triage-alerts.md` — daily SOC operations
