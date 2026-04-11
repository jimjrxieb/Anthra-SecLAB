# 04-triage-alerts.md — L6 Daily Alert Triage

| Field | Value |
|---|---|
| **NIST Controls** | AU-6 (audit review), CA-7 (continuous monitoring), SC-12, SC-13, SC-28 |
| **Frequency** | Daily (15–30 minutes) |
| **Objective** | Review encryption, key management, and secrets alerts — act on anomalies |
| **Rank** | D (pattern recognition) / C (anomaly investigation) |

---

## Daily Triage Queue

Work through these in order. Stop and escalate if you find an active incident.

---

## 1. Azure Key Vault Access Logs

**What to look for:** Unusual access patterns, repeated failures, unauthorized principals.

```bash
# Pull last 24h of Key Vault operations
az monitor activity-log list \
    --start-time "$(date -u -d '24 hours ago' '+%Y-%m-%dT%H:%M:%SZ')" \
    --resource-type "microsoft.keyvault/vaults" \
    --output json 2>/dev/null \
    | python3 -c "
import json,sys
events = json.load(sys.stdin)
for e in events:
    status = e.get('status',{}).get('value','')
    op = e.get('operationName',{}).get('value','')
    caller = e.get('caller','')
    time = e.get('eventTimestamp','')
    if status == 'Failed':
        print(f'[FAIL] {time} | {op} | caller={caller}')
    elif 'SecretGet' in op or 'KeyDecrypt' in op or 'KeyEncrypt' in op:
        print(f'[ACCESS] {time} | {op} | caller={caller}')
"

# WHY: Failed Key Vault operations = wrong permissions, misconfigured apps, or enumeration attempts.
# Multiple failures from the same IP = credential stuffing against Key Vault.
```

**Alert triggers:**
- More than 10 failed operations in 1 hour from a single identity
- Access from an IP not in the expected range
- Access outside business hours from service principals (bots don't need 2 AM access)
- Unexpected key export or backup operation

**Investigation workflow:**
```bash
# Get details on a suspicious operation
az monitor activity-log list \
    --caller "<suspicious-object-id>" \
    --start-time "$(date -u -d '24 hours ago' '+%Y-%m-%dT%H:%M:%SZ')" \
    -o json | python3 -m json.tool
```

---

## 2. HashiCorp Vault Audit Logs

**What to look for:** Unusual decrypt volume, token errors, policy denials.

```bash
VAULT_LOG="${VAULT_LOG_PATH:-/opt/vault/logs/vault-audit.log}"

# Check for policy denials in last 24h
tail -n 10000 "$VAULT_LOG" 2>/dev/null \
    | python3 -c "
import json,sys
from datetime import datetime, timezone, timedelta

cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
denials = []
errors = []

for line in sys.stdin:
    try:
        entry = json.loads(line.strip())
        ts_str = entry.get('time','')
        ts = datetime.fromisoformat(ts_str.replace('Z','+00:00')) if ts_str else None
        if ts and ts < cutoff:
            continue
        req = entry.get('request', {})
        resp = entry.get('response', {})
        auth = entry.get('auth', {})
        error = entry.get('error', '')

        if error and 'permission denied' in error.lower():
            path = req.get('path','')
            accessor = auth.get('accessor','unknown')
            denials.append(f'{ts_str} | POLICY DENY | path={path} | accessor={accessor}')
        elif error:
            errors.append(f'{ts_str} | ERROR | {error}')
    except json.JSONDecodeError:
        pass

print(f'Policy denials (24h): {len(denials)}')
for d in denials[:20]:
    print(f'  {d}')
print(f'Errors (24h): {len(errors)}')
for e in errors[:10]:
    print(f'  {e}')
" 2>/dev/null || echo "Vault audit log not found at ${VAULT_LOG}"

# WHY: Policy denials = misconfigured app, attempted privilege escalation, or
#      application using wrong token/path. Normal apps don't get policy denials.
```

**Alert triggers:**
- Policy denial on a transit/decrypt or secret/get path (legitimate apps don't get denied)
- Token renew failures (service may lose access to secrets — approaching outage)
- Unusual decrypt volume spike (possible data exfiltration — decrypting more than expected)
- Root token usage (root token should only be used for break-glass scenarios)

```bash
# Check for root token usage (critical alert)
grep -l '"display_name":"root"' "$VAULT_LOG" 2>/dev/null \
    | while read -r log; do
        RECENT=$(grep '"display_name":"root"' "$log" \
            | python3 -c "
import json,sys,datetime
now = datetime.datetime.now(datetime.timezone.utc)
for line in sys.stdin:
    try:
        e = json.loads(line)
        ts = datetime.datetime.fromisoformat(e.get('time','').replace('Z','+00:00'))
        if (now - ts).total_seconds() < 86400:
            print(f'[CRITICAL] Root token used: {e.get(\"time\")}')
    except:
        pass
")
        echo "$RECENT"
    done
```

---

## 3. gitleaks CI Results

**What to look for:** New secrets committed since last check.

```bash
# Run on current branch
gitleaks detect --source . --report-path /tmp/gitleaks-daily.json \
    --report-format json --exit-code 1 2>/dev/null && \
    echo "[PASS] No new secrets detected" || {
    echo "[FAIL] Secrets detected in repository"
    python3 -c "
import json
with open('/tmp/gitleaks-daily.json') as f:
    leaks = json.load(f)
for leak in leaks[:10]:
    print(f'  Rule: {leak.get(\"RuleID\",\"?\")} | File: {leak.get(\"File\",\"?\")} | Line: {leak.get(\"StartLine\",\"?\")}')
" 2>/dev/null
    echo ""
    echo "IMMEDIATE ACTION REQUIRED:"
    echo "1. Identify which secret type was exposed"
    echo "2. Rotate the secret IMMEDIATELY (before doing anything else)"
    echo "3. Check git log to determine when it was committed"
    echo "4. Determine if it was pushed to remote (if yes: assume compromised)"
    echo "5. Check access logs for unauthorized use of the exposed credential"
}

# Check only commits from last 24h
git log --since="24 hours ago" --format="%H" 2>/dev/null \
    | while read -r commit; do
        gitleaks detect --source . --log-opts "-n 1 ${commit}" \
            --exit-code 1 --quiet 2>/dev/null || \
            echo "[FAIL] Secret found in commit: ${commit}"
    done
```

**If secrets are found:**

```bash
# Determine the secret type and rotate it
# Common types and where to rotate:
# github-pat         → GitHub Settings > Developer settings > Personal access tokens
# aws-access-key     → AWS Console > IAM > Users > Access keys
# azure-client-secret → Azure AD > App registrations > Certificates & secrets
# generic-api-key    → Check the specific service

# After rotating: check if the old secret was used
# (Splunk/CloudTrail query for the leaked credential ID)
```

---

## 4. Certificate Expiry Alerts

**What to look for:** Certificates expiring within 30 days.

```bash
# cert-manager certificates
kubectl get certificates -A -o json 2>/dev/null \
    | python3 -c "
import json,sys,datetime
data = json.load(sys.stdin)
now = datetime.datetime.now(datetime.timezone.utc)
for cert in data.get('items', []):
    ns = cert['metadata']['namespace']
    name = cert['metadata']['name']
    not_after = cert.get('status', {}).get('notAfter', '')
    if not_after:
        exp = datetime.datetime.fromisoformat(not_after.replace('Z','+00:00'))
        days_left = (exp - now).days
        if days_left < 0:
            print(f'[FAIL] {ns}/{name}: EXPIRED {abs(days_left)}d ago')
        elif days_left < 30:
            print(f'[WARN] {ns}/{name}: expires in {days_left}d ({not_after})')
        else:
            pass  # Normal — no output
" 2>/dev/null || echo "cert-manager not found"

# Check external TLS endpoints
for host in your-service.internal api.internal dashboard.internal; do
    EXPIRY=$(echo | timeout 5 openssl s_client -connect "${host}:443" 2>/dev/null \
        | openssl x509 -noout -enddate 2>/dev/null \
        | cut -d= -f2)
    if [[ -n "$EXPIRY" ]]; then
        DAYS_LEFT=$(( ($(date -d "$EXPIRY" +%s) - $(date +%s)) / 86400 ))
        if [[ $DAYS_LEFT -lt 30 ]]; then
            echo "[WARN] ${host}: expires in ${DAYS_LEFT}d ($EXPIRY)"
        fi
    fi
done

# Azure Key Vault certificate expiry
[[ -n "${AZURE_VAULT_NAME:-}" ]] && \
az keyvault certificate list --vault-name "$AZURE_VAULT_NAME" -o json 2>/dev/null \
    | python3 -c "
import json,sys,datetime
certs = json.load(sys.stdin)
now = datetime.datetime.now(datetime.timezone.utc)
for cert in certs:
    exp_str = cert.get('attributes',{}).get('expires','')
    if exp_str:
        exp = datetime.datetime.fromisoformat(exp_str.replace('Z','+00:00'))
        days = (exp - now).days
        name = cert.get('name','?')
        if days < 30:
            print(f'[WARN] AKV cert {name}: expires in {days}d')
" 2>/dev/null

# WHY: Expired certificates cause outages. 30-day window allows renewal
#      without emergency weekend work.
```

---

## 5. Unusual Decryption Patterns

**What to look for:** Volume spikes in decrypt operations — possible data exfiltration.

```bash
# HashiCorp Vault: decrypt operation count by hour
tail -n 50000 "${VAULT_LOG:-/opt/vault/logs/vault-audit.log}" 2>/dev/null \
    | python3 -c "
import json,sys,re
from collections import defaultdict
from datetime import datetime, timezone, timedelta

counts = defaultdict(int)
cutoff = datetime.now(timezone.utc) - timedelta(hours=24)

for line in sys.stdin:
    try:
        e = json.loads(line)
        ts_str = e.get('time','')
        if not ts_str:
            continue
        ts = datetime.fromisoformat(ts_str.replace('Z','+00:00'))
        if ts < cutoff:
            continue
        req = e.get('request',{})
        path = req.get('path','')
        if 'decrypt' in path or 'unwrap' in path:
            hour = ts.strftime('%Y-%m-%d %H:00')
            counts[hour] += 1
    except:
        pass

if counts:
    print('Decrypt operations by hour (last 24h):')
    for hour in sorted(counts.keys()):
        bar = '#' * min(counts[hour] // 10, 50)
        print(f'  {hour}: {counts[hour]:5d} {bar}')
    avg = sum(counts.values()) / len(counts)
    print(f'  Average per hour: {avg:.0f}')
    for hour, count in counts.items():
        if count > avg * 3:
            print(f'  [WARN] Spike at {hour}: {count} ops ({count/avg:.1f}x normal)')
else:
    print('No decrypt operations in audit log')
" 2>/dev/null

# WHY: A 3x+ spike in decrypt operations without a known deployment/batch job
#      may indicate data exfiltration using a compromised credential.
```

---

## Investigation Workflow

When an anomaly requires deeper investigation:

```
1. CONTAIN
   - Which credential/key is involved?
   - Rotate it immediately if there's any doubt
   - Revoke the suspicious token/API key

2. SCOPE
   - What data was accessible with the compromised credential?
   - When did the anomaly start?
   - What did the attacker DO (not just how they got in)?

3. EVIDENCE
   - Export all relevant logs to /tmp/jsa-evidence/incident-<date>/
   - Vault audit log: filtered for the suspicious accessor
   - Azure Key Vault: diagnostic logs for the operation window
   - K8s audit logs: kubectl get events, audit webhook

4. ESCALATE if:
   - Production data was accessed
   - Multiple credentials were exposed
   - There's evidence of lateral movement
   → This becomes a B-rank decision (human-only)
```

---

## Daily Triage Checklist

```
Date: ___________  Time: ___________  Analyst: ___________

Azure Key Vault:
[ ] No failed operations > 10/hour from single identity
[ ] No access from unexpected IPs
[ ] No key export/backup operations by non-admin accounts

HashiCorp Vault:
[ ] Policy denials: _____ (expected: 0)
[ ] Root token used: [ ] Yes [ ] No  (if Yes: ESCALATE)
[ ] Decrypt spike > 3x baseline: [ ] Yes [ ] No

gitleaks / Secrets:
[ ] CI scan: [ ] Pass [ ] Fail  (if Fail: ROTATE IMMEDIATELY)
[ ] No new .env files in git

Certificates:
[ ] No certificates expiring within 30 days

Anomalies investigated:
_________________________________________________
_________________________________________________

Escalated to B-rank: [ ] Yes [ ] No
If Yes: ticket # ___________
```
