# 04-triage-alerts.md — L5 Session Layer Daily Alert Triage

| Field | Value |
|---|---|
| **NIST Controls** | AU-6 (Audit Review), IR-5 (Incident Monitoring), AC-12 (Session Termination) |
| **Tools** | az CLI (Entra ID sign-in logs), Keycloak admin events, kubectl audit logs |
| **Time** | 30 minutes daily |
| **Rank** | B (human judgment required to distinguish false positives from real threats) |

---

## Purpose

Daily review of session-related alerts across three sources: Entra ID sign-in logs, Keycloak event log, and K8s audit log (RBAC events). Each section provides the query, what to look for, and the investigation workflow for real incidents.

---

## 1. Entra ID Sign-in Logs

### Failed logins — spray and brute force detection

```bash
# Failed sign-ins in last 24 hours — group by IP to spot spray patterns
az rest \
  --method GET \
  --url "https://graph.microsoft.com/v1.0/auditLogs/signIns?\$filter=status/errorCode ne 0 and createdDateTime ge $(date -u -d '24 hours ago' '+%Y-%m-%dT%H:%M:%SZ')&\$top=1000" \
  | python3 -c "
import json, sys
from collections import Counter
data = json.load(sys.stdin)
signins = data.get('value', [])
print(f'Failed sign-ins (24h): {len(signins)}')
print()

# Group by IP
by_ip = Counter(s.get('ipAddress', 'unknown') for s in signins)
print('Top source IPs (spray pattern if single IP hits many users):')
for ip, count in by_ip.most_common(10):
    users = {s['userPrincipalName'] for s in signins if s.get('ipAddress') == ip}
    print(f'  {count:4d} attempts | {ip} | {len(users)} users targeted')

# Group by user (brute force if many failures on single user)
print()
by_user = Counter(s.get('userPrincipalName', 'unknown') for s in signins)
print('Top targeted users (brute force if single user hit many times):')
for user, count in by_user.most_common(10):
    ips = {s['ipAddress'] for s in signins if s.get('userPrincipalName') == user}
    print(f'  {count:4d} failures | {user} | {len(ips)} source IPs')
"
```

**Triage threshold:**
- Single IP hitting 10+ users → likely spray attack → check if Conditional Access blocked it
- Single user hit 20+ times → likely brute force → check if account is locked, notify user

### Impossible travel detection

```bash
# Sign-ins from multiple geographies for same user in short window
az rest \
  --method GET \
  --url "https://graph.microsoft.com/v1.0/auditLogs/signIns?\$filter=riskLevelDuringSignIn eq 'high' or riskLevelDuringSignIn eq 'medium'&\$top=50" \
  | python3 -c "
import json, sys
data = json.load(sys.stdin)
risky = data.get('value', [])
print(f'High/medium risk sign-ins: {len(risky)}')
for s in risky:
    user = s.get('userPrincipalName', 'unknown')
    ip = s.get('ipAddress', 'unknown')
    loc = s.get('location', {})
    city = loc.get('city', '?')
    country = loc.get('countryOrRegion', '?')
    risk = s.get('riskLevelDuringSignIn', 'unknown')
    reason = s.get('riskDetail', 'unknown')
    ts = s.get('createdDateTime', 'unknown')
    print(f'  [{risk.upper()}] {user} | {ip} | {city}/{country} | {reason} | {ts}')
"
```

### Conditional Access failures (blocked sign-ins)

```bash
az rest \
  --method GET \
  --url "https://graph.microsoft.com/v1.0/auditLogs/signIns?\$filter=conditionalAccessStatus eq 'failure'&\$top=50&\$orderby=createdDateTime desc" \
  | python3 -c "
import json, sys
data = json.load(sys.stdin)
failures = data.get('value', [])
print(f'Conditional Access failures: {len(failures)}')
print()
for s in failures[:20]:
    user = s.get('userPrincipalName', 'unknown')
    app = s.get('appDisplayName', 'unknown')
    ip = s.get('ipAddress', 'unknown')
    reason = s.get('status', {}).get('failureReason', 'unknown')
    ts = s.get('createdDateTime', 'unknown')
    ca_applied = [p.get('displayName','?') for p in s.get('appliedConditionalAccessPolicies', []) if p.get('result') == 'failure']
    print(f'  {ts} | {user} | {app} | {ip}')
    print(f'    Reason: {reason}')
    if ca_applied:
        print(f'    CA policy that blocked: {ca_applied}')
    print()
"
```

**Triage workflow for CA failure:**
1. If user is legitimate and failing MFA → assist with MFA setup (check device enrollment)
2. If IP is known malicious → investigate if user account is compromised
3. If CA policy blocking legitimate access → review policy scope, consider named location exclusion

---

## 2. Keycloak Event Logs

```bash
KC_URL="${KEYCLOAK_URL:-http://localhost:8080}"
KC_REALM="${KEYCLOAK_REALM:-master}"
KC_TOKEN="${KEYCLOAK_ADMIN_TOKEN:-}"

# Failed login events (LOGIN_ERROR)
echo "=== Keycloak LOGIN_ERROR Events (last 24h) ==="
curl -s "${KC_URL}/admin/realms/${KC_REALM}/events?type=LOGIN_ERROR&max=100" \
  -H "Authorization: Bearer ${KC_TOKEN}" \
  | python3 -c "
import json, sys, datetime
from collections import Counter
events = json.load(sys.stdin)
print(f'LOGIN_ERROR events: {len(events)}')
print()
by_user = Counter(e.get('userId', e.get('details', {}).get('username', 'unknown')) for e in events)
by_ip = Counter(e.get('ipAddress', 'unknown') for e in events)

print('By user:')
for user, count in by_user.most_common(10):
    print(f'  {count:3d} x {user}')
print()
print('By source IP:')
for ip, count in by_ip.most_common(10):
    print(f'  {count:3d} x {ip}')
"

# User registration events
echo ""
echo "=== Keycloak REGISTER Events (last 24h) ==="
curl -s "${KC_URL}/admin/realms/${KC_REALM}/events?type=REGISTER&max=50" \
  -H "Authorization: Bearer ${KC_TOKEN}" \
  | python3 -c "
import json, sys
events = json.load(sys.stdin)
print(f'REGISTER events: {len(events)}')
for e in events[:10]:
    user = e.get('details', {}).get('username', 'unknown')
    ip = e.get('ipAddress', 'unknown')
    ts = e.get('time', 0)
    import datetime
    dt = datetime.datetime.fromtimestamp(ts/1000).isoformat() if ts else 'unknown'
    print(f'  {dt} | {user} | {ip}')
"

# Admin events (realm config changes)
echo ""
echo "=== Keycloak Admin Events (last 24h) ==="
curl -s "${KC_URL}/admin/realms/${KC_REALM}/admin-events?max=50" \
  -H "Authorization: Bearer ${KC_TOKEN}" \
  | python3 -c "
import json, sys
events = json.load(sys.stdin)
print(f'Admin events: {len(events)}')
for e in events[:20]:
    op = e.get('operationType', 'unknown')
    resource = e.get('resourceType', 'unknown')
    path = e.get('resourcePath', 'unknown')
    admin = e.get('authDetails', {}).get('username', 'unknown')
    ts = e.get('time', 0)
    import datetime
    dt = datetime.datetime.fromtimestamp(ts/1000).isoformat() if ts else 'unknown'
    print(f'  {dt} | {op} | {resource} | {path} | by: {admin}')
"
```

**Triage rules for Keycloak:**
- `LOGIN_ERROR` from same IP hitting >5 users → spray → check if brute force protection kicked in
- Unexpected `REGISTER` events → unauthorized account creation → check registration policy
- `UPDATE_REALM` admin event from unexpected admin → config tampering → compare to baseline

---

## 3. K8s RBAC Audit Events

```bash
# Note: K8s audit logging must be enabled with --audit-log-path on kube-apiserver
# Check if audit logs exist
AUDIT_LOG="${AUDIT_LOG_PATH:-/var/log/kubernetes/audit.log}"

if [[ ! -f "$AUDIT_LOG" ]]; then
    echo "WARN: Audit log not found at ${AUDIT_LOG}"
    echo "Check: /etc/kubernetes/manifests/kube-apiserver.yaml for --audit-log-path"
    echo "Alternative: check cloud provider audit log location"
else
    # kubectl exec attempts (potential container escape)
    echo "=== kubectl exec attempts (last 24h) ==="
    grep '"verb":"create","resource":"pods/exec"' "${AUDIT_LOG}" 2>/dev/null | \
        python3 -c "
import json, sys
for line in sys.stdin:
    try:
        event = json.loads(line)
        user = event.get('user', {}).get('username', 'unknown')
        ns = event.get('objectRef', {}).get('namespace', 'unknown')
        pod = event.get('objectRef', {}).get('name', 'unknown')
        status = event.get('responseStatus', {}).get('code', '?')
        ts = event.get('requestReceivedTimestamp', 'unknown')
        print(f'  [{status}] {ts} | {user} | {ns}/{pod}')
    except:
        pass
" | head -20

    # RBAC escalation attempts (creating bindings)
    echo ""
    echo "=== ClusterRoleBinding create attempts (last 24h) ==="
    grep '"verb":"create","resource":"clusterrolebindings"' "${AUDIT_LOG}" 2>/dev/null | \
        python3 -c "
import json, sys
for line in sys.stdin:
    try:
        event = json.loads(line)
        user = event.get('user', {}).get('username', 'unknown')
        status = event.get('responseStatus', {}).get('code', '?')
        ts = event.get('requestReceivedTimestamp', 'unknown')
        print(f'  [{status}] {ts} | {user}')
    except:
        pass
" | head -20

    # Secret access events
    echo ""
    echo "=== Secret access events (last 24h) ==="
    grep '"resource":"secrets"' "${AUDIT_LOG}" 2>/dev/null | \
        python3 -c "
import json, sys
from collections import Counter
records = []
for line in sys.stdin:
    try:
        event = json.loads(line)
        user = event.get('user', {}).get('username', 'unknown')
        verb = event.get('verb', 'unknown')
        ns = event.get('objectRef', {}).get('namespace', 'unknown')
        records.append((user, verb, ns))
    except:
        pass
by_user_verb = Counter(records)
for (user, verb, ns), count in by_user_verb.most_common(20):
    print(f'  {count:3d} x {user} | {verb} secrets | ns={ns}')
" | head -20
fi
```

**Triage rules for K8s:**
- `exec` on pods by non-admin users → investigate immediately, check if SA was compromised
- `create clusterrolebindings` by service accounts → RBAC escalation attempt
- High volume `get secrets` from a single SA → secret enumeration

---

## Investigation Workflow

When an alert warrants investigation:

```
1. Identify the identity
   - Entra ID: az ad user show --id <upn>
   - Keycloak: GET /admin/realms/<realm>/users/<id>
   - K8s: kubectl get serviceaccount <sa> -n <ns>

2. Scope the blast radius
   - What resources can this identity access?
   - kubectl auth can-i --list --as system:serviceaccount:<ns>:<sa>

3. Check for active sessions
   - Entra ID: az rest --url .../users/<id>/authentication/signInActivity
   - Keycloak: GET /admin/realms/<realm>/users/<id>/sessions

4. Revoke if confirmed compromise
   - Entra ID: az rest --method POST --url .../users/<id>/revokeSignInSessions
   - Keycloak: DELETE /admin/realms/<realm>/users/<id>/sessions
   - K8s SA: kubectl delete secret <sa-token-secret> -n <ns>

5. Document in evidence/
   - Screenshot of alert
   - Commands run during investigation
   - Disposition: false positive / confirmed / escalated
```
