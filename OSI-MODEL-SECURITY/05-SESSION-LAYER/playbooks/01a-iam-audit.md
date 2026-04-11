# 01a-iam-audit.md — Entra ID IAM Deep-Dive Audit

| Field | Value |
|---|---|
| **NIST Controls** | AC-2 (account management), IA-2 (authentication), AC-6 (least privilege) |
| **Tools** | az CLI, Microsoft Graph API, Entra ID portal |
| **Enterprise Equiv** | Microsoft Defender for Identity ($15/user/mo), CyberArk Identity ($200K+/yr) |
| **Time** | 1.5 hours |
| **Rank** | D (query-based, no decisions in audit phase) |

---

## Purpose

Entra ID focused deep-dive: user inventory, MFA registration status, Conditional Access policy review, sign-in log analysis, and privileged role assignments. Run `audit-mfa-status.sh --entra-only` and `audit-session-policy.sh --entra-only` first for automated checks. This playbook covers the investigation layer those scripts cannot automate.

---

## 1. User Inventory

```bash
# Full user inventory with license, MFA, account status
az ad user list \
  --query "[].{upn:userPrincipalName, display:displayName, enabled:accountEnabled, id:id}" \
  -o table

# Count by account status
az ad user list \
  --query "[?accountEnabled==\`true\`] | length(@)" -o tsv
az ad user list \
  --query "[?accountEnabled==\`false\`] | length(@)" -o tsv

# Users not logged in for 90+ days (stale accounts — AC-2 account management)
az rest \
  --method GET \
  --url "https://graph.microsoft.com/v1.0/users?\$select=userPrincipalName,signInActivity,accountEnabled" \
  | python3 -c "
import json, sys
from datetime import datetime, timezone, timedelta
data = json.load(sys.stdin)
cutoff = datetime.now(timezone.utc) - timedelta(days=90)
stale = []
for u in data.get('value', []):
    sia = u.get('signInActivity', {})
    last = sia.get('lastSignInDateTime') if sia else None
    if not last:
        stale.append((u['userPrincipalName'], 'never signed in'))
    else:
        last_dt = datetime.fromisoformat(last.rstrip('Z')).replace(tzinfo=timezone.utc)
        if last_dt < cutoff:
            stale.append((u['userPrincipalName'], last))
for upn, last in stale:
    print(f'STALE: {upn} | last: {last}')
print(f'Total stale: {len(stale)}')
"
```

**NIST AC-2 finding:** Stale accounts must be disabled or removed. Unused accounts are open doors for credential stuffing.

---

## 2. MFA Registration Status

```bash
# Per-user authentication methods (requires UserAuthenticationMethod.Read.All)
# For a specific user:
USER_UPN="user@yourdomain.com"
az rest \
  --method GET \
  --url "https://graph.microsoft.com/v1.0/users/${USER_UPN}/authentication/methods" \
  | python3 -c "
import json, sys
data = json.load(sys.stdin)
methods = [m.get('@odata.type','').split('.')[-1] for m in data.get('value',[])]
print('Methods registered:', methods)
has_mfa = any(m for m in methods if 'password' not in m.lower())
print('MFA registered:', has_mfa)
"

# Bulk report (requires Reports.Read.All — Azure AD Premium P1+)
az rest \
  --method GET \
  --url "https://graph.microsoft.com/v1.0/reports/credentialUserRegistrationDetails" \
  | python3 -c "
import json, sys
data = json.load(sys.stdin)
users = data.get('value', [])
total = len(users)
mfa_registered = sum(1 for u in users if u.get('isMfaRegistered'))
mfa_capable = sum(1 for u in users if u.get('isMfaCapable'))
no_mfa = [u['userPrincipalName'] for u in users if not u.get('isMfaRegistered')]
print(f'Total: {total}')
print(f'MFA registered: {mfa_registered} ({mfa_registered/total*100:.1f}%)')
print(f'MFA capable: {mfa_capable}')
print(f'No MFA registered: {len(no_mfa)}')
print()
for u in no_mfa[:20]:
    print(f'  NO-MFA: {u}')
" 2>/dev/null || echo "Report requires Azure AD Premium P1 — check portal instead"
```

---

## 3. Conditional Access Policy Review

```bash
# Full CA policy dump
CA_POLICIES=$(az rest \
  --method GET \
  --url "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies")

# Summary: policy names, states, grant controls
echo "$CA_POLICIES" | python3 -c "
import json, sys
data = json.load(sys.stdin)
print(f'Total CA policies: {len(data.get(\"value\", []))}')
print()
for p in data.get('value', []):
    state = p.get('state', 'unknown')
    name = p.get('displayName', 'unnamed')
    gc = p.get('grantControls', {})
    controls = gc.get('builtInControls', []) if gc else []
    sc = p.get('sessionControls', {}) or {}
    sif = sc.get('signInFrequency', {}) or {}
    state_icon = '✓' if state == 'enabled' else '?' if 'Report' in state else 'X'
    print(f'[{state_icon}] {name}')
    print(f'    State: {state}')
    print(f'    Grant: {controls}')
    if sif.get('isEnabled'):
        print(f'    SignInFreq: {sif.get(\"value\")} {sif.get(\"type\")}')
    print()
"

# Check for critical missing policies
echo "$CA_POLICIES" | python3 -c "
import json, sys
data = json.load(sys.stdin)
policies = data.get('value', [])

checks = {
    'MFA enforcement': lambda p: 'mfa' in (p.get('grantControls') or {}).get('builtInControls', []),
    'Legacy auth block': lambda p: (
        'exchangeActiveSync' in (p.get('conditions') or {}).get('clientAppTypes', []) and
        'block' in (p.get('grantControls') or {}).get('builtInControls', [])
    ),
    'Sign-in frequency': lambda p: (p.get('sessionControls') or {}).get('signInFrequency', {}).get('isEnabled'),
}

for check_name, check_fn in checks.items():
    found = any(check_fn(p) for p in policies if p.get('state') == 'enabled')
    status = 'PRESENT' if found else 'MISSING'
    print(f'{status}: {check_name}')
"
```

---

## 4. Sign-in Log Analysis

```bash
# Failed sign-ins in the last 24 hours (requires AuditLog.Read.All)
az rest \
  --method GET \
  --url "https://graph.microsoft.com/v1.0/auditLogs/signIns?\$filter=status/errorCode ne 0&\$top=100&\$orderby=createdDateTime desc" \
  | python3 -c "
import json, sys
from collections import Counter
data = json.load(sys.stdin)
signins = data.get('value', [])
print(f'Recent failed sign-ins: {len(signins)}')
print()
# Group by failure reason
reasons = Counter(s.get('status', {}).get('failureReason', 'unknown') for s in signins)
print('Top failure reasons:')
for reason, count in reasons.most_common(10):
    print(f'  {count:3d} x {reason}')
print()
# Show risky ones
for s in signins[:10]:
    user = s.get('userPrincipalName', 'unknown')
    ip = s.get('ipAddress', 'unknown')
    app = s.get('appDisplayName', 'unknown')
    reason = s.get('status', {}).get('failureReason', 'unknown')
    risk = s.get('riskLevelDuringSignIn', 'none')
    ts = s.get('createdDateTime', 'unknown')
    print(f'{ts} | {user} | {ip} | {app} | {reason} | risk:{risk}')
"

# Risky sign-ins (requires Identity Protection — Azure AD Premium P2)
az rest \
  --method GET \
  --url "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers" \
  | python3 -c "
import json, sys
data = json.load(sys.stdin)
risky = data.get('value', [])
print(f'Risky users: {len(risky)}')
for u in risky[:10]:
    print(f'  [{u.get(\"riskLevel\",\"?\")}] {u.get(\"userPrincipalName\",\"unknown\")} — {u.get(\"riskDetail\",\"unknown\")}')
" 2>/dev/null || echo "Identity Protection requires Azure AD Premium P2"
```

---

## 5. Privileged Role Assignments

```bash
# Who has Global Admin? (maximum of 5 recommended for most orgs)
az rest \
  --method GET \
  --url "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?\$expand=principal,roleDefinition&\$filter=roleDefinition/displayName eq 'Global Administrator'" \
  | python3 -c "
import json, sys
data = json.load(sys.stdin)
assignments = data.get('value', [])
print(f'Global Administrator count: {len(assignments)}')
if len(assignments) > 5:
    print(f'WARNING: {len(assignments)} Global Admins is excessive (target: 2-5)')
for a in assignments:
    principal = a.get('principal', {})
    print(f'  {principal.get(\"userPrincipalName\", principal.get(\"displayName\", \"unknown\"))}')
"

# All privileged role assignments
az rest \
  --method GET \
  --url "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?\$expand=principal,roleDefinition" \
  | python3 -c "
import json, sys
from collections import Counter
data = json.load(sys.stdin)
assignments = data.get('value', [])
roles = Counter(a.get('roleDefinition', {}).get('displayName', 'unknown') for a in assignments)
print(f'Total privileged role assignments: {len(assignments)}')
print()
print('By role:')
for role, count in roles.most_common():
    print(f'  {count:3d} x {role}')
"
```

---

## Output: IAM Assessment Report

Capture results to evidence:

```bash
EVIDENCE_DIR="/tmp/jsa-evidence/iam-audit-$(date +%Y%m%d)"
mkdir -p "$EVIDENCE_DIR"

# Save each query output
az ad user list -o json > "${EVIDENCE_DIR}/user-inventory.json"
az rest --url ".../conditionalAccess/policies" > "${EVIDENCE_DIR}/ca-policies.json"
az rest --url ".../auditLogs/signIns?..." > "${EVIDENCE_DIR}/signin-logs.json"
az rest --url ".../roleAssignments..." > "${EVIDENCE_DIR}/privileged-roles.json"

echo "Evidence: ${EVIDENCE_DIR}"
```

**Gap findings → feed into:**
- MFA gaps: `02b-fix-IA2-mfa.md`
- CA policy gaps: `02-fixers/fix-conditional-access-policy.md`
- Stale accounts: remediate via `az ad user update --id <id> --account-enabled false`
