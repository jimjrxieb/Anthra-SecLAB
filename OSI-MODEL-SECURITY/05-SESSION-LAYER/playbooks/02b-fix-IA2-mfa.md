# 02b-fix-IA2-mfa.md — MFA Enforcement (IA-2)

| Field | Value |
|---|---|
| **NIST Controls** | IA-2 (Identification and Authentication), IA-8 (Non-organizational Users), AC-7 (Unsuccessful Login Attempts) |
| **Tools** | fix-mfa-enforcement.md, az CLI, Keycloak admin API |
| **Enterprise Equiv** | Duo Security ($80K+/yr), Microsoft Entra ID P1 ($6/user/mo) |
| **Time** | 1 hour |
| **Rank** | D (configuration, no decisions required for standard enforcement) |

---

## Purpose

Enforce MFA on both Entra ID (Conditional Access) and Keycloak (required actions, TOTP policy). Run `audit-mfa-status.sh` first. This playbook remediates the findings.

---

## Prerequisite Check

```bash
# Run MFA audit first
./01-auditors/audit-mfa-status.sh

# Check percentage — if <90% coverage, proceed
# If >95% coverage, verify CA policy is enforcing (not just reporting)
```

---

## Entra ID: Block Legacy Auth First

MFA enforcement is bypassed by legacy authentication. Block legacy auth before enabling MFA enforcement — or you have a hole.

```bash
# Check if legacy auth is already blocked
az rest \
  --method GET \
  --url "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" \
  | python3 -c "
import json, sys
data = json.load(sys.stdin)
for p in data.get('value', []):
    ccts = p.get('conditions', {}).get('clientAppTypes', [])
    if ('exchangeActiveSync' in ccts or 'other' in ccts) and \
       'block' in (p.get('grantControls', {}) or {}).get('builtInControls', []):
        print(f'FOUND: {p[\"displayName\"]} (state: {p[\"state\"]})')
        break
else:
    print('MISSING: No legacy auth block policy found')
"

# If MISSING, create it first:
az rest \
  --method POST \
  --url "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" \
  --headers "Content-Type=application/json" \
  --body '{
    "displayName": "BLOCK: Legacy Authentication",
    "state": "enabled",
    "conditions": {
      "users": {"includeUsers": ["All"]},
      "applications": {"includeApplications": ["All"]},
      "clientAppTypes": ["exchangeActiveSync", "other"]
    },
    "grantControls": {"operator": "OR", "builtInControls": ["block"]}
  }'
```

---

## Entra ID: Enforce MFA

Full guide with all steps: `02-fixers/fix-mfa-enforcement.md`

Quick reference:

```bash
# 1. Create MFA CA policy (start report-only)
az rest \
  --method POST \
  --url "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" \
  --headers "Content-Type=application/json" \
  --body '{
    "displayName": "REQUIRE: MFA for All Users",
    "state": "enabledForReportingButNotEnforced",
    "conditions": {
      "users": {"includeUsers": ["All"]},
      "applications": {"includeApplications": ["All"]},
      "clientAppTypes": ["browser", "mobileAppsAndDesktopClients"]
    },
    "grantControls": {"operator": "OR", "builtInControls": ["mfa"]}
  }'

# 2. Monitor sign-in logs for 1-2 weeks

# 3. Enable enforcement
POLICY_ID="<policy-id-from-step-1>"
az rest \
  --method PATCH \
  --url "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/${POLICY_ID}" \
  --headers "Content-Type=application/json" \
  --body '{"state": "enabled"}'
```

Use `03-templates/entra-id/mfa-enforcement-policy.json` as the full policy template.

---

## Keycloak: Enforce TOTP

```bash
KC_URL="${KEYCLOAK_URL:-http://localhost:8080}"
KC_REALM="${KEYCLOAK_REALM:-master}"
KC_TOKEN="${KEYCLOAK_ADMIN_TOKEN}"

# 1. Enable CONFIGURE_TOTP as default required action
curl -s -o /dev/null -w "HTTP %{http_code}\n" \
  -X PUT \
  "${KC_URL}/admin/realms/${KC_REALM}/authentication/required-actions/CONFIGURE_TOTP" \
  -H "Authorization: Bearer ${KC_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "alias": "CONFIGURE_TOTP",
    "name": "Configure OTP",
    "providerId": "CONFIGURE_TOTP",
    "enabled": true,
    "defaultAction": true,
    "priority": 10,
    "config": {}
  }'
# Expected: HTTP 204

# 2. Configure OTP policy (6-digit TOTP, 30s, SHA1)
curl -s -o /dev/null -w "HTTP %{http_code}\n" \
  -X PUT "${KC_URL}/admin/realms/${KC_REALM}" \
  -H "Authorization: Bearer ${KC_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "otpPolicyType": "totp",
    "otpPolicyAlgorithm": "HmacSHA1",
    "otpPolicyDigits": 6,
    "otpPolicyPeriod": 30,
    "otpPolicyLookAheadWindow": 1
  }'
# Expected: HTTP 204

# 3. Verify
curl -s "${KC_URL}/admin/realms/${KC_REALM}" \
  -H "Authorization: Bearer ${KC_TOKEN}" \
  | python3 -c "
import json, sys
d = json.load(sys.stdin)
print('CONFIGURE_TOTP default action:', any(
    a.get('alias') == 'CONFIGURE_TOTP' and a.get('defaultAction')
    for a in d.get('requiredActions', [])))
print('OTP type:', d.get('otpPolicyType'))
print('OTP digits:', d.get('otpPolicyDigits'))
print('OTP period:', d.get('otpPolicyPeriod'))
"
```

---

## Push TOTP to Existing Users Without MFA

```bash
# Find users without TOTP and push required action
KC_USERS=$(curl -s "${KC_URL}/admin/realms/${KC_REALM}/users?max=500" \
  -H "Authorization: Bearer ${KC_TOKEN}")

echo "$KC_USERS" | python3 - <<'PYEOF'
import json, sys, subprocess, os

users = json.loads(sys.stdin.read())
kc_url = os.environ.get('KEYCLOAK_URL', 'http://localhost:8080')
kc_realm = os.environ.get('KEYCLOAK_REALM', 'master')
kc_token = os.environ.get('KEYCLOAK_ADMIN_TOKEN', '')

updated = 0
for user in users:
    user_id = user['id']
    username = user.get('username', user_id)
    
    creds_resp = subprocess.run(
        ['curl', '-s', f'{kc_url}/admin/realms/{kc_realm}/users/{user_id}/credentials',
         '-H', f'Authorization: Bearer {kc_token}'],
        capture_output=True, text=True
    )
    
    try:
        creds = json.loads(creds_resp.stdout)
        has_otp = any(c.get('type') == 'otp' for c in creds)
    except:
        continue
    
    if not has_otp:
        required_actions = user.get('requiredActions', [])
        if 'CONFIGURE_TOTP' not in required_actions:
            required_actions.append('CONFIGURE_TOTP')
            result = subprocess.run(
                ['curl', '-s', '-o', '/dev/null', '-w', '%{http_code}',
                 '-X', 'PUT', f'{kc_url}/admin/realms/{kc_realm}/users/{user_id}',
                 '-H', f'Authorization: Bearer {kc_token}',
                 '-H', 'Content-Type: application/json',
                 '-d', json.dumps({'requiredActions': required_actions})],
                capture_output=True, text=True
            )
            status = result.stdout.strip()
            print(f'[HTTP {status}] Pushed CONFIGURE_TOTP to: {username}')
            updated += 1

print(f'\nTotal users updated: {updated}')
PYEOF
```

---

## Evidence

```bash
EVIDENCE_DIR="/tmp/jsa-evidence/mfa-fix-$(date +%Y%m%d)"
mkdir -p "${EVIDENCE_DIR}"

# Entra ID: CA policy export
az rest \
  --url "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" \
  > "${EVIDENCE_DIR}/entra-ca-policies-after.json"

# Keycloak: realm config
curl -s "${KC_URL}/admin/realms/${KC_REALM}" \
  -H "Authorization: Bearer ${KC_TOKEN}" \
  > "${EVIDENCE_DIR}/keycloak-realm-after.json"

# Re-run audit to show improvement
./01-auditors/audit-mfa-status.sh 2>&1 | tee "${EVIDENCE_DIR}/mfa-audit-after.txt"

echo "Evidence: ${EVIDENCE_DIR}"
```

**Verify in 03-validate.md:** Check MFA % coverage improved, test that MFA challenge is presented on next sign-in.
