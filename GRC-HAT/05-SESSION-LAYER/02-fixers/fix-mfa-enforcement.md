# fix-mfa-enforcement.md — How to Enforce MFA (Dual-Stack)

| Field | Value |
|---|---|
| **NIST Controls** | IA-2 (identification/authentication), IA-8 (non-org users), AC-7 (unsuccessful logins) |
| **Platforms** | Entra ID (Conditional Access) + Keycloak (Required Actions, OTP Policy) |
| **Enterprise Equiv** | Duo Security ($80K+/yr), Okta MFA ($150K+/yr) |
| **Time** | 1 hour |
| **Rank** | D (scripted, low decision complexity) |

---

## Why This Matters

Microsoft's own data: **99.9% of compromised accounts did not have MFA**.
NIST 800-63B requires multi-factor authentication for any system processing sensitive data.
MFA is the single highest-ROI security control you can deploy.

A registered MFA method is not the same as enforced MFA. Users can have TOTP apps registered but never be challenged to use them. Enforcement requires Conditional Access (Entra ID) or Required Actions (Keycloak).

---

## Part 1: Entra ID

### Prerequisite: Block Legacy Authentication First

Legacy authentication protocols (IMAP, SMTP, POP3, basic auth) do not support MFA challenges.
If legacy auth is allowed, attackers bypass MFA entirely via password spray.
**Block legacy auth before enforcing MFA — or MFA enforcement is circumventable.**

```bash
# Create CA policy to block legacy authentication
az rest \
  --method POST \
  --url "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" \
  --headers "Content-Type=application/json" \
  --body '{
    "displayName": "BLOCK: Legacy Authentication",
    "state": "enabled",
    "conditions": {
      "users": {
        "includeUsers": ["All"]
      },
      "applications": {
        "includeApplications": ["All"]
      },
      "clientAppTypes": [
        "exchangeActiveSync",
        "other"
      ]
    },
    "grantControls": {
      "operator": "OR",
      "builtInControls": ["block"]
    }
  }'
```

**NIST mapping:** AC-17 (remote access), IA-2 (identification/authentication)
**MITRE ATT&CK:** T1110.003 (Password Spraying) — legacy auth enables spray with no MFA challenge

**Verify:**

```bash
# Check if legacy auth CA policy exists and is enabled
az rest \
  --method GET \
  --url "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" \
  | python3 -c "
import json, sys
data = json.load(sys.stdin)
for p in data.get('value', []):
    ccts = p.get('conditions', {}).get('clientAppTypes', [])
    if 'exchangeActiveSync' in ccts or 'other' in ccts:
        gc = p.get('grantControls', {})
        if 'block' in gc.get('builtInControls', []):
            print(f'FOUND: {p[\"displayName\"]} (state: {p[\"state\"]})')
"
```

---

### Step 1: Require MFA for All Users

```bash
# Create Conditional Access policy: require MFA for all users, all apps
az rest \
  --method POST \
  --url "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" \
  --headers "Content-Type=application/json" \
  --body '{
    "displayName": "REQUIRE: MFA for All Users",
    "state": "enabledForReportingButNotEnforced",
    "conditions": {
      "users": {
        "includeUsers": ["All"],
        "excludeGroups": ["<break-glass-group-id>"]
      },
      "applications": {
        "includeApplications": ["All"]
      },
      "clientAppTypes": ["browser", "mobileAppsAndDesktopClients"]
    },
    "grantControls": {
      "operator": "OR",
      "builtInControls": ["mfa"]
    }
  }'
```

> Start with `enabledForReportingButNotEnforced` (report-only mode). Monitor for 2 weeks.
> Change to `"state": "enabled"` when false-positive rate is acceptable.

**NIST mapping:** IA-2.1 (MFA for privileged access), IA-2.2 (MFA for non-privileged access)
**MITRE ATT&CK:** T1078 (Valid Accounts) — MFA defeats credential-based lateral movement

**Move to enforced:**

```bash
# Get the policy ID from the create response, then update state
POLICY_ID="<policy-id-from-create-response>"

az rest \
  --method PATCH \
  --url "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/${POLICY_ID}" \
  --headers "Content-Type=application/json" \
  --body '{"state": "enabled"}'
```

---

### Step 2: Evidence — Export CA Policy State

```bash
# Export all CA policies to JSON for audit evidence
az rest \
  --method GET \
  --url "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" \
  -o json > /tmp/jsa-evidence/entra-ca-policies-$(date +%Y%m%d).json

# Show only MFA-requiring policies
python3 - <<'PYEOF'
import json
with open(f"/tmp/jsa-evidence/entra-ca-policies-$(date +%Y%m%d).json") as f:
    data = json.load(f)
for p in data.get('value', []):
    gc = p.get('grantControls', {})
    if 'mfa' in gc.get('builtInControls', []):
        print(f"Policy: {p['displayName']}")
        print(f"  State: {p['state']}")
        print(f"  Users: {p['conditions']['users'].get('includeUsers', [])}")
        print()
PYEOF
```

---

## Part 2: Keycloak

### Step 1: Enable TOTP as Required Action

TOTP as a "default required action" means every new user registration triggers the TOTP setup flow.
For existing users without TOTP, you push the required action manually or via bulk API.

```bash
KC_URL="${KEYCLOAK_URL:-http://localhost:8080}"
KC_REALM="${KEYCLOAK_REALM:-master}"
KC_TOKEN="${KEYCLOAK_ADMIN_TOKEN}"

# Enable CONFIGURE_TOTP as default required action
curl -s -X PUT \
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

echo "Exit code: $?"
```

**Verify:**

```bash
curl -s "${KC_URL}/admin/realms/${KC_REALM}/authentication/required-actions/CONFIGURE_TOTP" \
  -H "Authorization: Bearer ${KC_TOKEN}" \
  | python3 -c "import json,sys; d=json.load(sys.stdin); print('defaultAction:', d.get('defaultAction'), '| enabled:', d.get('enabled'))"
```

---

### Step 2: Configure OTP Policy

```bash
# Set OTP policy: 6-digit TOTP, 30-second period, SHA1
# (SHA1 is standard for TOTP per RFC 6238 — SHA256/512 not widely supported by authenticator apps)
curl -s -X PUT \
  "${KC_URL}/admin/realms/${KC_REALM}" \
  -H "Authorization: Bearer ${KC_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "otpPolicyType": "totp",
    "otpPolicyAlgorithm": "HmacSHA1",
    "otpPolicyDigits": 6,
    "otpPolicyPeriod": 30,
    "otpPolicyLookAheadWindow": 1
  }'

echo "HTTP status (expect 204): $(curl -s -o /dev/null -w '%{http_code}' \
  -X PUT "${KC_URL}/admin/realms/${KC_REALM}" \
  -H "Authorization: Bearer ${KC_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{}')"
```

---

### Step 3: Push Required Action to Existing Users Without TOTP

```bash
KC_URL="${KEYCLOAK_URL:-http://localhost:8080}"
KC_REALM="${KEYCLOAK_REALM:-master}"
KC_TOKEN="${KEYCLOAK_ADMIN_TOKEN}"

# Get users without OTP credentials
USERS=$(curl -s "${KC_URL}/admin/realms/${KC_REALM}/users?max=500" \
  -H "Authorization: Bearer ${KC_TOKEN}")

echo "$USERS" | python3 -c "
import json, sys, subprocess, os

users = json.load(sys.stdin)
kc_url = os.environ.get('KEYCLOAK_URL', 'http://localhost:8080')
kc_realm = os.environ.get('KEYCLOAK_REALM', 'master')
kc_token = os.environ.get('KEYCLOAK_ADMIN_TOKEN', '')

for user in users:
    user_id = user['id']
    username = user.get('username', user_id)
    
    # Check credentials
    creds = subprocess.run(
        ['curl', '-s', f'{kc_url}/admin/realms/{kc_realm}/users/{user_id}/credentials',
         '-H', f'Authorization: Bearer {kc_token}'],
        capture_output=True, text=True
    ).stdout
    
    try:
        cred_list = json.loads(creds)
        has_otp = any(c.get('type') == 'otp' for c in cred_list)
    except:
        has_otp = True  # skip on parse error
    
    if not has_otp:
        print(f'Pushing CONFIGURE_TOTP to: {username} ({user_id})')
        # Push required action to user
        required_actions = user.get('requiredActions', [])
        if 'CONFIGURE_TOTP' not in required_actions:
            required_actions.append('CONFIGURE_TOTP')
            subprocess.run(
                ['curl', '-s', '-X', 'PUT',
                 f'{kc_url}/admin/realms/{kc_realm}/users/{user_id}',
                 '-H', f'Authorization: Bearer {kc_token}',
                 '-H', 'Content-Type: application/json',
                 '-d', json.dumps({'requiredActions': required_actions})],
                capture_output=True
            )
"
```

---

### Evidence: Keycloak Realm Export

```bash
# Export realm configuration (includes required actions and OTP policy)
curl -s \
  "${KC_URL}/admin/realms/${KC_REALM}" \
  -H "Authorization: Bearer ${KC_TOKEN}" \
  | python3 -c "
import json, sys
realm = json.load(sys.stdin)
evidence = {
  'realm': realm.get('realm'),
  'otpPolicyType': realm.get('otpPolicyType'),
  'otpPolicyAlgorithm': realm.get('otpPolicyAlgorithm'),
  'otpPolicyDigits': realm.get('otpPolicyDigits'),
  'otpPolicyPeriod': realm.get('otpPolicyPeriod'),
  'requiredActions': realm.get('requiredActions', []),
  'bruteForceProtected': realm.get('bruteForceProtected'),
  'failureFactor': realm.get('failureFactor'),
  'exported_at': '$(date -u +%Y-%m-%dT%H:%M:%SZ)'
}
print(json.dumps(evidence, indent=2))
" > "/tmp/jsa-evidence/keycloak-mfa-evidence-$(date +%Y%m%d).json"

echo "Evidence saved: /tmp/jsa-evidence/keycloak-mfa-evidence-$(date +%Y%m%d).json"
```

---

## Evidence Summary

After completing both stacks, your audit package should contain:

| File | Contents |
|---|---|
| `entra-ca-policies-<date>.json` | All CA policies in tenant |
| `entra-mfa-registration.json` | Per-user MFA registration status |
| `keycloak-mfa-evidence-<date>.json` | Realm OTP policy + required actions |
| `keycloak-users-without-totp.txt` | Users who received CONFIGURE_TOTP action |

Archive to `evidence/` for compliance record-keeping.
