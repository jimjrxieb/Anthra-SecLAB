# 02a-fix-AC12-session.md — Session Timeout Enforcement (AC-12)

| Field | Value |
|---|---|
| **NIST Controls** | AC-12 (Session Termination), SC-23 (Session Authenticity) |
| **Tools** | fix-session-timeout.sh, az CLI, Keycloak admin API |
| **Enterprise Equiv** | Okta session policies ($150K+/yr), Azure AD Premium P1 ($6/user/mo) |
| **Time** | 30 minutes |
| **Rank** | D (scripted, configuration-only) |

---

## Purpose

Enforce session timeouts on both Entra ID (Conditional Access sign-in frequency) and Keycloak (realm SSO session settings). Run `audit-session-policy.sh` first to identify which gaps exist.

---

## Run the Fixer

```bash
# Dry-run first — review what will be applied
./02-fixers/fix-session-timeout.sh --dry-run

# Apply to both platforms
./02-fixers/fix-session-timeout.sh

# Or target a single platform:
./02-fixers/fix-session-timeout.sh --entra-only
./02-fixers/fix-session-timeout.sh --keycloak-only
```

---

## Manual Steps: Entra ID

If the script fails or you need to customize the values:

```bash
# Create sign-in frequency CA policy via Microsoft Graph
az rest \
  --method POST \
  --url "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" \
  --headers "Content-Type=application/json" \
  --body '{
    "displayName": "REQUIRE: Sign-in Every 8 Hours",
    "state": "enabled",
    "conditions": {
      "users": {"includeUsers": ["All"]},
      "applications": {"includeApplications": ["All"]},
      "clientAppTypes": ["browser", "mobileAppsAndDesktopClients"]
    },
    "sessionControls": {
      "signInFrequency": {
        "value": 8,
        "type": "hours",
        "isEnabled": true
      },
      "persistentBrowser": {
        "mode": "never",
        "isEnabled": true
      }
    }
  }'
```

**Verify:**

```bash
az rest \
  --method GET \
  --url "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" \
  | python3 -c "
import json, sys
data = json.load(sys.stdin)
for p in data.get('value', []):
    sc = p.get('sessionControls', {}) or {}
    sif = sc.get('signInFrequency', {}) or {}
    if sif.get('isEnabled'):
        print(f'FOUND: {p[\"displayName\"]} — every {sif.get(\"value\")} {sif.get(\"type\")} (state: {p[\"state\"]})')
"
```

---

## Manual Steps: Keycloak

```bash
KC_URL="${KEYCLOAK_URL:-http://localhost:8080}"
KC_REALM="${KEYCLOAK_REALM:-master}"
KC_TOKEN="${KEYCLOAK_ADMIN_TOKEN}"

# Apply session timeout settings to realm
curl -s -o /dev/null -w "HTTP %{http_code}\n" \
  -X PUT "${KC_URL}/admin/realms/${KC_REALM}" \
  -H "Authorization: Bearer ${KC_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "ssoSessionIdleTimeout": 900,
    "ssoSessionMaxLifespan": 36000,
    "accessTokenLifespan": 300,
    "rememberMe": false
  }'
# Expected: HTTP 204

# Verify
curl -s "${KC_URL}/admin/realms/${KC_REALM}" \
  -H "Authorization: Bearer ${KC_TOKEN}" \
  | python3 -c "
import json, sys
d = json.load(sys.stdin)
print('ssoSessionIdleTimeout:', d.get('ssoSessionIdleTimeout'), '(target: 900)')
print('ssoSessionMaxLifespan:', d.get('ssoSessionMaxLifespan'), '(target: 36000)')
print('accessTokenLifespan:', d.get('accessTokenLifespan'), '(target: 300)')
print('rememberMe:', d.get('rememberMe'), '(should be False)')
"
```

---

## Target Values Reference

| Setting | Target | Rationale |
|---|---|---|
| Entra ID sign-in frequency | 8 hours | Standard workday — balances security and UX |
| Entra ID persistent browser | never | Prevent browser restart from reusing sessions |
| Keycloak SSO idle | 900s (15min) | AC-12 idle termination |
| Keycloak SSO max | 36000s (10hr) | Force re-auth after workday |
| Keycloak access token | 300s (5min) | Short-lived access tokens limit theft window |
| Keycloak remember-me | disabled | Bypasses idle timeout; risk not worth UX convenience |

---

## Evidence

```bash
EVIDENCE_DIR="/tmp/jsa-evidence/ac12-fix-$(date +%Y%m%d)"
mkdir -p "${EVIDENCE_DIR}"

# Entra ID after state
az rest --url ".../identity/conditionalAccess/policies" \
  > "${EVIDENCE_DIR}/entra-after-ca-policies.json"

# Keycloak after state
curl -s "${KC_URL}/admin/realms/${KC_REALM}" \
  -H "Authorization: Bearer ${KC_TOKEN}" \
  > "${EVIDENCE_DIR}/keycloak-after-realm.json"

echo "Evidence: ${EVIDENCE_DIR}"
```

**Verify in 03-validate.md:** Test session timeout by logging in, waiting for idle period, and confirming re-authentication is required.
