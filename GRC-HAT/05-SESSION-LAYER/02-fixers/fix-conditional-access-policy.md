# fix-conditional-access-policy.md — Entra ID Conditional Access Policy Guide

| Field | Value |
|---|---|
| **NIST Controls** | AC-17 (remote access), IA-2 (authentication), IA-5 (authenticator management), AC-6 (least privilege) |
| **Platform** | Microsoft Entra ID (Azure AD) |
| **Enterprise Equiv** | Okta Adaptive MFA ($150K+/yr), CyberArk Identity ($200K+/yr) |
| **Time** | 45 minutes |
| **Rank** | D (configuration, no custom code) |

---

## What Is Conditional Access?

Conditional Access is Entra ID's policy engine. It evaluates every sign-in against a set of conditions and makes an access decision: Allow, Require MFA, Block.

Think of it as if-then rules for authentication:
- IF user is signing in from outside named locations → REQUIRE MFA
- IF authentication uses legacy protocol → BLOCK
- IF user is an admin signing into Azure Portal → REQUIRE compliant device

Without Conditional Access, MFA is optional. Users can register it and never be challenged.

---

## Example 1: Block Legacy Authentication

**Why:** Legacy authentication protocols (IMAP, SMTP, POP3, basic HTTP auth) do not support
modern MFA challenges. Password spray attacks almost exclusively target legacy auth endpoints
because a successful spray gives immediate access — no MFA prompt, no friction.

**NIST:** AC-17 (remote access controls), IA-2 (multi-factor authentication)
**MITRE ATT&CK:** T1110.003 (Password Spraying), T1078 (Valid Accounts)

### az cli

```bash
az rest \
  --method POST \
  --url "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" \
  --headers "Content-Type=application/json" \
  --body '{
    "displayName": "BLOCK: Legacy Authentication Protocols",
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

### Microsoft Graph API (direct)

```bash
ACCESS_TOKEN=$(az account get-access-token \
  --resource "https://graph.microsoft.com" \
  --query accessToken -o tsv)

curl -s -X POST \
  "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "displayName": "BLOCK: Legacy Authentication Protocols",
    "state": "enabled",
    "conditions": {
      "users": {"includeUsers": ["All"]},
      "applications": {"includeApplications": ["All"]},
      "clientAppTypes": ["exchangeActiveSync", "other"]
    },
    "grantControls": {
      "operator": "OR",
      "builtInControls": ["block"]
    }
  }'
```

### Portal Steps

1. Azure Portal → Entra ID → Security → Conditional Access → New policy
2. Name: "BLOCK: Legacy Authentication Protocols"
3. Users: Include → All users
4. Target resources: Include → All cloud apps
5. Conditions → Client apps → Select: Exchange ActiveSync, Other clients
6. Grant → Block access
7. Enable policy → On
8. Save

### Evidence

```bash
# Verify policy exists and is enabled
az rest \
  --method GET \
  --url "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" \
  | python3 -c "
import json, sys
for p in json.load(sys.stdin).get('value', []):
    ccts = p.get('conditions', {}).get('clientAppTypes', [])
    if 'exchangeActiveSync' in ccts or 'other' in ccts:
        gc = p.get('grantControls', {})
        if 'block' in gc.get('builtInControls', []):
            print(f'VERIFIED: {p[\"displayName\"]} — state: {p[\"state\"]}')
"
```

---

## Example 2: Require MFA From Untrusted Locations

**Why:** Users signing in from unfamiliar or untrusted networks are at higher risk of compromise.
Named locations define your trusted IP ranges (office, VPN). Requiring MFA from anywhere outside
those ranges stops credential theft attacks from attacker infrastructure.

**NIST:** IA-2.1 (MFA for privileged access), IA-2.2 (MFA for non-privileged)
**MITRE ATT&CK:** T1078.004 (Cloud Accounts), T1539 (Steal Web Session Cookie)

### Step 1: Create Named Location (Trusted IPs)

```bash
az rest \
  --method POST \
  --url "https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations" \
  --headers "Content-Type=application/json" \
  --body '{
    "@odata.type": "#microsoft.graph.ipNamedLocation",
    "displayName": "Corporate Network / VPN",
    "isTrusted": true,
    "ipRanges": [
      {
        "@odata.type": "#microsoft.graph.iPv4CidrRange",
        "cidrAddress": "203.0.113.0/24"
      },
      {
        "@odata.type": "#microsoft.graph.iPv4CidrRange",
        "cidrAddress": "198.51.100.0/28"
      }
    ]
  }'
```

> Replace IP ranges with your actual corporate/VPN CIDR blocks.
> Save the `id` from the response — you need it in the next step.

### Step 2: Create CA Policy (MFA Outside Named Locations)

```bash
NAMED_LOCATION_ID="<id-from-previous-step>"

az rest \
  --method POST \
  --url "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" \
  --headers "Content-Type=application/json" \
  --body "{
    \"displayName\": \"REQUIRE: MFA from Untrusted Locations\",
    \"state\": \"enabledForReportingButNotEnforced\",
    \"conditions\": {
      \"users\": {
        \"includeUsers\": [\"All\"],
        \"excludeGroups\": [\"<break-glass-group-id>\"]
      },
      \"applications\": {
        \"includeApplications\": [\"All\"]
      },
      \"locations\": {
        \"includeLocations\": [\"All\"],
        \"excludeLocations\": [\"${NAMED_LOCATION_ID}\", \"AllTrusted\"]
      }
    },
    \"grantControls\": {
      \"operator\": \"OR\",
      \"builtInControls\": [\"mfa\"]
    }
  }"
```

### Portal Steps

1. Entra ID → Security → Conditional Access → Named locations → Add IP ranges location
2. Name: "Corporate Network / VPN", mark as trusted, enter CIDR blocks
3. New policy → Include: All users, All cloud apps
4. Conditions → Locations → Include: Any location, Exclude: All trusted locations
5. Grant → Require MFA → Select
6. Start in report-only mode, move to enabled after 1-2 week monitoring period

---

## Example 3: Require Compliant Device for Admin Portal Access

**Why:** Admin portals (Azure Portal, Entra ID admin, Exchange admin) are high-value targets.
Requiring a device enrolled in Intune (Compliant) or Hybrid Azure AD Joined ensures the admin
is working from a managed, policy-compliant endpoint — not from a BYOD device or attacker VM.

**NIST:** AC-6 (least privilege — limiting access to managed devices), AC-2 (account management)
**MITRE ATT&CK:** T1550.001 (Application Access Token), T1078.004 (Cloud Accounts)

### Prerequisite: Intune Enrollment / Hybrid Join

Device compliance requires either:
- Microsoft Intune enrollment (cloud-managed, marks device as "Compliant")
- Hybrid Azure AD Join (on-prem AD + Entra ID joined)

### az cli

```bash
az rest \
  --method POST \
  --url "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" \
  --headers "Content-Type=application/json" \
  --body '{
    "displayName": "REQUIRE: Compliant Device for Admin Portals",
    "state": "enabledForReportingButNotEnforced",
    "conditions": {
      "users": {
        "includeRoles": [
          "62e90394-69f5-4237-9190-012177145e10",
          "194ae4cb-b126-40b2-bd5b-6091b380977d",
          "f28a1f50-f6e7-4571-818b-6a12f2af6b6c"
        ]
      },
      "applications": {
        "includeApplications": [
          "797f4846-ba00-4fd7-ba43-dac1f8f63013",
          "00000002-0000-0ff1-ce00-000000000000"
        ]
      }
    },
    "grantControls": {
      "operator": "OR",
      "builtInControls": [
        "compliantDevice",
        "domainJoinedDevice"
      ]
    }
  }'
```

> Role IDs above: Global Admin, Security Admin, Exchange Admin.
> App IDs: Azure Portal (797f4846...), Office 365 Exchange Online.

### Portal Steps

1. New policy → Users: Directory roles → Global Administrator, Security Administrator
2. Target resources: Select apps → Azure portal, Microsoft Admin Portals
3. Grant → Require device to be marked as compliant OR Require Hybrid Azure AD joined device
4. Start report-only, enforce after confirming all admin devices are enrolled

### NIST Annotation

```
Control: AC-6 (Least Privilege)
Rationale: Administrative access restricted to managed endpoints prevents
           unauthorized access from unmanaged or compromised devices.
           Combined with MFA, provides defense-in-depth for privileged access.
```

---

## Operational Notes

### Break-Glass Accounts

Always exclude at least one break-glass account from ALL Conditional Access policies.
If you lock yourself out of your tenant, break-glass is your recovery path.

```bash
# Create break-glass exclusion group
az ad group create \
  --display-name "CA-Exclusion-BreakGlass" \
  --mail-nickname "ca-exclusion-breakglass"

# Get group ID
BREAKGLASS_GROUP_ID=$(az ad group show \
  --group "CA-Exclusion-BreakGlass" \
  --query id -o tsv)

echo "Add this to excludeGroups in every CA policy: ${BREAKGLASS_GROUP_ID}"
```

### Report-Only Mode

Always start new CA policies in `"state": "enabledForReportingButNotEnforced"` mode.
Sign-in logs show what would have been blocked — validate before enforcing.

```bash
# Move policy from report-only to enabled
POLICY_ID="<policy-id>"
az rest \
  --method PATCH \
  --url "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/${POLICY_ID}" \
  --headers "Content-Type=application/json" \
  --body '{"state": "enabled"}'
```

### Sign-in Log Monitoring

```bash
# Check recent CA policy failures (last 24 hours)
az rest \
  --method GET \
  --url "https://graph.microsoft.com/v1.0/auditLogs/signIns?\$filter=conditionalAccessStatus eq 'failure'&\$top=50" \
  | python3 -c "
import json, sys
data = json.load(sys.stdin)
for signin in data.get('value', []):
    user = signin.get('userPrincipalName', 'unknown')
    ip = signin.get('ipAddress', 'unknown')
    app = signin.get('appDisplayName', 'unknown')
    status = signin.get('status', {}).get('failureReason', 'unknown')
    ts = signin.get('createdDateTime', 'unknown')
    print(f'{ts} | {user} | {ip} | {app} | {status}')
"
```
