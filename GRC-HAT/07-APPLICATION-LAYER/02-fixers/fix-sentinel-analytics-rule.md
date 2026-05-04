# fix-sentinel-analytics-rule.md — Create Custom Sentinel Analytics Rules

**NIST:** AU-6 (audit review), SI-4 (information system monitoring)
**Skill level:** CySA+ core skill — every analyst must know this cold
**Time:** 15–30 minutes per rule

---

## What This Fixes

Missing detection coverage in Microsoft Sentinel. If `audit-alert-rules.sh` reports gaps in brute force, privilege escalation, or impossible travel detection — this playbook fills them.

---

## Portal Path (Step-by-Step)

1. Azure Portal → **Microsoft Sentinel** → select your workspace
2. Left menu: **Configuration** → **Analytics**
3. Click **+ Create** → **Scheduled query rule**
4. Fill in:
   - **Name**: descriptive (e.g., "Brute Force — Multiple Failed Logins from Single IP")
   - **Description**: what it detects and why
   - **Tactics**: select MITRE ATT&CK (e.g., Credential Access)
   - **Techniques**: (e.g., T1110 — Brute Force)
   - **Severity**: High / Medium / Low / Informational
5. Tab: **Set rule logic**
   - Paste KQL query
   - Set **Query scheduling**: every 5 minutes, look back 5 minutes
   - Set **Alert threshold**: greater than 0 results
6. Tab: **Incident settings**
   - Enable incident creation: ON
   - Alert grouping: group alerts into incidents (by IP or Account)
7. Tab: **Automated response**
   - Attach Logic App playbook for auto-response (optional at first)
8. **Review + create** → confirm

---

## KQL Example 1: Brute Force Detection

**Detects:** 5+ failed logins from a single IP within 5 minutes
**MITRE:** T1110 — Brute Force
**Severity:** High

```kql
// Brute force detection — multiple failed sign-ins from single source IP
// Data source: Azure AD SigninLogs (requires AAD connector in Sentinel)
// AU-6: Audit review | SI-4: Monitoring | T1110 Brute Force
SigninLogs
| where TimeGenerated > ago(5m)
| where ResultType != "0"                              // 0 = success, anything else = failure
| where ResultType !in ("50140", "50173")              // exclude MFA prompts and password expiry
| summarize
    FailedAttempts    = count(),
    TargetAccounts    = make_set(UserPrincipalName),
    ErrorCodes        = make_set(ResultType),
    FirstSeen         = min(TimeGenerated),
    LastSeen          = max(TimeGenerated)
    by IPAddress,
       Location       = tostring(LocationDetails.city),
       Country        = tostring(LocationDetails.countryOrRegion)
| where FailedAttempts >= 5
| extend
    AccountCount      = array_length(TargetAccounts),
    Duration          = LastSeen - FirstSeen
| project-reorder FailedAttempts, AccountCount, IPAddress, Location, Country, TargetAccounts, ErrorCodes, FirstSeen, LastSeen
| sort by FailedAttempts desc
```

**Rule configuration:**
| Field | Value |
|---|---|
| Query frequency | Every 5 minutes |
| Query period (lookback) | 5 minutes |
| Trigger | Results > 0 |
| Severity | High |
| Tactics | CredentialAccess |
| Techniques | T1110 |
| Alert grouping | By IPAddress |

---

## KQL Example 2: Impossible Travel

**Detects:** Same user authenticating from two geographically impossible locations within 60 minutes
**MITRE:** T1078 — Valid Accounts
**Severity:** High

```kql
// Impossible travel detection — same user, different countries within 60 minutes
// Filters out known VPN/proxy ranges — tune CountryFilter as needed
// AU-6: Audit review | T1078 Valid Accounts
let MinTimeDelta = 1h;                         // minimum time between sign-ins to consider
let ExcludedCountries = dynamic(["US"]);       // tune: countries you expect users to be in
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType == "0"                      // successful logins only
| where isnotempty(LocationDetails.countryOrRegion)
| extend Country = tostring(LocationDetails.countryOrRegion)
| summarize
    Countries      = make_set(Country),
    SigninTimes    = make_list(TimeGenerated),
    AppDisplayName = make_set(AppDisplayName)
    by UserPrincipalName
| where array_length(Countries) > 1
| mv-expand Country = Countries to typeof(string)
| where Country !in (ExcludedCountries)
| summarize UniqueCountries = dcount(Country), Countries = make_set(Country) by UserPrincipalName
| where UniqueCountries >= 2
| extend AlertDetail = strcat("User ", UserPrincipalName, " authenticated from: ", tostring(Countries))
| project UserPrincipalName, UniqueCountries, Countries, AlertDetail
```

---

## KQL Example 3: Privilege Escalation — Global Admin Assignment

**Detects:** A user assigned the Global Administrator role
**MITRE:** T1548 — Abuse Elevation Control Mechanism
**Severity:** High

```kql
// Privilege escalation — Global Admin role assignment
// Any Global Admin assignment should trigger review — no exceptions
// AC-6: Least Privilege | AU-6: Audit review | T1548 Privilege Escalation
AuditLogs
| where TimeGenerated > ago(1h)
| where OperationName == "Add member to role"
| where Result == "success"
| extend
    TargetUser    = tostring(TargetResources[0].userPrincipalName),
    RoleName      = tostring(TargetResources[1].displayName),
    InitiatedBy   = tostring(InitiatedBy.user.userPrincipalName)
| where RoleName in (
    "Global Administrator",
    "Privileged Role Administrator",
    "Security Administrator",
    "Privileged Authentication Administrator"
  )
| project
    TimeGenerated,
    RoleName,
    TargetUser,
    InitiatedBy,
    CorrelationId
| sort by TimeGenerated desc
```

**Rule configuration:**
| Field | Value |
|---|---|
| Query frequency | Every 5 minutes |
| Query period | 5 minutes |
| Trigger | Results > 0 |
| Severity | High |
| Tactics | PrivilegeEscalation |
| Techniques | T1548 |
| Alert grouping | By TargetUser |

---

## ARM Template Deployment

Use when you need to deploy rules as code (GitOps, IaC):

```bash
# Deploy via ARM template
az deployment group create \
  --resource-group "$SENTINEL_RG" \
  --template-file ../03-templates/sentinel/analytics-rule-brute-force.json \
  --parameters \
    workspaceName="$SENTINEL_WORKSPACE"

# Deploy privilege escalation rule
az deployment group create \
  --resource-group "$SENTINEL_RG" \
  --template-file ../03-templates/sentinel/analytics-rule-priv-escalation.json \
  --parameters \
    workspaceName="$SENTINEL_WORKSPACE"
```

---

## az CLI Deployment (Direct API)

```bash
# Deploy rule directly via REST API (bypasses ARM, useful in automation)
RULE_BODY=$(cat ../03-templates/sentinel/analytics-rule-brute-force.json | jq '.resources[0].properties')

az rest \
  --method PUT \
  --url "https://management.azure.com/subscriptions/${AZURE_SUBSCRIPTION_ID}/resourceGroups/${SENTINEL_RG}/providers/Microsoft.OperationalInsights/workspaces/${SENTINEL_WORKSPACE}/providers/Microsoft.SecurityInsights/alertRules/brute-force-rule-01?api-version=2022-11-01" \
  --body "$RULE_BODY"
```

---

## Verify Deployment

```bash
# List all analytics rules — confirm your new rule appears
az rest \
  --method GET \
  --url "https://management.azure.com/subscriptions/${AZURE_SUBSCRIPTION_ID}/resourceGroups/${SENTINEL_RG}/providers/Microsoft.OperationalInsights/workspaces/${SENTINEL_WORKSPACE}/providers/Microsoft.SecurityInsights/alertRules?api-version=2022-11-01" \
  --query "value[].{Name:properties.displayName, Enabled:properties.enabled, Severity:properties.severity}" \
  --output table
```

---

## Validation

After deploying rules:
1. Simulate a brute force — run 10 failed logins against a test account, wait 5 minutes, check Incidents tab
2. Check Analytics > Active rules — confirm rule shows last run time and is "Enabled"
3. Run `../01-auditors/audit-alert-rules.sh --sentinel-only` — verify finding count decreases
