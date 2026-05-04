# AC-2: Account Management
**Family:** Access Control  
**NIST 800-53 Rev 5**  
**Layer:** Application (L7)

## Control Statement
The organization manages information system accounts including establishing, activating, modifying, reviewing, disabling, and removing accounts in accordance with account management procedures.

## Why It Matters at L7
At the application layer, account management failures manifest as orphaned service accounts with overprivileged API keys, ex-employee credentials that remain valid weeks after termination, and admin console access that was never revoked. Applications frequently maintain their own user stores, service account inventories, and API key registries entirely separate from enterprise IAM — making them invisible to routine access reviews unless explicitly included.

---

## GRC Analyst Perspective
> **No code access.** Tools: interviews, documentation review, SIEM dashboards, audit reports, evidence packages.

### Audit Questions
- Does the organization maintain a complete inventory of all application-level accounts, including service accounts, API keys, and admin console users?
- What is the documented process for provisioning and deprovisioning application accounts when employees join, transfer, or leave?
- How frequently are application access reviews conducted, and is there evidence (dated reports, approval signatures) of the last completed review?
- Is there a defined timeline for disabling accounts after an employee offboarding event? Who is accountable for executing it?
- Are shared or generic accounts (e.g., `admin`, `deploy-user`, `test-account`) prohibited by policy? If exceptions exist, are they documented and reviewed?
- How are application API keys and service account credentials rotated? Is there an expiration policy enforced technically, or only by policy?
- Is HR offboarding integrated with application account deprovisioning (automated workflow or manual checklist with SLA)?

### Evidence to Request
| Evidence Item | Source | Acceptable Format |
|---|---|---|
| Application account inventory with last-login timestamps | Application admin console / IAM system | CSV or PDF export, dated within 30 days |
| Access review records for last two review cycles | GRC platform, ticketing system, or email archive | Dated approval records, signed by data owner |
| Offboarding checklist or workflow records for last 3 departures | HR system or ITSM tickets | Ticket screenshots or workflow export showing account disable timestamp |
| API key and service account inventory with expiration dates | Secret manager (AWS Secrets Manager, Vault, K8s secrets) | Exported list with creation/expiration metadata |
| Account provisioning/deprovisioning SOP | Policy repository or SharePoint | PDF or link with version date |
| Privileged account list with justification | IAM / application admin console | Role-annotated export |

### Gap Documentation Template
**Control:** AC-2  
**Finding:** [Application user accounts are not included in quarterly access reviews; last review covered only Active Directory, leaving application-native accounts and API keys unreviewed for 14 months]  
**Risk:** Orphaned accounts and stale API keys create unauthorized access pathways that persist after employment termination or role change, increasing the risk of insider threat and credential-based breach]  
**Recommendation:** [Extend the access review process to include all application-layer accounts; integrate HR offboarding with automated account disable via SCIM provisioning or ITSM workflow within 24 hours of termination]  
**Owner:** Application Owner / IAM Team Lead  

### CISO Communication
> Our access review process currently covers Active Directory and enterprise SSO accounts, but application-native accounts — including API keys, service accounts, and admin console users — are outside that scope. During this assessment we identified accounts belonging to former employees that remain active in production applications, as well as API keys with no expiration date that have not been rotated in over a year. Each of these represents an open door that a malicious actor could exploit without triggering any existing alerts. Closing these gaps requires two things: expanding the quarterly access review to include application-layer accounts, and automating account deprovisioning as part of the HR offboarding workflow so that access is removed within 24 hours of a departure, not weeks later.

---

## Cybersecurity Engineer Perspective
> **Code access available.** Tools: kubectl, cloud CLI, SIEM queries, direct remediation.

### Assessment Commands
```bash
# List all service accounts in the application namespace
kubectl get serviceaccounts -n <app-namespace> -o wide

# Find service accounts with tokens that have never been used (potential orphans)
kubectl get serviceaccounts -n <app-namespace> -o json \
  | jq -r '.items[] | select(.secrets != null) | .metadata.name'

# Check which pods are using non-default service accounts
kubectl get pods -n <app-namespace> -o json \
  | jq -r '.items[] | "\(.metadata.name) | SA: \(.spec.serviceAccountName)"'

# List AWS IAM users with console access (run if app is AWS-hosted)
aws iam list-users --query 'Users[*].[UserName,PasswordLastUsed,CreateDate]' --output table

# Find IAM users with no activity in 90+ days
aws iam generate-credential-report
# GNU/Linux (works in CloudShell, most Linux distros):
CUTOFF=$(date -d "90 days ago" +%Y-%m-%d)
# macOS / BSD alternative:
# CUTOFF=$(date -v-90d +%Y-%m-%d)

aws iam get-credential-report --query 'Content' --output text | base64 -d \
  | awk -F',' -v cutoff="$CUTOFF" 'NR>1 && $5!="N/A" && $5 < cutoff {print $1, $5}'

# List Kubernetes secrets that contain credentials (potential API keys)
kubectl get secrets -n <app-namespace> -o json \
  | jq -r '.items[] | select(.type != "kubernetes.io/service-account-token") | "\(.metadata.name) | \(.type) | created: \(.metadata.creationTimestamp)"'
```

### Detection / Testing
```bash
# KQL — Sentinel: Detect logins from accounts with no recent activity (potential orphan account use)
// Run in Azure Sentinel Log Analytics
SigninLogs
| where TimeGenerated > ago(1d)
| join kind=leftouter (
    SigninLogs
    | where TimeGenerated between(ago(90d) .. ago(1d))
    | summarize LastLogin=max(TimeGenerated) by UserPrincipalName
) on UserPrincipalName
| where isempty(LastLogin)
| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress, ResultType

# SPL — Splunk: Find API key usage from accounts flagged as terminated
index=app_access sourcetype=api_gateway
| lookup terminated_users username AS api_user OUTPUT termination_date
| where isnotnull(termination_date) AND _time > strptime(termination_date, "%Y-%m-%d")
| stats count BY api_user, termination_date, api_endpoint
| sort -count

# Check for service accounts with cluster-admin binding (over-privileged)
kubectl get clusterrolebindings -o json \
  | jq -r '.items[] | select(.roleRef.name=="cluster-admin") | .subjects[]? | select(.kind=="ServiceAccount") | "\(.namespace)/\(.name)"'

# Find pods using the default service account (should be non-default for apps)
kubectl get pods -n <app-namespace> -o json \
  | jq -r '.items[] | select(.spec.serviceAccountName=="default") | .metadata.name'
```

### Remediation
```bash
# Disable automount of service account tokens on the default service account
kubectl patch serviceaccount default -n <app-namespace> \
  -p '{"automountServiceAccountToken": false}'

# Create a dedicated, minimal service account for the application
kubectl create serviceaccount <app-name>-sa -n <app-namespace>

# Apply the patched deployment to use the new service account
kubectl set serviceaccount deployment/<app-name> <app-name>-sa -n <app-namespace>

# Annotate service account with owner and last-review date (governance metadata)
kubectl annotate serviceaccount <app-name>-sa -n <app-namespace> \
  owner="platform-team@company.com" \
  last-review="2026-04-17" \
  review-schedule="quarterly"

# Rotate an AWS IAM access key for a service account
# Step 1: Create new key
aws iam create-access-key --user-name <service-account-user>
# Step 2: Update secret in Kubernetes
kubectl create secret generic <app-name>-aws-creds -n <app-namespace> \
  --from-literal=AWS_ACCESS_KEY_ID=<new-key-id> \
  --from-literal=AWS_SECRET_ACCESS_KEY=<new-secret> \
  --dry-run=client -o yaml | kubectl apply -f -
# Step 3: Delete old key after confirming rotation
aws iam delete-access-key --user-name <service-account-user> --access-key-id <old-key-id>
```

### Validation
```bash
# Confirm default SA has automount disabled
kubectl get serviceaccount default -n <app-namespace> -o jsonpath='{.automountServiceAccountToken}'
# Expected: false

# Confirm app pods are using the correct dedicated service account
kubectl get pods -n <app-namespace> -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.serviceAccountName}{"\n"}{end}'
# Expected: all pods show <app-name>-sa, not "default"

# Confirm no remaining cluster-admin service account bindings for the namespace
kubectl get clusterrolebindings -o json \
  | jq -r '.items[] | select(.roleRef.name=="cluster-admin") | .subjects[]? | select(.kind=="ServiceAccount" and .namespace=="<app-namespace>") | .name'
# Expected: empty output

# Confirm old AWS access key is deleted
aws iam list-access-keys --user-name <service-account-user>
# Expected: only one key entry with a recent CreateDate
```

### Evidence Capture
```bash
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
EVIDENCE_DIR="/tmp/ac2-evidence-${TIMESTAMP}"
mkdir -p "${EVIDENCE_DIR}"

# Service account inventory
kubectl get serviceaccounts -n <app-namespace> -o json \
  > "${EVIDENCE_DIR}/serviceaccounts-inventory.json"

# Pod-to-SA mapping
kubectl get pods -n <app-namespace> -o json \
  | jq '[.items[] | {pod: .metadata.name, serviceAccount: .spec.serviceAccountName}]' \
  > "${EVIDENCE_DIR}/pod-sa-mapping.json"

# Cluster role bindings snapshot
kubectl get clusterrolebindings -o json \
  > "${EVIDENCE_DIR}/clusterrolebindings-snapshot.json"

# Secret inventory (metadata only, no secret values)
kubectl get secrets -n <app-namespace> -o json \
  | jq '[.items[] | {name: .metadata.name, type: .type, created: .metadata.creationTimestamp, annotations: .metadata.annotations}]' \
  > "${EVIDENCE_DIR}/secrets-metadata.json"

echo "Evidence written to ${EVIDENCE_DIR}"
ls -lh "${EVIDENCE_DIR}"
```
