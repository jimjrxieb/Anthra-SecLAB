# IR-4: Incident Handling
**Family:** Incident Response  
**NIST 800-53 Rev 5**  
**Layer:** Application (L7)

## Control Statement
The organization implements an incident handling capability for security incidents that includes preparation, detection, analysis, containment, eradication, and recovery.

## Why It Matters at L7
Application-layer incidents — web application attacks, API abuse, authentication bypass, and SQL injection — require a structured handling process that begins with accurate classification and ends with documented evidence. Without ranked triage and defined escalation paths, responders waste time on noise while real incidents go uncontained. At L7 specifically, blast radius assessment depends on understanding which application, which user session, and which data store was involved before any containment action is taken.

---

## GRC Analyst Perspective
> **No code access.** Tools: interviews, documentation review, SIEM dashboards, audit reports, evidence packages.

### Audit Questions
- Does the organization have a documented incident response plan that covers application-layer attack categories (web app attacks, auth bypass, API abuse, data exfiltration, SQL injection)?
- Are incident severity tiers defined with clear criteria for escalation from analyst to senior analyst to management? How are tiers mapped to business impact?
- What is the documented escalation path for a Severity 1 (S-rank) application incident discovered outside business hours? Is there a named on-call owner?
- Are tabletop exercises conducted at least annually? Do exercises include application-layer scenarios such as credential stuffing or supply chain compromise?
- What are the organization's target MTTD and MTTR metrics for application incidents? Are actuals tracked and reported to leadership?
- Is there a chain-of-custody procedure for digital evidence collected during an incident? Who is authorized to collect evidence and from which systems?
- Are containment actions — such as WAF IP blocks, pod isolation, or account disablement — pre-authorized in the IR plan, or does each action require ad hoc approval?
- How are false positives tracked and fed back to improve detection rules? Is there a tuning process with documented outcomes?

### Evidence to Request
| Evidence Item | Source | Acceptable Format |
|---|---|---|
| Incident Response Plan (current version, signed) | CISO / IR Team Lead | PDF with approval date and version number |
| Incident register for last 90 days | SIEM / Ticketing System (Jira, ServiceNow) | CSV or dashboard export with severity, MTTD, MTTR columns |
| Tabletop exercise records (agenda, findings, action items) | IR Team | Meeting minutes or exercise report, dated |
| Escalation matrix / on-call runbook | IR / SOC Manager | Document naming roles and contact methods by severity |
| Post-incident review (PIR) reports, last 3 incidents | IR Team | PIR template output — root cause, timeline, lessons learned |
| WAF / firewall block log showing containment actions | Security Operations | SIEM export or WAF admin log, date-stamped |

### Gap Documentation Template
**Control:** IR-4  
**Finding:** No documented escalation path exists for B/S-rank application incidents; all incidents are routed to the same analyst queue regardless of severity.  
**Risk:** Critical incidents such as active data exfiltration or authentication bypass remain unescalated, increasing dwell time and potential data loss.  
**Recommendation:** Define a tiered escalation matrix aligned to the rank system (E/D → auto-handle, C → analyst, B → senior analyst, S → IR team + management). Publish on-call contacts and pre-authorize containment actions in the IR plan.  
**Owner:** CISO / IR Team Lead  

### CISO Communication
> Our incident handling program needs a clear map from alert to action — one that tells every analyst exactly what to do at every severity level without waiting for approval. Right now, the gap is in the middle: we have people who can close easy alerts and we have an escalation path for disasters, but the high-value decisions in between — the auth bypass, the API abuse, the account the attacker is actively using — those land in a queue with no defined owner or SLA. Formalizing a five-tier rank system, pre-authorizing the containment actions each tier requires, and tracking mean time to detect and respond against targets will give leadership the visibility and the evidence trail that auditors and regulators expect.

---

## Cybersecurity Engineer Perspective
> **Code access available.** Tools: kubectl, cloud CLI, SIEM (Sentinel/Splunk), direct remediation.

### Assessment Commands
```bash
# Check open incidents in Sentinel — last 24 hours, sorted by severity
# Run in Sentinel Log Analytics workspace
```

```kql
// Morning triage: all open incidents from last 24 hours
SecurityIncident
| where TimeGenerated > ago(24h)
| where Status != "Closed"
| project TimeGenerated, Title, Severity, Status,
          Owner = tostring(Owner.assignedTo),
          AlertCount, IncidentNumber
| sort by Severity asc, TimeGenerated desc
// Severity sort order: High=1, Medium=2, Low=3, Informational=4
```

```bash
# Check open incidents in Splunk ES (Notable Events)
# Paste into Splunk Search
```

```spl
/* Open notable events, last 24 hours */
index=main OR index=security earliest=-24h
| search _type=alert OR sourcetype=stash
| stats count by savedsearch_name, alert_severity
| sort -count
```

```bash
# List all pods and their status (scoping containment targets)
kubectl get pods -n <app-namespace> -o wide

# Check recent security events in K8s audit log
kubectl get events -n <app-namespace> --sort-by='.lastTimestamp' | tail -30
```

### Detection / Testing

```kql
// Hunt: web app attack — SQL injection patterns in request logs
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DeviceAction !in ("Deny", "Drop")
| where RequestURL matches regex @"(?i)(union.*select|drop.*table|insert.*into|'.*--|;.*--)"
| project TimeGenerated, SourceIP, RequestURL, DestinationHostName, ApplicationProtocol
| sort by TimeGenerated desc
```

```kql
// Hunt: auth bypass — repeated 401/403 with eventual 200 from same IP
W3CIISLog
| where TimeGenerated > ago(1h)
| summarize
    TotalRequests = count(),
    Failures = countif(scStatus in ("401","403")),
    Successes = countif(scStatus == "200")
    by cIP, csUriStem
| where Failures > 10 and Successes > 0
| project cIP, csUriStem, Failures, Successes, TotalRequests
| sort by Failures desc
```

```kql
// Hunt: data exfiltration — large outbound transfers
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DeviceAction !in ("Deny", "Drop", "Reset")
| where SentBytes > 104857600  // 100MB threshold
| project TimeGenerated, SourceIP, DestinationIP, DestinationPort, SentBytes, ReceivedBytes, ApplicationProtocol
| sort by SentBytes desc
```

```kql
// Hunt: API abuse — abnormally high request rate from single source
W3CIISLog
| where TimeGenerated > ago(1h)
| summarize RequestCount = count() by cIP, bin(TimeGenerated, 5m)
| where RequestCount > 500
| sort by RequestCount desc
```

```spl
/* Hunt: brute force — failed logins, rank threshold */
index=wineventlog EventCode=4625 earliest=-24h
| stats count as FailedAttempts, values(Account_Name) as Targets
    by Source_Network_Address, host
| where FailedAttempts > 5
| eval Rank = case(
    FailedAttempts > 50, "B-rank — senior analyst",
    FailedAttempts > 20, "C-rank — analyst verifies",
    true(), "D-rank — document and close")
| sort -FailedAttempts
| table Source_Network_Address, host, FailedAttempts, Targets, Rank
```

```spl
/* Hunt: kubectl exec in production — high-value L7 detection */
index=k8s sourcetype=kube:apiserver:audit verb=create earliest=-24h
| rex field=requestURI "\/api\/v1\/namespaces\/(?<Namespace>[^\/]+)\/pods\/(?<PodName>[^\/]+)\/(?<Action>exec|log|portforward)"
| where isnotnull(Action)
| spath output=Username path="user.username"
| table _time, Username, Namespace, PodName, Action, sourceIPAddresses{}
| sort -_time
```

### Remediation

```bash
# --- CONTAINMENT: Block IP in WAF (AWS WAF example) ---
ATTACKER_IP="<attacker-ip>"
WAF_ACL_ID="<waf-acl-id>"
RULE_NAME="EmergencyBlock-$(date +%Y%m%d-%H%M)"

# Get WAF IP Set ID (separate resource from ACL)
WAF_IPSET_ID=$(aws wafv2 list-ip-sets --scope REGIONAL \
  --query "IPSets[?Name=='BlockList'].Id" --output text)

# Get current lock token for IP set
LOCK_TOKEN=$(aws wafv2 get-ip-set \
  --name BlockList --scope REGIONAL --id "$WAF_IPSET_ID" \
  --query 'LockToken' --output text)

aws wafv2 update-ip-set \
  --scope CLOUDFRONT \
  --id "$WAF_IPSET_ID" \
  --name "BlockList" \
  --addresses "$ATTACKER_IP/32" \
  --lock-token "$LOCK_TOKEN"

# Verify block applied
aws wafv2 get-ip-set --scope CLOUDFRONT --id "$WAF_IPSET_ID" --name BlockList --query "IPSet.Addresses"
```

```bash
# --- CONTAINMENT: Isolate compromised pod (remove from service, keep for forensics) ---
COMPROMISED_POD="<pod-name>"

# Add isolate label — removes pod from service endpoints
kubectl label pod "$COMPROMISED_POD" -n <app-namespace> security.jsa/status=isolated --overwrite

# Cordon the node to prevent new scheduling (if node-level compromise suspected)
NODE=$(kubectl get pod "$COMPROMISED_POD" -n <app-namespace> -o jsonpath='{.spec.nodeName}')
kubectl cordon "$NODE"

# Take a memory/process snapshot before any restart
kubectl exec "$COMPROMISED_POD" -n <app-namespace> -- ps aux > /tmp/jsa-evidence/IR-4/ps-snapshot-$(date +%Y%m%d-%H%M%S).txt 2>&1

# Capture environment variables (may contain secrets)
kubectl exec "$COMPROMISED_POD" -n <app-namespace> -- env > /tmp/jsa-evidence/IR-4/env-snapshot-$(date +%Y%m%d-%H%M%S).txt 2>&1
```

```bash
# --- CONTAINMENT: Disable compromised IAM user (AWS) ---
COMPROMISED_USER="<iam-username>"

# Deactivate all access keys
aws iam list-access-keys --user-name "$COMPROMISED_USER" \
  --query 'AccessKeyMetadata[].AccessKeyId' --output text | \
  tr '\t' '\n' | while read KEY_ID; do
    echo "Deactivating key: $KEY_ID"
    aws iam update-access-key \
      --user-name "$COMPROMISED_USER" \
      --access-key-id "$KEY_ID" \
      --status Inactive
  done

# Attach explicit deny policy (belt-and-suspenders)
aws iam put-user-policy \
  --user-name "$COMPROMISED_USER" \
  --policy-name "EmergencyDenyAll" \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}'
```

```bash
# --- CONTAINMENT: Disable Entra ID / Azure AD user account ---
# Requires Azure CLI with appropriate permissions
USER_UPN="<user@domain.com>"

az ad user update --id "$USER_UPN" --account-enabled false

# Revoke all active sessions
az rest --method POST \
  --url "https://graph.microsoft.com/v1.0/users/$USER_UPN/revokeSignInSessions"

echo "Account disabled and sessions revoked for: $USER_UPN"
```

```bash
# --- CONTAINMENT: Rotate compromised Kubernetes secret ---
SECRET_NAME="<secret-name>"
NEW_VALUE="<new-secret-value>"

# Patch secret with new value
kubectl create secret generic "$SECRET_NAME" \
  -n <app-namespace> \
  --from-literal=password="$NEW_VALUE" \
  --dry-run=client -o yaml | kubectl apply -f -

# Restart deployment to pick up new secret
kubectl rollout restart deployment/<app-deployment> -n <app-namespace>
kubectl rollout status deployment/<app-deployment> -n <app-namespace>
```

### Validation

```bash
# Verify WAF block is active
aws wafv2 get-ip-set --scope CLOUDFRONT --id "<waf-acl-id>" --name BlockList \
  --query "IPSet.Addresses" --output table
# Expected: list includes <attacker-ip>/32

# Verify pod is isolated from service endpoints
kubectl get endpoints -n <app-namespace> | grep <app-service>
# Expected: isolated pod IP is NOT listed in ENDPOINTS column

# Verify IAM user is fully disabled
aws iam list-access-keys --user-name "<iam-username>" \
  --query 'AccessKeyMetadata[*].{Key:AccessKeyId,Status:Status}' --output table
# Expected: all keys show Status=Inactive

# Verify K8s secret rotation triggered rollout
kubectl rollout history deployment/<app-deployment> -n <app-namespace>
# Expected: new revision entry with timestamp matching rotation time

# Check no new incidents opened in last 30 minutes from same source
```

```kql
// Sentinel: confirm no new activity from contained IP post-block
let BlockedIP = "<attacker-ip>";
let ContainmentTime = datetime(2024-01-01T00:00:00Z);  // Replace with actual time
union SigninLogs, CommonSecurityLog, W3CIISLog
| where TimeGenerated > ContainmentTime
| where SourceIPAddress == BlockedIP or cIP == BlockedIP
| project TimeGenerated, Type, SourceIPAddress, cIP, Activity
// Expected: zero rows after containment time
```

### Evidence Capture

```bash
# Create evidence directory with date stamp
mkdir -p /tmp/jsa-evidence/IR-4/$(date +%Y%m%d)

# Export Sentinel incident timeline
# Run in Log Analytics — save output as incident-timeline.json
```

```kql
// Evidence: full incident timeline for IR-4 record
SecurityIncident
| where TimeGenerated > ago(7d)
| where IncidentNumber == "<incident-number>"
| project TimeGenerated, Title, Severity, Status, Classification,
          Owner = tostring(Owner.assignedTo), Comments, IncidentNumber
```

```bash
# Export K8s events during incident window
kubectl get events -n <app-namespace> \
  --sort-by='.lastTimestamp' \
  -o json > /tmp/jsa-evidence/IR-4/$(date +%Y%m%d)/k8s-events.json

# Export pod logs from isolated pod (before deletion)
kubectl logs "<compromised-pod>" -n <app-namespace> --previous \
  > /tmp/jsa-evidence/IR-4/$(date +%Y%m%d)/pod-logs-previous.txt 2>&1

kubectl logs "<compromised-pod>" -n <app-namespace> \
  > /tmp/jsa-evidence/IR-4/$(date +%Y%m%d)/pod-logs-current.txt 2>&1

# Export IAM CloudTrail events for compromised user
# macOS: date -v-1d +%Y-%m-%dT%H:%M:%SZ
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue="<iam-username>" \
  --start-time "$(date -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --output json > /tmp/jsa-evidence/IR-4/$(date +%Y%m%d)/cloudtrail-user-events.json

# Create chain-of-custody record
cat > /tmp/jsa-evidence/IR-4/$(date +%Y%m%d)/chain-of-custody.txt << 'EOF'
CHAIN OF CUSTODY — IR-4 EVIDENCE PACKAGE
=========================================
Incident Number : <incident-number>
Collection Date : $(date -u +%Y-%m-%dT%H:%M:%SZ)
Collected By    : <analyst-name>
Systems Accessed: <list-systems>
Files Collected :
  - k8s-events.json
  - pod-logs-previous.txt
  - pod-logs-current.txt
  - cloudtrail-user-events.json
  - ps-snapshot-*.txt
  - env-snapshot-*.txt
Hash (sha256)   : (run: sha256sum /tmp/jsa-evidence/IR-4/$(date +%Y%m%d)/*)
EOF

# Generate file hashes for chain of custody
sha256sum /tmp/jsa-evidence/IR-4/$(date +%Y%m%d)/* \
  > /tmp/jsa-evidence/IR-4/$(date +%Y%m%d)/sha256sums.txt

echo "[DONE] Evidence package: /tmp/jsa-evidence/IR-4/$(date +%Y%m%d)/"
ls -lh /tmp/jsa-evidence/IR-4/$(date +%Y%m%d)/
```
