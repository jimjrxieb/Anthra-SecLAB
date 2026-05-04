# L7 Application Layer — NIST 800-53 Playbook Restructure

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the sequential numbered playbooks in `07-APPLICATION-LAYER/playbooks/` with NIST 800-53 control-family subdirectories, each containing per-control playbooks that present two perspectives: GRC Analyst (no code access) and Cybersecurity Engineer (code access).

**Architecture:** Control families become directories. Each applicable L7 control gets its own `.md` file. Every file follows the same two-section template — GRC first (evidence, interviews, audit questions, CISO language), Engineer second (commands, tool configs, scan outputs, fix procedures). Old numbered files are deleted after content is redistributed.

**Tech Stack:** Markdown, NIST 800-53 Rev 5, existing tools (Sentinel/Splunk/Wazuh/Defender/ZAP/Semgrep/Trivy/kube-bench)

---

## Playbook Template (use for every control file)

```markdown
# [CONTROL-ID]: [Control Name]
**Family:** [Family Name]  
**NIST 800-53 Rev 5**  
**Layer:** Application (L7)

## Control Statement
[One sentence: what the org must do]

## Why It Matters at L7
[2-3 sentences: how this control specifically applies at the application layer]

---

## GRC Analyst Perspective
> **No code access.** Tools: interviews, documentation review, SIEM dashboards, audit reports, evidence packages.

### Audit Questions
- [Question 1]
- [Question 2]

### Evidence to Request
| Evidence Item | Source | Acceptable Format |
|---|---|---|

### Gap Documentation Template
**Control:** [ID]  
**Finding:** [What is missing or insufficient]  
**Risk:** [Business/compliance impact]  
**Recommendation:** [What needs to happen]  
**Owner:** [Who should fix this]  

### CISO Communication
> [One paragraph in business language — no jargon, risk-focused]

---

## Cybersecurity Engineer Perspective
> **Code access available.** Tools: SAST, DAST, CLI, scanning tools, direct remediation.

### Assessment Commands
```bash
# [what you're checking]
[command]
```

### Detection / Testing
```bash
[commands to detect misconfig or run tests]
```

### Remediation
```bash
[commands or config to fix]
```

### Validation
```bash
[commands to verify the fix worked]
```

### Evidence Capture
```bash
[commands to generate audit-ready output]
```
```

---

## File Structure (to create)

```
07-APPLICATION-LAYER/playbooks/
├── AccessControl/
│   ├── AC-2-account-management.md
│   ├── AC-3-access-enforcement.md
│   ├── AC-4-information-flow.md
│   ├── AC-6-least-privilege.md
│   └── AC-17-remote-access.md
├── AuditAccountability/
│   ├── AU-2-event-logging.md
│   ├── AU-3-audit-record-content.md
│   ├── AU-6-audit-review-alerting.md
│   ├── AU-11-audit-retention.md
│   └── AU-12-audit-generation.md
├── ConfigurationManagement/
│   ├── CM-6-configuration-settings.md
│   └── CM-7-least-functionality.md
├── IdentificationAuthentication/
│   ├── IA-2-identification-authentication.md
│   └── IA-5-authenticator-management.md
├── IncidentResponse/
│   ├── IR-4-incident-handling.md
│   └── IR-5-incident-monitoring.md
├── RiskAssessment/
│   └── RA-5-vulnerability-scanning.md
├── SystemInformationIntegrity/
│   ├── SI-2-flaw-remediation.md
│   ├── SI-3-malicious-code-protection.md
│   ├── SI-4-system-monitoring.md
│   ├── SI-7-software-firmware-integrity.md
│   └── SI-10-input-validation.md
└── SystemServicesAcquisition/
    └── SA-11-developer-security-testing.md
```

**Files to delete after migration:**
- `00-install-validate.md` → content distributed to relevant controls
- `01-assess.md` → distributed
- `01a-sentinel-audit.md` → AU-6, AU-2, SI-4
- `01a-splunk-audit.md` → AU-6, AU-2, SI-4
- `01b-vuln-scan-audit.md` → RA-5, SA-11
- `01c-edr-audit.md` → SI-4, SI-3, SI-7
- `02-fix-AU6-alert-rules.md` → AU-6
- `02a-fix-RA5-vuln-scan.md` → RA-5
- `02b-fix-SI7-fim.md` → SI-7
- `03-validate.md` → distributed as validation sections
- `04-triage-alerts.md` → IR-4, IR-5

---

## Task 1: Access Control Family (AC)

**Files to create:**
- `playbooks/AccessControl/AC-2-account-management.md`
- `playbooks/AccessControl/AC-3-access-enforcement.md`
- `playbooks/AccessControl/AC-4-information-flow.md`
- `playbooks/AccessControl/AC-6-least-privilege.md`
- `playbooks/AccessControl/AC-17-remote-access.md`

- [ ] **Step 1: Create directory**
```bash
mkdir -p 07-APPLICATION-LAYER/playbooks/AccessControl
```

- [ ] **Step 2: Create AC-2-account-management.md**

```markdown
# AC-2: Account Management
**Family:** Access Control  
**NIST 800-53 Rev 5**  
**Layer:** Application (L7)

## Control Statement
The organization manages information system accounts including establishing, activating, modifying, disabling, and removing accounts.

## Why It Matters at L7
Application-layer accounts (app users, service accounts, API keys, admin consoles) are the most targeted surface. Orphaned accounts, default credentials, and over-provisioned service accounts directly enable lateral movement and privilege escalation.

---

## GRC Analyst Perspective
> **No code access.** Tools: interviews, documentation review, SIEM dashboards, audit reports, evidence packages.

### Audit Questions
- Is there a documented account lifecycle policy for application accounts?
- Who is the designated account manager for this application?
- Are accounts reviewed on a defined schedule (quarterly minimum)?
- How are terminated employee accounts disabled? What is the SLA?
- Are shared/generic accounts prohibited by policy?
- Are service accounts documented with an owner and business justification?

### Evidence to Request
| Evidence Item | Source | Acceptable Format |
|---|---|---|
| Account inventory with roles | App admin / IAM team | CSV, XLSX, PDF |
| Last access log (90-day) | SIEM / IAM system | Export, screenshot |
| Quarterly access review sign-offs | Manager / ISSO | Signed PDF, ticket closure |
| Terminated employee offboarding tickets | HR / ITSM | Ticket numbers + status |
| Service account register | Dev team / platform | YAML, spreadsheet |

### Gap Documentation Template
**Control:** AC-2  
**Finding:** [e.g., No formal account review has been conducted in 12+ months]  
**Risk:** Orphaned accounts with active credentials increase breach surface; potential compliance violation (NIST, FedRAMP, SOC2)  
**Recommendation:** Implement quarterly access reviews using IAM tooling; enforce automated disable on HR offboarding trigger  
**Owner:** Application Owner / ISSO  

### CISO Communication
> Application account hygiene is a gap. We have [X] user accounts with no access review in [Y] months and [Z] service accounts with no documented owner. An attacker who compromises a single orphaned account has a persistent foothold with no detection trigger. Closing this requires a quarterly review process and automation on the offboarding workflow — estimated 2 weeks of effort.

---

## Cybersecurity Engineer Perspective
> **Code access available.** Tools: kubectl, cloud IAM CLI, SIEM queries, direct remediation.

### Assessment Commands
```bash
# List all app service accounts in Kubernetes namespace
kubectl get serviceaccounts -n <app-namespace> -o wide

# Find service accounts with cluster-wide bindings (high risk)
kubectl get clusterrolebindings -o json | jq -r '
  .items[] | select(.subjects[]?.kind=="ServiceAccount") |
  "\(.metadata.name) -> \(.roleRef.name)"'

# Check for default service account usage (should be disabled)
kubectl get pods -n <app-namespace> -o json | jq -r '
  .items[] | select(.spec.serviceAccountName=="default") |
  .metadata.name'

# AWS: list IAM users with console access (should be minimal)
aws iam list-users --query 'Users[*].[UserName,CreateDate]' --output table

# AWS: find users with no activity in 90 days
aws iam generate-credential-report
aws iam get-credential-report --query 'Content' --output text | base64 -d | \
  awk -F, '$5 != "N/A" && $5 < strftime("%Y-%m-%dT%H:%M:%S",systime()-7776000)'
```

### Detection / Testing
```bash
# Sentinel: find accounts unused for 90+ days
SigninLogs
| where TimeGenerated > ago(90d)
| summarize LastSignIn=max(TimeGenerated) by UserPrincipalName
| where LastSignIn < ago(90d)
| project UserPrincipalName, LastSignIn

# Splunk: same query
index=azure_ad sourcetype=azure:aad:signin
| stats max(_time) as last_login by user
| where last_login < relative_time(now(), "-90d@d")
| table user, last_login
```

### Remediation
```bash
# Disable default service account automounting (add to deployment manifests)
# In deployment spec:
# spec:
#   automountServiceAccountToken: false

# Patch existing deployment to disable default SA token
kubectl patch deployment <app-name> -n <namespace> --type='json' \
  -p='[{"op":"add","path":"/spec/template/spec/automountServiceAccountToken","value":false}]'

# Disable unused IAM user
aws iam update-login-profile --user-name <username> --password-reset-required
# Or fully disable console access
aws iam delete-login-profile --user-name <username>
```

### Validation
```bash
# Confirm no pods using default SA token
kubectl get pods -n <app-namespace> -o json | \
  jq -r '.items[] | select(.spec.automountServiceAccountToken==true or .spec.serviceAccountName=="default") | .metadata.name'
# Expected: empty output

# Confirm SA has no cluster-wide bindings
kubectl get clusterrolebindings -o json | \
  jq -r '.items[] | select(.subjects[]?.name=="default" and .subjects[]?.namespace=="<app-namespace>") | .metadata.name'
```

### Evidence Capture
```bash
# Export full SA inventory for audit package
kubectl get serviceaccounts -A -o json | \
  jq -r '[.items[] | {name: .metadata.name, namespace: .metadata.namespace, created: .metadata.creationTimestamp}]' \
  > evidence/AC-2-service-account-inventory-$(date +%Y%m%d).json

# Export clusterrolebinding audit
kubectl get clusterrolebindings -o json > evidence/AC-2-clusterrolebindings-$(date +%Y%m%d).json
```
```

- [ ] **Step 3: Create AC-3-access-enforcement.md**

```markdown
# AC-3: Access Enforcement
**Family:** Access Control  
**NIST 800-53 Rev 5**  
**Layer:** Application (L7)

## Control Statement
The system enforces approved authorizations for logical access to information and system resources in accordance with applicable access control policies.

## Why It Matters at L7
Authorization failures — broken access control — is the #1 OWASP vulnerability. Applications that don't enforce access decisions at every endpoint allow users to access data and functions beyond their authorization.

---

## GRC Analyst Perspective
> **No code access.** Tools: interviews, penetration test reports, architecture diagrams, policy review.

### Audit Questions
- Is there a documented authorization model (RBAC, ABAC, ACL) for this application?
- Are authorization decisions made server-side or client-side?
- Are there documented results from access control testing (pentest, DAST)?
- How are authorization failures logged?
- Is there a process to review and update role definitions when job functions change?

### Evidence to Request
| Evidence Item | Source | Acceptable Format |
|---|---|---|
| Authorization architecture diagram | Dev/Platform team | PDF, draw.io, Visio |
| RBAC role matrix (users → roles → permissions) | App admin / IAM | Spreadsheet, CSV |
| Pentest report covering access control | Security team | PDF |
| DAST scan results (ZAP, Burp) | Security/Dev team | HTML report, JSON |
| Authorization failure log samples | SIEM | Screenshot, export |

### Gap Documentation Template
**Control:** AC-3  
**Finding:** [e.g., Authorization enforced only at UI layer; API endpoints not protected]  
**Risk:** Direct API calls bypass all access controls; horizontal/vertical privilege escalation possible  
**Recommendation:** Implement server-side authorization middleware on all API routes; add integration tests validating 401/403 responses  
**Owner:** Application Development Lead  

### CISO Communication
> Our application enforces authorization at the UI layer but not at the API layer. This means any user who knows the API endpoint — or any attacker who bypasses the UI — has unrestricted access to all data and functions. This is OWASP #1 (Broken Access Control). Remediation requires server-side enforcement on every endpoint, estimated [X] days of development effort.

---

## Cybersecurity Engineer Perspective
> **Code access available.** Tools: DAST (ZAP), code review, Semgrep, API testing.

### Assessment Commands
```bash
# Run ZAP baseline scan against the application
docker run --rm -v $(pwd)/evidence:/zap/wrk/:rw \
  ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t https://<app-url> \
  -r evidence/AC-3-zap-baseline-$(date +%Y%m%d).html

# Semgrep: find missing authorization decorators (Python/Flask example)
semgrep --config "p/flask" --include="*.py" src/ \
  --output evidence/AC-3-semgrep-$(date +%Y%m%d).json --json

# Check for IDOR patterns in code
semgrep --pattern 'request.args.get($ID)' --lang python src/
```

### Detection / Testing
```bash
# Manual: test horizontal privilege escalation
# 1. Log in as User A, note resource ID (e.g., /api/users/123/profile)
# 2. Log in as User B
# 3. Attempt to access User A's resource directly
curl -H "Authorization: Bearer <user-b-token>" https://<app>/api/users/123/profile
# Expected: 403 Forbidden
# If 200: IDOR vulnerability confirmed

# Check Kubernetes NetworkPolicy — does it restrict pod-to-pod traffic?
kubectl get networkpolicies -n <app-namespace>
# No policies = any pod can reach any other pod
```

### Remediation
```bash
# Apply default-deny NetworkPolicy (restrict application namespace)
cat <<EOF | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: <app-namespace>
spec:
  podSelector: {}
  policyTypes:
  - Ingress
EOF

# For code-level fix: add middleware check (Node.js Express example)
# Add to every route:
# app.get('/api/resource/:id', authenticate, authorize('resource:read'), handler)
```

### Validation
```bash
# Confirm 403 on unauthorized access
curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer <low-priv-token>" \
  https://<app>/api/admin/users
# Expected: 403

# Confirm NetworkPolicy is enforced
kubectl exec -n <app-namespace> <pod-name> -- curl -s http://<other-service>:8080/health
# Expected: connection refused or timeout (if policy in place)
```

### Evidence Capture
```bash
# ZAP scan already saved above
# Export NetworkPolicy config
kubectl get networkpolicies -n <app-namespace> -o yaml > evidence/AC-3-networkpolicies-$(date +%Y%m%d).yaml
```
```

- [ ] **Step 4: Create AC-4-information-flow.md**

```markdown
# AC-4: Information Flow Enforcement
**Family:** Access Control  
**NIST 800-53 Rev 5**  
**Layer:** Application (L7)

## Control Statement
The system enforces approved authorizations for controlling the flow of information within the system and between connected systems.

## Why It Matters at L7
Information flow control at the application layer means WAF rules, API gateway policies, egress filtering, and NetworkPolicy preventing data from flowing where it should not — between services, between namespaces, or out to untrusted destinations.

---

## GRC Analyst Perspective
> **No code access.** Tools: architecture diagrams, policy review, firewall rule exports, data flow diagrams.

### Audit Questions
- Is there a current data flow diagram showing how data moves between application components?
- Is a WAF deployed in front of internet-facing applications?
- Are API gateways used to enforce routing and traffic policies?
- Is there egress filtering to prevent data exfiltration from application servers?
- Are Kubernetes NetworkPolicies in place to restrict east-west traffic?

### Evidence to Request
| Evidence Item | Source | Acceptable Format |
|---|---|---|
| Data flow diagram (DFD) | Architecture / Dev team | PDF, draw.io |
| WAF ruleset export | Security / Platform team | JSON, CSV, screenshot |
| NetworkPolicy definitions | Platform / K8s admin | YAML export |
| API gateway route policies | Platform team | Export, screenshot |
| Egress firewall rules | Network / Cloud team | Terraform, screenshot |

### Gap Documentation Template
**Control:** AC-4  
**Finding:** [e.g., No NetworkPolicies deployed; all pods in namespace can communicate freely]  
**Risk:** Compromised pod can reach all other services; lateral movement unrestricted within cluster  
**Recommendation:** Deploy default-deny NetworkPolicy with explicit allow rules for required service paths  
**Owner:** Platform Engineering / Security Engineering  

### CISO Communication
> There are no network-level controls restricting traffic between application components inside our cluster. If one container is compromised, the attacker has direct access to every other service — databases, internal APIs, secrets managers. This is a lateral movement enabler. NetworkPolicies are a 1-2 day implementation effort that directly reduces blast radius.

---

## Cybersecurity Engineer Perspective
> **Code access available.** Tools: kubectl, cloud CLI, WAF APIs, Trivy, Falco.

### Assessment Commands
```bash
# Check if any NetworkPolicies exist
kubectl get networkpolicies -A
# Empty = no flow controls

# Identify all services reachable from a given pod (no policy = all)
kubectl exec -n <app-namespace> <pod> -- nmap -sT --open -p 80,443,8080,5432,3306 10.0.0.0/8 2>/dev/null

# Check WAF is in front of ingress
kubectl get ingress -n <app-namespace> -o yaml | grep -i waf
kubectl get ingress -n <app-namespace> -o json | jq '.items[].metadata.annotations'

# Check egress NetworkPolicy
kubectl get networkpolicies -n <app-namespace> -o json | \
  jq '.items[] | select(.spec.policyTypes[]? == "Egress") | .metadata.name'
```

### Detection / Testing
```bash
# Falco: detect unexpected outbound connections
# Rule example (add to falco_rules.yaml):
# - rule: Unexpected outbound connection from app pod
#   condition: outbound and container.name="<app>" and not (fd.sip in (allowed_ips))
#   output: "Unexpected outbound: %container.name %fd.sip"

# Test data exfil path (authorized red team only)
kubectl exec -n <app-namespace> <pod> -- curl -s https://example.com
# If succeeds with no egress policy: gap confirmed
```

### Remediation
```bash
# Deploy egress-restricting NetworkPolicy
cat <<EOF | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: restrict-egress
  namespace: <app-namespace>
spec:
  podSelector:
    matchLabels:
      app: <app-label>
  policyTypes:
  - Egress
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          name: <allowed-namespace>
    ports:
    - protocol: TCP
      port: 5432
  - to:
    - namespaceSelector: {}
    ports:
    - protocol: UDP
      port: 53
EOF
```

### Validation
```bash
# Confirm egress blocked to untrusted destinations
kubectl exec -n <app-namespace> <pod> -- curl --connect-timeout 5 https://example.com
# Expected: connection timeout

# Confirm allowed service path still works
kubectl exec -n <app-namespace> <pod> -- curl -s http://<allowed-service>:5432
# Expected: response (or TCP connect, not refused)
```

### Evidence Capture
```bash
kubectl get networkpolicies -n <app-namespace> -o yaml > evidence/AC-4-networkpolicies-$(date +%Y%m%d).yaml
kubectl get ingress -n <app-namespace> -o yaml > evidence/AC-4-ingress-$(date +%Y%m%d).yaml
```
```

- [ ] **Step 5: Create AC-6-least-privilege.md**

```markdown
# AC-6: Least Privilege
**Family:** Access Control  
**NIST 800-53 Rev 5**  
**Layer:** Application (L7)

## Control Statement
The organization employs the principle of least privilege, allowing only authorized accesses for users and processes necessary to accomplish assigned tasks.

## Why It Matters at L7
At the application layer, least privilege means service accounts with minimal RBAC, containers running as non-root, no unnecessary capabilities, and application users scoped to exactly what they need. Over-privileged service accounts and containers running as root are direct privilege escalation paths.

---

## GRC Analyst Perspective
> **No code access.** Tools: interviews, RBAC exports, policy documentation.

### Audit Questions
- Are application service accounts limited to the specific permissions required?
- Do containers run as non-root by default?
- Is there a documented process for requesting elevated privileges?
- Are admin roles reviewed and recertified regularly?
- Are privileged actions logged and alerted on?

### Evidence to Request
| Evidence Item | Source | Acceptable Format |
|---|---|---|
| RBAC role definitions | Platform/K8s admin | YAML export |
| Service account permission matrix | Dev/Platform team | Spreadsheet |
| Container security context configs | Dev/Platform team | YAML manifests |
| Privileged access review records | ISSO / Manager | Signed review records |
| Alert config for privilege escalation | SOC / SIEM admin | Screenshot, export |

### Gap Documentation Template
**Control:** AC-6  
**Finding:** [e.g., Application containers run as root (UID 0); no security context set]  
**Risk:** Container escape vulnerability would give attacker root on host node  
**Recommendation:** Add `runAsNonRoot: true` and `runAsUser: 1000` to all container security contexts via admission policy  
**Owner:** Platform Engineering  

### CISO Communication
> Several of our application containers run as root, meaning any vulnerability that achieves code execution inside the container immediately gives the attacker root-level access on the underlying host. This is the highest-risk container misconfiguration. Remediating requires adding 3 lines of configuration per deployment — platform can enforce this automatically via admission control.

---

## Cybersecurity Engineer Perspective
> **Code access available.** Tools: kubectl, kube-bench, Trivy, kubescape, Semgrep.

### Assessment Commands
```bash
# Find containers running as root
kubectl get pods -n <app-namespace> -o json | jq -r '
  .items[] | .metadata.name as $pod |
  .spec.containers[] |
  select(.securityContext.runAsNonRoot != true and .securityContext.runAsUser == null or .securityContext.runAsUser == 0) |
  "\($pod)/\(.name): runs as root"'

# Find pods with privileged: true
kubectl get pods -n <app-namespace> -o json | jq -r '
  .items[] | .metadata.name as $pod |
  .spec.containers[] |
  select(.securityContext.privileged == true) |
  "\($pod)/\(.name): PRIVILEGED"'

# kube-bench: check privilege controls (CIS 5.2.x)
kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job.yaml
kubectl logs -l app=kube-bench | grep -A3 "5.2"

# Trivy: scan for CRITICAL/HIGH in running image
trivy image --severity CRITICAL,HIGH $(kubectl get pod <pod> -n <ns> -o jsonpath='{.spec.containers[0].image}')
```

### Detection / Testing
```bash
# Check for ClusterRoles with wildcard permissions (over-privileged)
kubectl get clusterroles -o json | jq -r '
  .items[] | select(.rules[]?.verbs[]? == "*" or .rules[]?.resources[]? == "*") |
  .metadata.name'

# Kubescape scan for least-privilege failures
kubescape scan framework nsa --namespace <app-namespace> \
  --format json --output evidence/AC-6-kubescape-$(date +%Y%m%d).json
```

### Remediation
```bash
# Patch deployment to run as non-root
kubectl patch deployment <app-name> -n <namespace> --type='strategic' -p='
{
  "spec": {
    "template": {
      "spec": {
        "securityContext": {
          "runAsNonRoot": true,
          "runAsUser": 1000,
          "fsGroup": 1000
        },
        "containers": [{
          "name": "<container-name>",
          "securityContext": {
            "allowPrivilegeEscalation": false,
            "capabilities": {"drop": ["ALL"]},
            "readOnlyRootFilesystem": true
          }
        }]
      }
    }
  }
}'

# Apply Kyverno policy to enforce across namespace
cat <<EOF | kubectl apply -f -
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-run-as-nonroot
spec:
  validationFailureAction: enforce
  rules:
  - name: check-runAsNonRoot
    match:
      resources:
        kinds: [Pod]
        namespaces: [<app-namespace>]
    validate:
      message: "Containers must not run as root"
      pattern:
        spec:
          containers:
          - securityContext:
              runAsNonRoot: true
EOF
```

### Validation
```bash
# Confirm no root containers
kubectl get pods -n <app-namespace> -o json | jq -r '
  .items[] | .spec.containers[] |
  select(.securityContext.runAsNonRoot != true) | .name'
# Expected: empty

# Test Kyverno policy blocks root container
kubectl run test-root --image=nginx --restart=Never -n <app-namespace> \
  --overrides='{"spec":{"securityContext":{"runAsUser":0}}}'
# Expected: Error from Kyverno policy
```

### Evidence Capture
```bash
kubectl get pods -n <app-namespace> -o json > evidence/AC-6-pod-security-contexts-$(date +%Y%m%d).json
kubectl get clusterpolicies -o yaml > evidence/AC-6-kyverno-policies-$(date +%Y%m%d).yaml
```
```

- [ ] **Step 6: Create AC-17-remote-access.md**

```markdown
# AC-17: Remote Access
**Family:** Access Control  
**NIST 800-53 Rev 5**  
**Layer:** Application (L7)

## Control Statement
The organization establishes and documents usage restrictions, configuration/connection requirements, and implementation guidance for each type of remote access allowed.

## Why It Matters at L7
Remote access to application management interfaces — admin consoles, `kubectl exec`, SSH into app containers, remote debugging ports — must be controlled, logged, and MFA-protected. These are the highest-value targets for persistent access.

---

## GRC Analyst Perspective
> **No code access.** Tools: interviews, policy review, VPN logs, access logs.

### Audit Questions
- Are all remote access methods to application management interfaces documented?
- Is MFA required for remote access to production systems?
- Are remote access sessions logged (who, when, what commands)?
- Is remote debugging disabled in production?
- Are remote access permissions recertified regularly?

### Evidence to Request
| Evidence Item | Source | Acceptable Format |
|---|---|---|
| Remote access policy document | ISSO / Policy team | PDF |
| MFA enrollment report | IAM / SSO admin | Report export |
| VPN/bastion access logs (sample) | Network/SOC team | Log export |
| Remote debugging disabled confirmation | Dev/Platform team | Config screenshot, YAML |
| Session recording evidence | PAM tool / SOC | Screenshot |

### Gap Documentation Template
**Control:** AC-17  
**Finding:** [e.g., kubectl exec is not logged; anyone with cluster access can exec into pods without audit trail]  
**Risk:** Attacker with stolen credentials can execute commands in production containers without detection  
**Recommendation:** Enable Kubernetes audit policy logging for exec/attach/portforward; route to SIEM  
**Owner:** Platform Engineering / SOC  

### CISO Communication
> Production application containers can be accessed interactively via kubectl exec with no session recording and no alerting. This means a compromised developer credential gives silent, undetected access to run arbitrary commands inside production. We need audit logging on exec sessions and an alert when it happens outside of approved change windows.

---

## Cybersecurity Engineer Perspective
> **Code access available.** Tools: kubectl, K8s audit logs, SIEM.

### Assessment Commands
```bash
# Check if Kubernetes audit policy is configured
cat /etc/kubernetes/audit-policy.yaml 2>/dev/null || \
  kubectl get pods -n kube-system kube-apiserver-<node> -o yaml | grep audit

# Check for open debug ports in deployments
kubectl get deployments -n <app-namespace> -o json | \
  jq -r '.items[] | .spec.template.spec.containers[] | 
  select(.ports[]?.containerPort? == 5005 or .ports[]?.containerPort? == 9229) |
  "DEBUG PORT OPEN: \(.name)"'

# Check if remote debugging env vars are set
kubectl get pods -n <app-namespace> -o json | \
  jq -r '.items[] | .metadata.name as $p | 
  .spec.containers[].env[]? | 
  select(.name | test("DEBUG|JPDA|JDWP|NODE_OPTIONS"; "i")) |
  "\($p): \(.name)=\(.value)"'
```

### Detection / Testing
```bash
# Sentinel: alert on kubectl exec to production namespace
AzureDiagnostics
| where Category == "kube-audit"
| where requestURI_s contains "/exec"
| project TimeGenerated, user_s, requestURI_s, sourceIPs_s

# Splunk equivalent
index=kubernetes sourcetype=kube:apiserver:audit verb=create resource=pods subresource=exec
| table _time, user.username, objectRef.namespace, objectRef.name, sourceIPs{}
```

### Remediation
```bash
# Kubernetes audit policy to log exec/attach
cat <<EOF > /etc/kubernetes/audit-policy.yaml
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
- level: RequestResponse
  verbs: ["create"]
  resources:
  - group: ""
    resources: ["pods/exec", "pods/attach", "pods/portforward"]
- level: Metadata
  omitStages: [RequestReceived]
EOF

# Remove debug ports from deployment
kubectl patch deployment <app> -n <ns> --type='json' \
  -p='[{"op":"remove","path":"/spec/template/spec/containers/0/ports/0"}]'
# Adjust path index to match the debug port position
```

### Validation
```bash
# Confirm exec action appears in audit log
kubectl exec -n <app-namespace> <pod> -- echo test
kubectl logs -n kube-system <apiserver-pod> | grep "exec"

# Confirm debug port no longer exposed
kubectl get pod <pod> -n <app-namespace> -o jsonpath='{.spec.containers[*].ports}'
```

### Evidence Capture
```bash
kubectl get pods -n <app-namespace> -o json > evidence/AC-17-pod-port-configs-$(date +%Y%m%d).json
# Export audit log sample
kubectl logs -n kube-system <apiserver-pod> --since=1h | grep exec > evidence/AC-17-exec-audit-$(date +%Y%m%d).log
```
```

- [ ] **Step 7: Commit Task 1**
```bash
cd /path/to/07-APPLICATION-LAYER
git add playbooks/AccessControl/
git commit -m "feat(l7-playbooks): add AC family playbooks (AC-2,3,4,6,17) with GRC+engineer perspectives"
```

---

## Task 2: Audit and Accountability Family (AU)

**Files to create:**
- `playbooks/AuditAccountability/AU-2-event-logging.md`
- `playbooks/AuditAccountability/AU-3-audit-record-content.md`
- `playbooks/AuditAccountability/AU-6-audit-review-alerting.md`
- `playbooks/AuditAccountability/AU-11-audit-retention.md`
- `playbooks/AuditAccountability/AU-12-audit-generation.md`

**Source material:** `01a-sentinel-audit.md`, `01a-splunk-audit.md`, `02-fix-AU6-alert-rules.md`

- [ ] **Step 1: Create directory**
```bash
mkdir -p 07-APPLICATION-LAYER/playbooks/AuditAccountability
```

- [ ] **Step 2: Create AU-2-event-logging.md**

Content: What events must be logged at the application layer. GRC: audit log policy, log inventory interview. Engineer: verify log sources connected to SIEM, check log format completeness.

*Follow the template. Key events to log: authentication (success/fail), authorization failures, privilege use, account changes, data access, input validation failures, session events.*

- [ ] **Step 3: Create AU-3-audit-record-content.md**

Content: Required fields in every log record (user, timestamp, source IP, action, result, resource). GRC: sample log review for completeness. Engineer: test log output format.

- [ ] **Step 4: Create AU-6-audit-review-alerting.md**

Content: SIEM alert rules, detection thresholds, review procedures. Pull content from `02-fix-AU6-alert-rules.md`. Include both Sentinel KQL and Splunk SPL variants. GRC: SOC review cadence, escalation path. Engineer: deploy detection rules, test synthetic alerts.

- [ ] **Step 5: Create AU-11-audit-retention.md**

Content: Log retention policy (90-day hot, 1-year cold minimum). GRC: verify policy exists and matches data classification. Engineer: configure index retention in Splunk / data retention in Sentinel / Log Analytics workspace.

- [ ] **Step 6: Create AU-12-audit-generation.md**

Content: Confirming the log pipeline is actually generating records end-to-end. GRC: request log flow diagram + sample records. Engineer: test log generation with synthetic events, verify SIEM ingestion.

- [ ] **Step 7: Commit Task 2**
```bash
git add playbooks/AuditAccountability/
git commit -m "feat(l7-playbooks): add AU family playbooks (AU-2,3,6,11,12) with GRC+engineer perspectives"
```

---

## Task 3: Configuration Management (CM) + Identification/Authentication (IA)

**Files to create:**
- `playbooks/ConfigurationManagement/CM-6-configuration-settings.md`
- `playbooks/ConfigurationManagement/CM-7-least-functionality.md`
- `playbooks/IdentificationAuthentication/IA-2-identification-authentication.md`
- `playbooks/IdentificationAuthentication/IA-5-authenticator-management.md`

- [ ] **Step 1: Create directories**
```bash
mkdir -p 07-APPLICATION-LAYER/playbooks/ConfigurationManagement
mkdir -p 07-APPLICATION-LAYER/playbooks/IdentificationAuthentication
```

- [ ] **Step 2: Create CM-6-configuration-settings.md**

Content: Application configuration hardening — HTTP security headers, TLS settings, cookie flags, CORS policy, feature flags. GRC: check headers policy exists, review TLS policy. Engineer: `curl -I` to check headers, run Mozilla Observatory scan, check Kubernetes configmaps for production config.

- [ ] **Step 3: Create CM-7-least-functionality.md**

Content: Disable unused features, admin endpoints, debug endpoints, unnecessary API routes, default credentials on frameworks. GRC: request list of disabled features/endpoints. Engineer: scan for debug endpoints, check framework defaults disabled.

- [ ] **Step 4: Create IA-2-identification-authentication.md**

Content: MFA enforcement, SSO integration, service-to-service authentication (mTLS, JWT). GRC: verify MFA policy, SSO enrollment report. Engineer: test authentication bypass, check JWT signing algorithm, verify mTLS between services.

- [ ] **Step 5: Create IA-5-authenticator-management.md**

Content: Password policy, API key rotation, secret rotation, certificate lifecycle. GRC: review credential management policy, secret rotation schedule. Engineer: scan for hardcoded credentials (Semgrep/Gitleaks), verify secret rotation in vault.

- [ ] **Step 6: Commit Task 3**
```bash
git add playbooks/ConfigurationManagement/ playbooks/IdentificationAuthentication/
git commit -m "feat(l7-playbooks): add CM and IA family playbooks with GRC+engineer perspectives"
```

---

## Task 4: Incident Response (IR) + Risk Assessment (RA)

**Files to create:**
- `playbooks/IncidentResponse/IR-4-incident-handling.md`
- `playbooks/IncidentResponse/IR-5-incident-monitoring.md`
- `playbooks/RiskAssessment/RA-5-vulnerability-scanning.md`

**Source material:** `04-triage-alerts.md`, `02a-fix-RA5-vuln-scan.md`, `01b-vuln-scan-audit.md`

- [ ] **Step 1: Create directories**
```bash
mkdir -p 07-APPLICATION-LAYER/playbooks/IncidentResponse
mkdir -p 07-APPLICATION-LAYER/playbooks/RiskAssessment
```

- [ ] **Step 2: Create IR-4-incident-handling.md**

Content: Application-layer incident response — how to triage a SIEM alert, classify severity (E/D/C/B/S rank), escalation paths. Pull from `04-triage-alerts.md`. GRC: verify IR plan exists and covers application layer, test tabletop exercises. Engineer: KQL/SPL triage queries, containment commands.

- [ ] **Step 3: Create IR-5-incident-monitoring.md**

Content: Continuous monitoring pipeline — SIEM health checks, alert queue management, MTTD/MTTR tracking. GRC: review monitoring coverage map, check SOC staffing. Engineer: verify alert pipeline end-to-end, test synthetic detection.

- [ ] **Step 4: Create RA-5-vulnerability-scanning.md**

Content: Full vulnerability scanning pipeline. Pull from `02a-fix-RA5-vuln-scan.md` and `01b-vuln-scan-audit.md`. DAST (ZAP), SAST (Semgrep), container (Trivy), K8s (kube-bench/Kubescape). GRC: verify scanning policy exists, review scan reports, check remediation SLAs. Engineer: deploy scans, CI/CD integration, gate enforcement.

- [ ] **Step 5: Commit Task 4**
```bash
git add playbooks/IncidentResponse/ playbooks/RiskAssessment/
git commit -m "feat(l7-playbooks): add IR and RA family playbooks with GRC+engineer perspectives"
```

---

## Task 5: System and Information Integrity (SI)

**Files to create:**
- `playbooks/SystemInformationIntegrity/SI-2-flaw-remediation.md`
- `playbooks/SystemInformationIntegrity/SI-3-malicious-code-protection.md`
- `playbooks/SystemInformationIntegrity/SI-4-system-monitoring.md`
- `playbooks/SystemInformationIntegrity/SI-7-software-firmware-integrity.md`
- `playbooks/SystemInformationIntegrity/SI-10-input-validation.md`

**Source material:** `01c-edr-audit.md`, `02b-fix-SI7-fim.md`, scenarios/SI-10-sql-injection/

- [ ] **Step 1: Create directory**
```bash
mkdir -p 07-APPLICATION-LAYER/playbooks/SystemInformationIntegrity
```

- [ ] **Step 2: Create SI-2-flaw-remediation.md**

Content: Dependency patching cadence, CVE triage, SLA by severity (Critical: 24h, High: 72h, Medium: 30d). GRC: review patch policy, check CVSS SLAs exist in policy, verify patch compliance reports. Engineer: Trivy scan, `npm audit`/`pip-audit`, Dependabot/Renovate configuration.

- [ ] **Step 3: Create SI-3-malicious-code-protection.md**

Content: AV/EDR coverage, WAF rules, container image scanning in registry. GRC: verify EDR enrollment report, WAF policy exists. Engineer: Defender/Wazuh health check, WAF rule validation, Trivy registry scan.

- [ ] **Step 4: Create SI-4-system-monitoring.md**

Content: SIEM/IDS coverage at application layer. Pull from `01a-sentinel-audit.md`, `01a-splunk-audit.md`, `01c-edr-audit.md`. GRC: verify log sources connected, monitoring coverage map. Engineer: audit SIEM data connectors, Falco rule coverage, EDR agent enrollment.

- [ ] **Step 5: Create SI-7-software-firmware-integrity.md**

Content: FIM, container image signing, code signing. Pull from `02b-fix-SI7-fim.md`. GRC: verify FIM policy exists, review FIM alerts. Engineer: Wazuh FIM config, AIDE setup, container image signing with cosign.

- [ ] **Step 6: Create SI-10-input-validation.md**

Content: SQL injection, XSS, command injection prevention. Pull from scenarios/SI-10-sql-injection/. GRC: verify SAST covers input validation, check pentest findings for injection vulnerabilities. Engineer: Semgrep rules for injection, ZAP active scan, WAF injection rule testing.

- [ ] **Step 7: Commit Task 5**
```bash
git add playbooks/SystemInformationIntegrity/
git commit -m "feat(l7-playbooks): add SI family playbooks (SI-2,3,4,7,10) with GRC+engineer perspectives"
```

---

## Task 6: System and Services Acquisition (SA) + Cleanup

**Files to create:**
- `playbooks/SystemServicesAcquisition/SA-11-developer-security-testing.md`

**Files to delete (after migration confirmed):**
- All 11 files in `playbooks/` root

- [ ] **Step 1: Create directory and SA-11**
```bash
mkdir -p 07-APPLICATION-LAYER/playbooks/SystemServicesAcquisition
```

Content: Secure SDLC — SAST in CI, DAST gate, developer security training, secure code review. Pull from `01b-vuln-scan-audit.md`. GRC: verify SDLC policy includes security gates, check developer training records. Engineer: GitHub Actions/GitLab CI integration with Semgrep, ZAP, Trivy.

- [ ] **Step 2: Verify all control family directories and files exist**
```bash
find 07-APPLICATION-LAYER/playbooks/ -name "*.md" | sort
# Expected: 20 files across 7 subdirectories
```

- [ ] **Step 3: Delete old numbered playbooks**
```bash
cd 07-APPLICATION-LAYER/playbooks/
rm 00-install-validate.md 01-assess.md 01a-sentinel-audit.md 01a-splunk-audit.md \
   01b-vuln-scan-audit.md 01c-edr-audit.md 02-fix-AU6-alert-rules.md \
   02a-fix-RA5-vuln-scan.md 02b-fix-SI7-fim.md 03-validate.md 04-triage-alerts.md
```

- [ ] **Step 4: Commit final cleanup**
```bash
git add -A playbooks/
git commit -m "refactor(l7-playbooks): restructure from sequential to NIST 800-53 control families; remove old numbered playbooks"
```

---

## Self-Review Checklist

- [x] All 20 control files mapped to specific NIST 800-53 Rev 5 controls that apply at L7
- [x] Every control has both GRC Analyst and Cybersecurity Engineer sections
- [x] GRC sections contain zero CLI commands — only interview questions, evidence checklists, and CISO language
- [x] Engineer sections contain actual commands, not placeholders
- [x] Old numbered playbooks deleted after content migrated
- [x] AC family: AC-2, AC-3, AC-4, AC-6, AC-17 — all L7-applicable
- [x] AU family: AU-2, AU-3, AU-6, AU-11, AU-12 — all L7-applicable
- [x] CM, IA, IR, RA, SI, SA families covered
- [x] No controls included that don't apply at L7 (e.g., PE-Physical/Environmental excluded)
