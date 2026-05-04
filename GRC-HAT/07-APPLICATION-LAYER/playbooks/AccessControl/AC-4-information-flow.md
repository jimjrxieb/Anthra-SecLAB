# AC-4: Information Flow Enforcement
**Family:** Access Control  
**NIST 800-53 Rev 5**  
**Layer:** Application (L7)

## Control Statement
The information system enforces approved authorizations for controlling the flow of information within the system and between interconnected systems based on applicable policy.

## Why It Matters at L7
At the application layer, information flow controls are the difference between an application that can only communicate with authorized services and one that can freely exfiltrate data to any external destination. A compromised pod without egress restrictions can beacon out to attacker infrastructure, exfiltrate database dumps, or pivot laterally to other services. WAFs enforce inbound information flow policy; NetworkPolicies and API gateway rules enforce east-west and egress flow policy. Both must be present and configured correctly.

---

## GRC Analyst Perspective
> **No code access.** Tools: interviews, documentation review, SIEM dashboards, audit reports, evidence packages.

### Audit Questions
- Is there a Web Application Firewall (WAF) deployed in front of all internet-facing application components? Is it in blocking mode or detection-only mode?
- Are Kubernetes NetworkPolicies deployed for all application namespaces, and do they default-deny all traffic unless explicitly permitted?
- Does the application have documented data flow diagrams showing all ingress and egress paths, including third-party APIs, databases, and external services the application communicates with?
- Is egress traffic from application pods restricted to known, authorized destinations? Or can pods make outbound connections to arbitrary internet endpoints?
- Are API gateway policies enforced between microservices to prevent unauthorized service-to-service communication?
- Is there SIEM alerting on anomalous egress traffic from application pods — for example, unexpected DNS lookups, connections to new external IPs, or high-volume data transfers?
- Has an information flow control assessment been conducted as part of any recent security review or architecture review board process?

### Evidence to Request
| Evidence Item | Source | Acceptable Format |
|---|---|---|
| WAF configuration and rule set export | Cloud WAF (AWS WAF, Azure WAF, Cloudflare) or ingress WAF | Configuration export or rule list PDF, dated within 30 days |
| NetworkPolicy manifest for each application namespace | Kubernetes cluster / GitOps repository | YAML files or kubectl output |
| Data flow diagram showing all ingress/egress paths | Architecture documentation | Diagram with version date |
| API gateway policy configuration | Kong, Istio, AWS API GW, or equivalent | Policy export or screenshot |
| SIEM alert rules for anomalous egress traffic | SIEM platform | Alert rule export, including last trigger date |
| WAF block/allow log sample | WAF or SIEM | Log export showing blocked requests by rule |

### Gap Documentation Template
**Control:** AC-4  
**Finding:** [Application pods in the production namespace have no egress NetworkPolicy; pods can initiate outbound TCP connections to any internet destination on any port, allowing a compromised workload to exfiltrate data or establish command-and-control channels undetected]  
**Risk:** [An attacker who compromises a single application pod can exfiltrate all data accessible to that pod — including database credentials and secrets mounted as environment variables — to any external destination without triggering any existing detection controls]  
**Recommendation:** [Deploy a default-deny egress NetworkPolicy for all production namespaces and explicitly whitelist only required external destinations; enable WAF in blocking mode on the internet-facing ingress; configure SIEM alerting on egress traffic to new or unexpected destinations]  
**Owner:** Platform/Infrastructure Security Team  

### CISO Communication
> Our application workloads currently have no restrictions on where they can send data. If an attacker were to compromise any application container — through a software vulnerability, a malicious dependency, or a stolen credential — that container could immediately begin sending sensitive data to any internet destination without triggering any existing alerts. This is the equivalent of having no locks on the outbound mail room. The fix is network-level egress controls that restrict each application to communicating only with the specific services it needs, and a Web Application Firewall that blocks malicious traffic before it reaches the application. These controls are foundational — they reduce the blast radius of any breach and are required by our compliance frameworks.

---

## Cybersecurity Engineer Perspective
> **Code access available.** Tools: kubectl, cloud CLI, SIEM queries, direct remediation.

### Assessment Commands
```bash
# Check whether any NetworkPolicies exist in the application namespace
kubectl get networkpolicy -n <app-namespace>
# If output is empty, the namespace has no traffic controls (all traffic permitted)

# Check for a default-deny policy specifically
kubectl get networkpolicy -n <app-namespace> -o json \
  | jq -r '.items[] | select(.spec.podSelector == {}) | .metadata.name'

# Check ingress resources for WAF annotations
kubectl get ingress -n <app-namespace> -o json \
  | jq -r '.items[] | {name: .metadata.name, annotations: .metadata.annotations}'

# Check for AWS WAF association on ALB ingress
kubectl get ingress -n <app-namespace> -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.metadata.annotations.alb\.ingress\.kubernetes\.io/wafv2-acl-arn}{"\n"}{end}'

# Test egress from a running pod — does it have unrestricted internet access?
# This spawns a temporary pod to test outbound connectivity
kubectl run egress-test --image=curlimages/curl:8.6.0 --restart=Never \
  -n <app-namespace> --rm -it -- \
  curl -m 5 -o /dev/null -s -w "%{http_code}" https://ifconfig.me
# Expected after remediation: connection refused or timeout — NOT a 200 response
```

### Detection / Testing
```bash
# Test whether a pod can reach an external IP (data exfil simulation)
kubectl exec -n <app-namespace> <pod-name> -- \
  curl -m 5 -o /dev/null -s -w "%{http_code}" https://example.com
# Expected after fix: exit code non-zero or timeout

# Test east-west: can a pod in namespace A reach pods in namespace B without policy?
kubectl run cross-ns-test --image=curlimages/curl:8.6.0 --restart=Never \
  -n <other-namespace> --rm -it -- \
  curl -m 5 http://<app-name>.<app-namespace>.svc.cluster.local:8080/health
# Expected after fix: connection refused (NetworkPolicy blocking cross-namespace)

# KQL — Sentinel: Detect pod egress to unexpected external IPs
AzureDiagnostics
| where Category == "NetworkSecurityGroupFlowEvent"
| where Direction == "Outbound"
| where isnotempty(PublicIPAddresses)
| where not(PublicIPAddresses has_any (split("<known_egress_ips>", ",")))
| summarize count() by IPAddresses, DestinationPort, bin(TimeGenerated, 1h)
| order by count_ desc

# SPL — Splunk: Detect anomalous egress volume from app pods (possible exfil)
index=network sourcetype=pan_traffic direction=egress
| where src_zone="kubernetes-prod" AND bytes_out > 10000000
| stats sum(bytes_out) AS total_bytes_out BY src_ip, dest_ip
| where total_bytes_out > 100000000
| sort -total_bytes_out
```

### Remediation
```bash
# Deploy a default-deny ingress AND egress NetworkPolicy for the application namespace
cat <<EOF | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: <app-namespace>
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
EOF

# Allow ingress only from the ingress-nginx namespace to app pods
cat <<EOF | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-ingress-from-nginx
  namespace: <app-namespace>
spec:
  podSelector:
    matchLabels:
      app: <app-name>
  policyTypes:
  - Ingress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: ingress-nginx
    ports:
    - protocol: TCP
      port: 8080
EOF

# Allow egress only to the database namespace and DNS (port 53)
cat <<EOF | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-egress-db-and-dns
  namespace: <app-namespace>
spec:
  podSelector:
    matchLabels:
      app: <app-name>
  policyTypes:
  - Egress
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: database
    ports:
    - protocol: TCP
      port: 5432
  - ports:
    - protocol: UDP
      port: 53
    - protocol: TCP
      port: 53
EOF

# Associate AWS WAF ACL with ALB ingress (annotate the ingress resource)
kubectl annotate ingress <app-name>-ingress -n <app-namespace> \
  alb.ingress.kubernetes.io/wafv2-acl-arn="arn:aws:wafv2:<region>:<account-id>:regional/webacl/<acl-name>/<acl-id>" \
  --overwrite
```

### Validation
```bash
# Verify the default-deny policy is present
kubectl get networkpolicy default-deny-all -n <app-namespace>
# Expected: policy exists

# Re-test egress from an app pod — should now be blocked
kubectl run egress-test-post --image=curlimages/curl:8.6.0 --restart=Never \
  -n <app-namespace> --rm -it -- \
  curl -m 5 -o /dev/null -s -w "%{http_code}" https://ifconfig.me
# Expected: curl: (28) Operation timed out — NOT 200

# Confirm WAF annotation is on the ingress
kubectl get ingress <app-name>-ingress -n <app-namespace> \
  -o jsonpath='{.metadata.annotations.alb\.ingress\.kubernetes\.io/wafv2-acl-arn}'
# Expected: full WAF ACL ARN

# Confirm app still works (health check through allowed path)
curl -o /dev/null -s -w "%{http_code}" https://<app-name>/health
# Expected: 200
```

### Evidence Capture
```bash
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
EVIDENCE_DIR="/tmp/ac4-evidence-${TIMESTAMP}"
mkdir -p "${EVIDENCE_DIR}"

# All NetworkPolicies in the namespace
kubectl get networkpolicy -n <app-namespace> -o yaml \
  > "${EVIDENCE_DIR}/networkpolicies.yaml"

# Ingress configuration including WAF annotations
kubectl get ingress -n <app-namespace> -o json \
  > "${EVIDENCE_DIR}/ingress-config.json"

# Egress test result (post-remediation)
kubectl run egress-evidence --image=curlimages/curl:8.6.0 --restart=Never \
  -n <app-namespace> --rm -- \
  sh -c 'curl -m 5 -v https://ifconfig.me 2>&1; echo "Exit: $?"' \
  > "${EVIDENCE_DIR}/egress-test-blocked.txt" 2>&1 || true

# Namespace label snapshot (for NetworkPolicy selector verification)
kubectl get namespace <app-namespace> -o json \
  | jq '{name: .metadata.name, labels: .metadata.labels}' \
  > "${EVIDENCE_DIR}/namespace-labels.json"

echo "Evidence written to ${EVIDENCE_DIR}"
ls -lh "${EVIDENCE_DIR}"
```
