# AC-17: Remote Access
**Family:** Access Control  
**NIST 800-53 Rev 5**  
**Layer:** Application (L7)

## Control Statement
The organization establishes and documents usage restrictions, configuration requirements, and implementation guidance for each type of remote access allowed, and authorizes each type of remote access prior to allowing connections.

## Why It Matters at L7
At the application layer, "remote access" includes more than VPN — it covers `kubectl exec` into production pods, remote debug ports left open in container images (JVM debug port 5005, Node.js inspector 9229, Python debugpy 5678), and administrative consoles exposed without MFA. These are high-value targets because they provide interactive access to running workloads and are frequently overlooked in production hardening reviews. An open debug port is a direct shell into the application process.

---

## GRC Analyst Perspective
> **No code access.** Tools: interviews, documentation review, SIEM dashboards, audit reports, evidence packages.

### Audit Questions
- Is `kubectl exec`, `kubectl attach`, and `kubectl port-forward` access logged in the Kubernetes audit log, and are those logs forwarded to the SIEM with alerting on production namespace access?
- Are remote debug ports (JVM 5005, Node.js 9229, Python 5678, Ruby 1234) explicitly disabled or absent in all production container images and Kubernetes manifests?
- Does the organization require MFA for all administrative console access — including Kubernetes dashboard, ArgoCD, Grafana, Kibana, and any other management plane?
- Is there a documented and enforced policy prohibiting direct interactive access to production pods except during declared incidents with change management approval?
- Are privileged remote access sessions (exec into pods, SSH to nodes) recorded or audited with sufficient detail to reconstruct what actions were taken?
- Is access to the Kubernetes API server restricted by IP allowlist or private network boundary, preventing public internet access to `kubectl`?
- When an incident requires emergency remote access to production, is there a documented break-glass procedure with post-incident review?

### Evidence to Request
| Evidence Item | Source | Acceptable Format |
|---|---|---|
| Kubernetes audit policy configuration | Kubernetes API server config / cluster admin | YAML policy file or documentation showing audit levels |
| SIEM alert rules for kubectl exec/attach events in production | SIEM platform | Alert rule export with last trigger timestamp |
| MFA enforcement evidence for admin consoles (ArgoCD, Grafana, K8s dashboard) | IdP / SSO configuration | Screenshot or configuration export showing MFA requirement |
| Container image scan confirming no debug ports exposed | Trivy or Dockerfile review | Scan report or Dockerfile showing no EXPOSE for debug ports |
| Kubernetes API server access restriction (IP allowlist or private endpoint) | Cloud provider network config | VPC/security group config or kubeconfig showing private endpoint |
| Break-glass access procedure documentation | Policy or runbook repository | Documented procedure with approval and review requirements |

### Gap Documentation Template
**Control:** AC-17  
**Finding:** [Production container images expose JVM debug port 5005 via EXPOSE directive in the Dockerfile, and three Kubernetes deployments define containerPort 5005; no Kubernetes audit log forwarding to SIEM is configured, meaning exec/attach events in production are not monitored]  
**Risk:** [Any user with network access to the cluster can attach a debugger to the production JVM process, enabling inspection and modification of runtime state including in-memory secrets and credentials; absence of audit logging means such access would be completely undetected]  
**Recommendation:** [Remove EXPOSE 5005 and all debug port definitions from production Dockerfiles and deployment manifests; configure Kubernetes audit policy to log exec/attach/portforward at RequestResponse level; create SIEM alert for any exec event in the production namespace]  
**Owner:** Application Development Lead / Platform Security Team  

### CISO Communication
> Several of our production application containers are currently configured with remote debug ports open — features intended for developer troubleshooting that were never disabled before deployment to production. An open debug port gives anyone with network access to the cluster the ability to attach directly to the running application process and inspect or modify its behavior in real time, including reading secrets from memory. Separately, interactive access to production containers via `kubectl exec` is not being logged, so we have no audit trail of who has accessed production workloads or what they did. Fixing the debug ports is a configuration change in the build process. Fixing the audit trail requires enabling Kubernetes audit logging and forwarding those logs to our SIEM. Both are required for compliance and represent foundational visibility gaps.

---

## Cybersecurity Engineer Perspective
> **Code access available.** Tools: kubectl, cloud CLI, SIEM queries, direct remediation.

### Assessment Commands
```bash
# Check for debug ports exposed in running pod specs
kubectl get pods -n <app-namespace> -o json \
  | jq -r '.items[] | .metadata.name as $pod | .spec.containers[] | .ports[]? | select(.containerPort | IN(5005, 9229, 5678, 1234, 4004, 8787)) | "\($pod): DEBUG PORT \(.containerPort) EXPOSED"'

# Check for debug port environment variables that activate debuggers
kubectl get pods -n <app-namespace> -o json \
  | jq -r '.items[] | .metadata.name as $pod | .spec.containers[] | .env[]? | select(.name | test("DEBUG|JPDA|JDWP|NODE_DEBUG|DEBUGPY"; "i")) | "\($pod): \(.name)=\(.value // .valueFrom)"'

# Check Kubernetes audit policy (look for exec/attach coverage)
# On managed clusters (EKS), check via AWS CLI
aws eks describe-cluster --name <cluster-name> \
  --query 'cluster.logging.clusterLogging[?enabled==`true`].types' --output json

# For self-managed: check audit policy file
kubectl get cm -n kube-system audit-policy -o yaml 2>/dev/null || \
  echo "Audit policy not found as ConfigMap — check API server flags"

# Check if Kubernetes dashboard is exposed externally
kubectl get svc -n kubernetes-dashboard 2>/dev/null
kubectl get ingress -n kubernetes-dashboard 2>/dev/null

# Check ArgoCD exposure and auth settings
kubectl get svc -n argocd argocd-server -o jsonpath='{.spec.type}'
kubectl get ingress -n argocd -o json \
  | jq -r '.items[] | {name: .metadata.name, host: .spec.rules[].host, annotations: .metadata.annotations}'
```

### Detection / Testing
```bash
# Test whether debug port is reachable from within the cluster
kubectl run debug-port-test --image=curlimages/curl:8.6.0 --restart=Never \
  -n <app-namespace> --rm -it -- \
  curl -m 3 http://<pod-ip>:5005
# Expected after fix: connection refused

# KQL — Sentinel: Alert on kubectl exec/attach/portforward to production pods
AuditLogs
| where OperationName in ("pod/exec", "pod/attach", "pod/portforward")
| where ResponseStatus has "201"
| extend Namespace = tostring(split(ObjectId, "/")[0])
| where Namespace == "<app-namespace>"
| project TimeGenerated, User=InitiatedBy.user.userPrincipalName, OperationName, ObjectId, ClientIPAddress=tostring(CallerIPAddress)
| order by TimeGenerated desc

# SPL — Splunk: Detect exec into production pods (Kubernetes audit log)
index=k8s_audit sourcetype=kubernetes:audit
| where verb IN ("create") AND resource="pods" AND subresource IN ("exec","attach","portforward")
| where namespace="<app-namespace>"
| stats count BY user.username, objectRef.name, requestURI, sourceIPs{}
| sort -count

# Check for any active port-forward sessions against app pods
kubectl get events -n <app-namespace> \
  --field-selector reason=PortForwardStarted 2>/dev/null
```

### Remediation
```bash
# Remove debug port from deployment spec if containerPort 5005 is defined
kubectl patch deployment <app-name> -n <app-namespace> --type='json' -p='[
  {
    "op": "remove",
    "path": "/spec/template/spec/containers/0/ports/0"
  }
]'
# Note: adjust the path index to match the specific port entry to remove

# Apply a NetworkPolicy to explicitly deny traffic to known debug ports
cat <<EOF | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-debug-ports
  namespace: <app-namespace>
spec:
  podSelector:
    matchLabels:
      app: <app-name>
  policyTypes:
  - Ingress
  ingress:
  - ports:
    - protocol: TCP
      port: 8080
    # Only the application port is allowed — debug ports implicitly denied by default-deny policy
EOF

# Enable EKS control plane logging for audit events (if using EKS)
aws eks update-cluster-config \
  --name <cluster-name> \
  --logging '{"clusterLogging":[{"types":["api","audit","authenticator","controllerManager","scheduler"],"enabled":true}]}'

# Annotate production namespace to flag it for exec alerting
kubectl label namespace <app-namespace> \
  security.company.com/exec-alerting=enabled \
  --overwrite
```

### Validation
```bash
# Confirm no debug ports in pod spec
kubectl get pods -n <app-namespace> -o json \
  | jq -r '.items[] | .metadata.name as $pod | .spec.containers[] | .ports[]? | select(.containerPort | IN(5005, 9229, 5678)) | "\($pod): \(.containerPort)"'
# Expected: empty output

# Confirm EKS audit logging is enabled
aws eks describe-cluster --name <cluster-name> \
  --query 'cluster.logging.clusterLogging[?enabled==`true`].types[]' \
  --output json
# Expected: includes "audit"

# Attempt debug port connection — should be refused
kubectl run val-debug-test --image=curlimages/curl:8.6.0 --restart=Never \
  -n <app-namespace> --rm -- \
  curl -m 3 http://<pod-ip>:5005 2>&1 || echo "Connection refused - PASS"
# Expected: connection refused or timeout

# Confirm application still responds on legitimate port
kubectl exec -n <app-namespace> <pod-name> -- \
  wget -qO- http://localhost:8080/health
# Expected: {"status":"ok"} or equivalent health response
```

### Evidence Capture
```bash
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
EVIDENCE_DIR="/tmp/ac17-evidence-${TIMESTAMP}"
mkdir -p "${EVIDENCE_DIR}"

# Pod port inventory — confirms no debug ports
kubectl get pods -n <app-namespace> -o json \
  | jq '[.items[] | {pod: .metadata.name, ports: [.spec.containers[].ports[]? | {containerPort: .containerPort, protocol: .protocol}]}]' \
  > "${EVIDENCE_DIR}/pod-port-inventory.json"

# EKS audit logging status
aws eks describe-cluster --name <cluster-name> \
  --query 'cluster.logging' --output json \
  > "${EVIDENCE_DIR}/eks-audit-logging-status.json" 2>/dev/null || \
  echo "Non-EKS cluster — check audit policy separately" \
  > "${EVIDENCE_DIR}/eks-audit-logging-status.txt"

# Kubernetes audit policy (if accessible)
kubectl get cm -n kube-system audit-policy -o yaml \
  > "${EVIDENCE_DIR}/k8s-audit-policy.yaml" 2>/dev/null || \
  echo "Audit policy not stored as ConfigMap" \
  > "${EVIDENCE_DIR}/k8s-audit-policy.txt"

# Ingress and service exposure for admin tools
kubectl get svc,ingress -n argocd -o json \
  > "${EVIDENCE_DIR}/argocd-exposure.json" 2>/dev/null || true
kubectl get svc,ingress -n kubernetes-dashboard -o json \
  > "${EVIDENCE_DIR}/k8s-dashboard-exposure.json" 2>/dev/null || true

# NetworkPolicy confirming debug port deny
kubectl get networkpolicy deny-debug-ports -n <app-namespace> -o yaml \
  > "${EVIDENCE_DIR}/deny-debug-ports-policy.yaml" 2>/dev/null || true

echo "Evidence written to ${EVIDENCE_DIR}"
ls -lh "${EVIDENCE_DIR}"
```
