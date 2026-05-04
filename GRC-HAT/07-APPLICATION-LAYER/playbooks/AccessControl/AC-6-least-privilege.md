# AC-6: Least Privilege
**Family:** Access Control  
**NIST 800-53 Rev 5**  
**Layer:** Application (L7)

## Control Statement
The organization employs the principle of least privilege, allowing only authorized accesses for users and processes which are necessary to accomplish assigned tasks in accordance with organizational missions and business functions.

## Why It Matters at L7
At the application layer, least privilege governs what a running container process is actually permitted to do on the host and within the cluster. A container running as root with all Linux capabilities can break out of its isolation boundary. A service account with wildcard RBAC permissions can read secrets from other namespaces. A pod with `privileged: true` is equivalent to having root on the node. These are not hypothetical risks — they are the documented exploitation path in the majority of Kubernetes container escape incidents.

---

## GRC Analyst Perspective
> **No code access.** Tools: interviews, documentation review, SIEM dashboards, audit reports, evidence packages.

### Audit Questions
- Do application containers run as non-root users? Is this enforced by policy (Kyverno, OPA Gatekeeper, Pod Security Standards) or only by convention?
- Have all container images been reviewed to confirm they do not require privileged mode or the addition of Linux capabilities beyond the minimal required set?
- Are Kubernetes service account RBAC permissions scoped to the minimum required for each workload? Are there any service accounts with wildcard (`*`) permissions or cluster-admin binding?
- Is there a Pod Security Standards (PSS) baseline or restricted profile enforced at the namespace or cluster level?
- Has a CIS Kubernetes Benchmark scan been conducted? What were the findings related to pod security and RBAC?
- Are Kubernetes secrets accessed only by the specific workloads that require them, or are broad secret-read permissions granted to service accounts?
- Is there a process for reviewing and approving any exception to least-privilege policy (e.g., a workload that legitimately requires elevated permissions)?

### Evidence to Request
| Evidence Item | Source | Acceptable Format |
|---|---|---|
| CIS Kubernetes Benchmark scan report | kube-bench or equivalent | HTML or JSON report, dated within 90 days |
| Pod Security Standards enforcement level per namespace | Kubernetes cluster | kubectl output or namespace configuration export |
| Service account RBAC role bindings with permission listing | Kubernetes cluster | kubectl output or RBAC audit tool report |
| Container image scan report showing running user and capabilities | Trivy or equivalent | JSON or HTML report, dated within 30 days |
| Kyverno or OPA policy list enforcing runAsNonRoot and drop ALL capabilities | GitOps repository or cluster | Policy YAML files |
| Exception register for workloads with elevated privileges | GRC platform or change management | Dated approval records with business justification |

### Gap Documentation Template
**Control:** AC-6  
**Finding:** [12 of 18 production application pods run as root (UID 0) with no capability restrictions; 3 pods have privileged: true set in the container security context, and no Pod Security Standards policy is enforced on the production namespace]  
**Risk:** [A container escape vulnerability in any of these workloads gives an attacker root-level access to the underlying Kubernetes node, compromising all other workloads on that node and potentially the entire cluster through subsequent lateral movement]  
**Recommendation:** [Enforce the Kubernetes Pod Security Standards "restricted" profile on the production namespace; update Dockerfiles to use non-root users; implement Kyverno policies to block deployment of containers with privileged: true or runAsRoot: true; conduct Trivy image scanning in CI pipeline]  
**Owner:** Platform Engineering / DevSecOps Team  

### CISO Communication
> A significant portion of our application workloads are currently running with more system access than they need — in some cases, running as the system administrator equivalent inside their containers. If an attacker exploits a vulnerability in one of these applications, they gain the highest level of access to the underlying server infrastructure, not just to the application itself. This significantly amplifies the blast radius of any breach. The remediation is a configuration change to how our containers are deployed — requiring each container to run as a limited, non-privileged user — combined with an automated policy that prevents any future deployment from regressing to this state. This is a high-priority, low-cost fix that directly reduces our risk of a complete infrastructure compromise.

---

## Cybersecurity Engineer Perspective
> **Code access available.** Tools: kubectl, cloud CLI, SIEM queries, direct remediation.

### Assessment Commands
```bash
# Find all pods running as root (runAsUser: 0 or no runAsNonRoot: true)
kubectl get pods -n <app-namespace> -o json \
  | jq -r '.items[] | {
      pod: .metadata.name,
      runAsUser: (.spec.securityContext.runAsUser // "NOT SET"),
      runAsNonRoot: (.spec.securityContext.runAsNonRoot // "NOT SET"),
      containers: [.spec.containers[] | {
          name: .name,
          runAsUser: (.securityContext.runAsUser // "NOT SET"),
          runAsNonRoot: (.securityContext.runAsNonRoot // "NOT SET"),
          privileged: (.securityContext.privileged // false),
          capabilities: (.securityContext.capabilities // "NOT SET")
      }]
  }' | jq .

# Find pods with privileged: true
kubectl get pods -n <app-namespace> -o json \
  | jq -r '.items[] | select(.spec.containers[].securityContext.privileged == true) | .metadata.name'

# Find pods missing readOnlyRootFilesystem
kubectl get pods -n <app-namespace> -o json \
  | jq -r '.items[] | .metadata.name as $pod | .spec.containers[] | select(.securityContext.readOnlyRootFilesystem != true) | "\($pod)/\(.name): readOnlyRootFilesystem NOT enforced"'

# Check service account RBAC permissions for the app's SA
kubectl auth can-i --list --as=system:serviceaccount:<app-namespace>:<app-name>-sa

# Check for wildcard permissions in roles bound to the namespace
kubectl get rolebindings,clusterrolebindings -n <app-namespace> -o json \
  | jq -r '.. | .rules? // empty | .[] | select(.verbs[] == "*" or .resources[] == "*") | .'

# Run kube-bench CIS benchmark (if installed)
kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job.yaml
kubectl logs -f job/kube-bench
```

### Detection / Testing
```bash
# Run Trivy to scan running images for root user and missing security contexts
trivy image --severity HIGH,CRITICAL \
  $(kubectl get pod <pod-name> -n <app-namespace> -o jsonpath='{.spec.containers[0].image}') \
  --format json > /tmp/trivy-ac6-scan.json

# Check if PSS is enforced on the namespace
kubectl get namespace <app-namespace> -o jsonpath='{.metadata.labels}'
# Expected: pod-security.kubernetes.io/enforce=restricted or baseline

# Attempt to exec into a pod and check effective UID (should NOT be 0)
kubectl exec -n <app-namespace> <pod-name> -- id
# Expected: uid=1000 (or non-zero) — FAIL if uid=0

# Check for host path mounts (privilege escalation path)
kubectl get pods -n <app-namespace> -o json \
  | jq -r '.items[] | .metadata.name as $pod | .spec.volumes[]? | select(.hostPath != null) | "\($pod): hostPath mount: \(.hostPath.path)"'

# KQL — Sentinel: Detect container exec to privileged pods
AuditLogs
| where OperationName == "pod/exec"
| where ResponseStatus has "200"
| extend PodName = tostring(ObjectId)
| join kind=inner (
    KubeNodeInventory
    | where Labels has "privileged=true"
) on $left.PodName == $right.Name
| project TimeGenerated, User, PodName, Namespace

# SPL — Splunk: Detect privilege escalation attempt from container
index=falco sourcetype=falco_alert
| where rule_name IN ("Launch Privileged Container","Container Run as Root User","Write below root")
| stats count BY rule_name, container_name, namespace, user
| sort -count
```

### Remediation
```bash
# Enforce Pod Security Standards on the namespace (restricted profile)
kubectl label namespace <app-namespace> \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/enforce-version=latest \
  pod-security.kubernetes.io/warn=restricted \
  pod-security.kubernetes.io/warn-version=latest \
  --overwrite

# Apply a Kyverno policy to require non-root and drop ALL capabilities
cat <<EOF | kubectl apply -f -
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-non-root-containers
spec:
  validationFailureAction: Enforce
  background: true
  rules:
  - name: check-runAsNonRoot
    match:
      any:
      - resources:
          kinds:
          - Pod
          namespaces:
          - <app-namespace>
    validate:
      message: "Containers must run as non-root and drop ALL capabilities."
      pattern:
        spec:
          containers:
          - securityContext:
              runAsNonRoot: true
              allowPrivilegeEscalation: false
              capabilities:
                drop:
                - ALL
              readOnlyRootFilesystem: true
EOF

# Patch the application deployment to add security context
kubectl patch deployment <app-name> -n <app-namespace> --type='json' -p='[
  {
    "op": "add",
    "path": "/spec/template/spec/securityContext",
    "value": {
      "runAsNonRoot": true,
      "runAsUser": 1000,
      "fsGroup": 2000,
      "seccompProfile": {"type": "RuntimeDefault"}
    }
  },
  {
    "op": "add",
    "path": "/spec/template/spec/containers/0/securityContext",
    "value": {
      "allowPrivilegeEscalation": false,
      "readOnlyRootFilesystem": true,
      "capabilities": {"drop": ["ALL"]}
    }
  }
]'
```

### Validation
```bash
# Confirm pods are now running as non-root
kubectl get pods -n <app-namespace> -o json \
  | jq -r '.items[] | .metadata.name as $pod | .spec.containers[] | "\($pod)/\(.name): runAsNonRoot=\(.securityContext.runAsNonRoot // false)"'
# Expected: all entries show runAsNonRoot=true

# Confirm PSS label is applied
kubectl get namespace <app-namespace> -o jsonpath='{.metadata.labels.pod-security\.kubernetes\.io/enforce}'
# Expected: restricted

# Confirm no pods have privileged: true
kubectl get pods -n <app-namespace> -o json \
  | jq -r '[.items[] | select(.spec.containers[].securityContext.privileged == true) | .metadata.name]'
# Expected: empty array []

# Try to deploy a privileged pod — Kyverno should block it
kubectl run priv-test --image=nginx:1.25 --restart=Never -n <app-namespace> \
  --overrides='{"spec":{"containers":[{"name":"priv-test","image":"nginx:1.25","securityContext":{"privileged":true}}]}}'
# Expected: Error from Kyverno — admission webhook denied
```

### Evidence Capture
```bash
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
EVIDENCE_DIR="/tmp/ac6-evidence-${TIMESTAMP}"
mkdir -p "${EVIDENCE_DIR}"

# Security context snapshot for all pods
kubectl get pods -n <app-namespace> -o json \
  | jq '[.items[] | {pod: .metadata.name, securityContext: .spec.securityContext, containers: [.spec.containers[] | {name: .name, securityContext: .securityContext}]}]' \
  > "${EVIDENCE_DIR}/pod-security-contexts.json"

# Namespace PSS labels
kubectl get namespace <app-namespace> -o json \
  | jq '{name: .metadata.name, labels: .metadata.labels}' \
  > "${EVIDENCE_DIR}/namespace-pss-labels.json"

# Kyverno policies in effect
kubectl get clusterpolicy -o yaml \
  > "${EVIDENCE_DIR}/kyverno-policies.yaml"

# RBAC permissions for app service account
kubectl auth can-i --list --as=system:serviceaccount:<app-namespace>:<app-name>-sa \
  > "${EVIDENCE_DIR}/sa-rbac-permissions.txt"

# Trivy image scan
trivy image \
  $(kubectl get pod -n <app-namespace> -l app=<app-name> -o jsonpath='{.items[0].spec.containers[0].image}') \
  --format json --output "${EVIDENCE_DIR}/trivy-image-scan.json"

echo "Evidence written to ${EVIDENCE_DIR}"
ls -lh "${EVIDENCE_DIR}"
```
