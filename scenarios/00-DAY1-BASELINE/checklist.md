# Day 1 Baseline Checklist

**CSF 2.0 Coverage:** ID.AM-01, PR.PS-01, DE.CM-03, ID.RA-01, PR.AA-05
**CIS Controls:** 1.1, 4.6, 6.8, 7.5, 12.2

Work through each section in order. Run every command yourself. Note the result.
If a result does not match the expected output, write down what you actually saw.

---

## Section 1 — Cluster Health (ID.AM-01)

**Control:** NIST CSF ID.AM-01 — Hardware assets inventoried and maintained
**CIS v8:** 1.1 — Establish Enterprise Asset Inventory

---

### 1.1 Confirm cluster context

```bash
kubectl config current-context
```

**Expected output:**
```
k3d-seclab
```

**If it does not match:** Stop. Do not continue. Run `kubectl config get-contexts` to see what contexts
are available. Switch to the correct context with `kubectl config use-context k3d-seclab`.

---

### 1.2 Node count and status

```bash
kubectl get nodes -o wide
```

**Expected output:** 3 nodes, all with STATUS `Ready`. You should see one node named with `-server-0`
and two named with `-agent-0` and `-agent-1`. Kubernetes version column should show v1.31.x.

**If nodes are NotReady:** Run `kubectl describe node <node-name>` and look at the Conditions section.
Common causes: disk pressure, memory pressure, or kubelet not running.

**If fewer than 3 nodes:** The cluster did not start cleanly. Stop and notify the lab administrator.

---

### 1.3 Namespace inventory

```bash
kubectl get namespaces
```

**Expected output:** You should see at minimum these namespaces:

```
anthra       Active
falco        Active
kyverno      Active
logging      Active
monitoring   Active
```

Also expect: `default`, `kube-system`, `kube-public`, `kube-node-lease`.

**If any required namespace is missing:** The security stack or application did not deploy. Do not
continue with that section until the namespace exists.

---

### 1.4 Pods in the anthra namespace

```bash
kubectl get pods -n anthra -o wide
```

**Expected output:** 3 pods, all in `Running` state, all with READY `1/1`.

| Pod name prefix | Expected state |
|-----------------|---------------|
| portfolio-anthra-portfolio-app-api | Running 1/1 |
| portfolio-anthra-portfolio-app-ui | Running 1/1 |
| portfolio-anthra-portfolio-app-chroma | Running 1/1 |

**If a pod is in CrashLoopBackOff:** Run `kubectl logs -n anthra <pod-name> --previous` to see why it
crashed.

**If a pod is in Pending:** Run `kubectl describe pod -n anthra <pod-name>` and look at Events at the
bottom. Pending usually means resource constraints or a missing PVC.

**If 0/1 READY:** The pod started but the readiness probe is failing. Check logs with
`kubectl logs -n anthra <pod-name>`.

---

## Section 2 — Security Stack (DE.CM-03)

**Control:** NIST CSF DE.CM-03 — Personnel activity monitored
**CIS v8:** 6.8 — Manage Audit Log Storage

---

### 2.1 Falco status

```bash
kubectl get pods -n falco -o wide
```

**Expected output:** At least one pod with name starting `falco-` in `Running` state with READY `1/1`.
Falco runs as a DaemonSet, so you should see one pod per node (3 pods for a 3-node cluster).

**If Falco is not running:** Runtime threat detection is offline. Any kernel-level attacks that happen
during this session will not be detected. Note this in the Pre-Existing Issues section of your report.

**Verify Falco is producing events:**

```bash
kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=20 2>/dev/null || \
kubectl logs -n falco -l app=falco --tail=20
```

**Expected output:** JSON log lines or structured output showing rule matches or startup messages like
`Starting Falco` or `Loading rules`. If you see `No output` or nothing at all, Falco may have started
but is not logging correctly.

---

### 2.2 Kyverno status

```bash
kubectl get pods -n kyverno -o wide
```

**Expected output:** At least one pod named `kyverno-` in `Running` state.

**Check Kyverno policy count:**

```bash
kubectl get clusterpolicies -A 2>/dev/null | wc -l
```

**Expected output:** A number greater than 1 (the header line plus at least one policy). If you see
only `1` or `0`, no Kyverno policies are loaded.

**Check Kyverno enforcement mode on loaded policies:**

```bash
kubectl get clusterpolicies -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.validationFailureAction}{"\n"}{end}'
```

**Expected output:** Each line shows a policy name and its enforcement mode. Values will be `Enforce`
or `Audit`.

- `Enforce` means Kyverno will block a violating deployment from being admitted.
- `Audit` means Kyverno will log the violation but allow the deployment through.

Write down which policies are in Audit mode. Audit mode policies do not stop bad deployments.
This is a finding if critical policies (e.g., require-non-root, require-resource-limits) are in Audit.

---

### 2.3 Fluent Bit status

```bash
kubectl get pods -n logging -o wide
```

**Expected output:** One or more pods with name starting `fluent-bit-` in `Running` state. Fluent Bit
runs as a DaemonSet, so expect one pod per node.

**If Fluent Bit is not running:** Container logs are not being shipped. If a scenario triggers alerts
that are expected to appear in the log aggregator, they will not be there.

---

### 2.4 Prometheus and Grafana status

```bash
kubectl get pods -n monitoring -o wide
```

**Expected output:** Pods for Prometheus and Grafana in `Running` state. You should see at minimum:

| Pod name prefix | Expected state |
|-----------------|---------------|
| prometheus-* | Running 1/1 or 2/2 |
| grafana-* | Running 1/1 |

**If Prometheus is down:** Metrics are not being collected. Some scenario detection steps rely on
Prometheus alert rules.

---

## Section 3 — Application Security (PR.PS-01)

**Control:** NIST CSF PR.PS-01 — Configuration management practices established
**CIS v8:** 4.6 — Securely configure enterprise assets

---

### 3.1 Security context on anthra pods

Run this for each of the three application deployments:

```bash
kubectl get pod -n anthra -l app.kubernetes.io/name=portfolio-app-api \
  -o jsonpath='{.items[0].spec.containers[0].securityContext}' | python3 -m json.tool
```

```bash
kubectl get pod -n anthra -l app.kubernetes.io/name=portfolio-app-ui \
  -o jsonpath='{.items[0].spec.containers[0].securityContext}' | python3 -m json.tool
```

```bash
kubectl get pod -n anthra -l app.kubernetes.io/name=portfolio-app-chroma \
  -o jsonpath='{.items[0].spec.containers[0].securityContext}' | python3 -m json.tool
```

**Expected output for a well-configured pod:**

```json
{
    "allowPrivilegeEscalation": false,
    "capabilities": {
        "drop": ["ALL"]
    },
    "readOnlyRootFilesystem": true,
    "runAsNonRoot": true
}
```

**What to look for:**

| Field | Secure value | Finding if missing |
|-------|-------------|-------------------|
| runAsNonRoot | true | Container may run as root |
| allowPrivilegeEscalation | false | Container can gain privileges |
| readOnlyRootFilesystem | true | Container can write to root filesystem |
| capabilities.drop | ["ALL"] | Container retains Linux capabilities |

Write down which fields are missing for each pod.

---

### 3.2 NetworkPolicies in anthra namespace

```bash
kubectl get networkpolicies -n anthra
```

**Expected output:** One or more NetworkPolicy resources listed.

**If no NetworkPolicies exist:** All pods in the namespace can communicate freely with any other pod
in the cluster. This is a finding.

**Inspect the NetworkPolicy details:**

```bash
kubectl describe networkpolicies -n anthra
```

Look for:
- Is there a policy that restricts ingress to only expected sources?
- Is there a policy that restricts egress to only expected destinations?
- Is there a default-deny policy?

**A default-deny policy** looks like this in the output — it has no `podSelector` match rules and
blocks all traffic:

```
PodSelector:     <none> (Pods in the policy's namespace)
PolicyTypes:     Ingress, Egress
```

Note whether default-deny is present.

---

### 3.3 Service types in anthra namespace

```bash
kubectl get services -n anthra
```

**Expected output:** Services should be of type `ClusterIP` (internal only) unless there is a
specific reason for `NodePort` or `LoadBalancer`.

**Finding if you see:** `NodePort` or `LoadBalancer` on internal application services. These expose
the service outside the cluster without going through a proper ingress controller.

---

### 3.4 Service account token automount

```bash
kubectl get pods -n anthra -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.automountServiceAccountToken}{"\n"}{end}'
```

**Expected output:** Each pod listed with `false` (automount disabled).

```
portfolio-anthra-portfolio-app-api-xxxxx    false
portfolio-anthra-portfolio-app-ui-xxxxx     false
portfolio-anthra-portfolio-app-chroma-xxxxx false
```

**If you see `true` or blank (blank defaults to true):** The pod is automatically mounting a
Kubernetes API token into its filesystem. If the application is compromised, an attacker can use that
token to call the Kubernetes API. This is a finding.

---

## Section 4 — Vulnerability Posture (ID.RA-01)

**Control:** NIST CSF ID.RA-01 — Vulnerabilities identified and documented
**CIS v8:** 7.5 — Perform automated patch management

---

### 4.1 Trivy image scan

Get the image names currently running:

```bash
kubectl get pods -n anthra -o jsonpath='{range .items[*]}{.spec.containers[*].image}{"\n"}{end}'
```

Run trivy against each image. Replace `<image>` with the full image:tag from the output above:

```bash
trivy image --severity HIGH,CRITICAL <image>
```

**Expected output:** A table of CVEs. You are not expected to fix anything today. You are documenting
the starting vulnerability count.

Record for each image:
- Total CRITICAL CVEs
- Total HIGH CVEs
- Highest CVE ID (most severe)

**If trivy is not found:** Run `which trivy`. If not on path, check `/usr/local/bin/trivy`.

---

### 4.2 kube-bench cluster configuration scan

```bash
kube-bench run --targets node 2>/dev/null | tail -30
```

**Expected output:** A summary section at the bottom showing PASS, FAIL, WARN, and INFO counts.

Example summary format:
```
== Summary ==
41 checks PASS
13 checks FAIL
11 checks WARN
0 checks INFO
```

Record the PASS/FAIL/WARN counts. Do not attempt to remediate today. This is the baseline.

**If kube-bench is not found:** Run `which kube-bench`. If missing, note it in the report as a tool
gap.

---

### 4.3 Kubescape security score

```bash
kubescape scan --format pretty-printer 2>/dev/null | tail -40
```

**Expected output:** A compliance score percentage and a breakdown by framework (NSA, MITRE, etc.).

Example:
```
Overall risk-score (lower is better): 45%
```

Record the overall risk score. A score above 50% indicates significant misconfiguration.

**If kubescape is not found:** Run `which kubescape`. If missing, note it in the report.

---

## Section 5 — RBAC (PR.AA-05)

**Control:** NIST CSF PR.AA-05 — Access permissions managed with principle of least privilege
**CIS v8:** 12.2 — Implement Privileged Access Management

---

### 5.1 Cluster-admin bindings

```bash
kubectl get clusterrolebindings -o json | \
  python3 -c "
import json, sys
data = json.load(sys.stdin)
for item in data['items']:
  if item.get('roleRef', {}).get('name') == 'cluster-admin':
    for sub in item.get('subjects', []):
      print(f\"{item['metadata']['name']}: {sub.get('kind','?')} / {sub.get('name','?')} in {sub.get('namespace','cluster')}\")
"
```

**Expected output:** A short list of bindings. System-level bindings are expected:

```
cluster-admin: User / kubernetes-admin in cluster
system:masters: Group / system:masters in cluster
```

**Finding if you see:** A `ServiceAccount` bound to `cluster-admin`, or a user/group that is not a
known system identity. ServiceAccounts with cluster-admin have full control over the cluster.

---

### 5.2 Wildcard roles (overly permissive RBAC)

```bash
kubectl get clusterroles -o json | \
  python3 -c "
import json, sys
data = json.load(sys.stdin)
for item in data['items']:
  name = item['metadata']['name']
  if name.startswith('system:'):
    continue
  for rule in item.get('rules', []):
    if '*' in rule.get('verbs', []) or '*' in rule.get('resources', []):
      print(f\"{name}: verbs={rule.get('verbs',[])} resources={rule.get('resources',[])} apiGroups={rule.get('apiGroups',[])}\"  )
"
```

**Expected output:** No output, or only expected system roles.

**Finding if you see:** Custom ClusterRoles (not prefixed with `system:`) that have wildcard (`*`)
verbs or resources. These grant broad permissions and violate least privilege.

---

### 5.3 Service account permissions in anthra namespace

```bash
kubectl get rolebindings -n anthra -o wide
```

**Expected output:** Zero or minimal bindings. The application service account should not need
Kubernetes API access. If you see bindings granting `edit`, `admin`, or custom roles to application
service accounts, that is a finding.

---

## Checklist Complete

Once you have run every command in every section, move to the report template:

```
scenarios/00-DAY1-BASELINE/baseline-report-template.md
```

Fill in every table row. No blanks. Sign and date.
