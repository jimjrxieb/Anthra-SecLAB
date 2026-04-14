# L7-03 — Investigate: CIS Benchmark Findings

## Objective

You have run kube-bench and kubescape. You have a list of FAIL findings. Now
you need to:

1. Count failures by section
2. Identify the top 5 highest-risk findings
3. Check which findings already have compensating controls
4. Classify and rank the scenario
5. Decide: fix now, document as POA&M, or accept

---

## Step 1: Count FAIL findings by kube-bench section

kube-bench output is organized by section number. Count failures per section to
understand where the cluster is weakest.

```bash
BENCH_FILE=$(ls /tmp/kube-bench-*.txt 2>/dev/null | tail -1)

echo "=== FAIL counts by section ==="
echo "Section 1 (Control Plane):"
grep "^\[FAIL\] 1\." "${BENCH_FILE}" | wc -l

echo "Section 2 (etcd):"
grep "^\[FAIL\] 2\." "${BENCH_FILE}" | wc -l

echo "Section 3 (Control Plane Config):"
grep "^\[FAIL\] 3\." "${BENCH_FILE}" | wc -l

echo "Section 4 (Worker Nodes):"
grep "^\[FAIL\] 4\." "${BENCH_FILE}" | wc -l

echo "Section 5 (Policies):"
grep "^\[FAIL\] 5\." "${BENCH_FILE}" | wc -l

echo ""
echo "=== All FAIL findings ==="
grep "^\[FAIL\]" "${BENCH_FILE}"
```

On a k3s cluster, sections 1-3 findings are often WARN rather than FAIL because
k3s manages these components differently than upstream Kubernetes. Section 4
(kubelet) and section 5 (policies) are the ones that will have real FAIL entries.

---

## Step 2: Identify the top 5 highest-risk findings

These are the findings that matter most in a real attack scenario. Check each
one against the cluster.

### Finding 1: Pods running as root (CIS 5.2.6, kubescape C-0013)

```bash
# Check each Portfolio deployment
for DEPLOY in portfolio-anthra-portfolio-app-api \
              portfolio-anthra-portfolio-app-ui \
              portfolio-anthra-portfolio-app-chroma; do
  echo "--- ${DEPLOY} ---"
  kubectl get deployment "${DEPLOY}" -n anthra \
    -o jsonpath='runAsNonRoot: {.spec.template.spec.securityContext.runAsNonRoot}{"\n"}runAsUser: {.spec.template.spec.securityContext.runAsUser}{"\n"}' \
    2>/dev/null
done
```

Risk: A process running as root inside a container has UID 0. If the container
escapes (kernel vulnerability, misconfigured mount), the attacker is root on
the node.

### Finding 2: Privilege escalation not blocked (CIS 5.2.5, kubescape C-0016)

```bash
for DEPLOY in portfolio-anthra-portfolio-app-api \
              portfolio-anthra-portfolio-app-ui \
              portfolio-anthra-portfolio-app-chroma; do
  echo "--- ${DEPLOY} ---"
  kubectl get deployment "${DEPLOY}" -n anthra \
    -o jsonpath='allowPrivilegeEscalation: {.spec.template.spec.containers[0].securityContext.allowPrivilegeEscalation}{"\n"}' \
    2>/dev/null
done
```

Risk: `allowPrivilegeEscalation: true` (or unset, which defaults to true) means
a process inside the container can call `setuid` to gain more privileges. This is
a direct path to privilege escalation if a vulnerability is present.

### Finding 3: No NetworkPolicy (CIS 5.3.2, kubescape C-0030)

```bash
kubectl get networkpolicy -n anthra
```

Risk: Without NetworkPolicy, every pod in the namespace can reach every other
pod. A compromised chroma instance can freely query the API. A compromised API
can scan the entire cluster network. Defense-in-depth requires segmentation.

### Finding 4: No Pod Security Standards enforcement (CIS 5.2.1)

```bash
kubectl get namespace anthra -o jsonpath='{.metadata.labels}' | python3 -m json.tool 2>/dev/null \
  || kubectl get namespace anthra --show-labels
```

Risk: Without PSS labels, the namespace will admit pods that violate any of the
above security context requirements. A developer can deploy a privileged container
and the cluster will not block it. PSS is the cluster-level enforcement layer.

### Finding 5: Resource limits not set (CIS 5.7.4, kubescape C-0044)

```bash
for DEPLOY in portfolio-anthra-portfolio-app-api \
              portfolio-anthra-portfolio-app-ui \
              portfolio-anthra-portfolio-app-chroma; do
  echo "--- ${DEPLOY} ---"
  kubectl get deployment "${DEPLOY}" -n anthra \
    -o jsonpath='CPU limit: {.spec.template.spec.containers[0].resources.limits.cpu}{"\n"}Memory limit: {.spec.template.spec.containers[0].resources.limits.memory}{"\n"}' \
    2>/dev/null
done
```

Risk: No resource limits means a single misbehaving or compromised container can
consume all available CPU and memory on the node, causing a denial-of-service
against all other workloads on that node.

---

## Step 3: Check for compensating controls

Before classifying a finding as unmitigated, verify whether an existing policy
or control already addresses it.

```bash
# Check Kyverno cluster policies
kubectl get clusterpolicy 2>/dev/null || echo "No Kyverno ClusterPolicies found"

# Check namespace-scoped Kyverno policies
kubectl get policy -n anthra 2>/dev/null || echo "No Kyverno Policies in anthra"

# Check OPA Gatekeeper constraints
kubectl get constraints 2>/dev/null || echo "No Gatekeeper constraints found"

# Check LimitRange (compensates for missing per-pod resource limits)
kubectl get limitrange -n anthra 2>/dev/null || echo "No LimitRange in anthra"

# Check ResourceQuota
kubectl get resourcequota -n anthra 2>/dev/null || echo "No ResourceQuota in anthra"
```

Document what you find. If Kyverno enforces `runAsNonRoot` at admission but
kube-bench still reports the check as FAIL (because it reads the manifest, not
admission history), the assessor needs to see both:

1. The kube-bench FAIL finding
2. The Kyverno policy that compensates for it
3. Evidence that the policy is enforced (Kyverno audit log or test result)

---

## Step 4: Classify and rank

| Classification Field | Value |
|----------------------|-------|
| CSF Function         | PROTECT |
| CSF Category         | PR.PS — Platform Security |
| CSF Subcategory      | PR.PS-01 — Configuration management practices applied |
| CIS Controls v8      | 4.1 — Establish and Maintain a Secure Configuration Process |
| NIST 800-53          | CM-6, CM-7 |
| Severity             | Medium to High (depends on which findings are present) |
| Rank                 | C — Analyst proposes remediation, human approves changes |

Why C-rank and not D-rank: These configuration changes affect running workloads.
Patching a securityContext on a deployment causes a rollout. Adding NetworkPolicy
can break legitimate traffic if the policy is wrong. A human needs to review each
change before it is applied to production.

---

## Step 5: Decision matrix

For each finding, choose one of three paths:

### Fix immediately (top 5 above)

These are fixable from the analyst's position, low-risk to apply, and directly
compensate for benchmark failures. Run fix.sh.

### Document as POA&M

Findings that require cluster admin access, code changes, or architectural
decisions. Examples:
- Control plane audit logging configuration (requires k3s config change and
  node restart)
- etcd encryption at rest (requires cluster reconfiguration)
- kubelet anonymous authentication (may be needed for health check endpoints)

For each POA&M item, document:
- Finding (CIS check ID and description)
- Risk if not remediated
- Proposed remediation
- Estimated completion date
- Owner (who will do it)

### Accept with documented compensating control

Findings where an existing control provides equivalent protection. Document the
compensating control explicitly and get it reviewed.

Example: kube-bench 5.2.6 (pods running as root) — ACCEPTED with compensating
control: Kyverno ClusterPolicy `require-run-as-non-root` enforces
`runAsNonRoot: true` at admission and blocks deployment of non-compliant pods.

---

## Summary Before Remediation

After completing investigation, you should have:

- [ ] kube-bench FAIL count by section
- [ ] kubescape compliance score and failing controls
- [ ] Top 5 findings identified and risk-rated
- [ ] Compensating controls checked and documented
- [ ] POA&M items drafted for what cannot be fixed now
- [ ] C-rank classification recorded

Move to `fix.sh` to remediate the top 5 findings.
