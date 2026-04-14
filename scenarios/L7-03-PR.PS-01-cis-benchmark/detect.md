# L7-03 — Detect: Reading CIS Benchmark Output

## What You Are Looking For

You are a Level 1 analyst. The cluster has been running for some time and nobody
has run a formal CIS audit. Your job is to run two tools, understand what they
report, and identify which findings are real risks versus noise.

---

## Step 1: Run kube-bench

kube-bench tests the cluster configuration against the CIS Kubernetes Benchmark.
It checks things the operating system and kubelet are configured to do — not
application-level issues.

```bash
/usr/local/bin/kube-bench run --targets node 2>/dev/null | tee /tmp/kube-bench-$(date +%Y%m%d).txt
```

### Reading kube-bench output

Each line starts with one of four prefixes:

| Prefix   | Meaning |
|----------|---------|
| `[PASS]` | The check passed. Configuration matches the CIS recommendation. |
| `[FAIL]` | The check failed. This is a gap that needs remediation or compensating control documentation. |
| `[WARN]` | kube-bench could not determine the result automatically. A human needs to verify. |
| `[INFO]` | Informational only. No action needed. |

The check ID maps directly to the CIS Kubernetes Benchmark section. For example:

- `4.2.1` = Section 4 (Worker Nodes), Subsection 2 (Kubelet), Check 1
- `5.2.3` = Section 5 (Policies), Subsection 2 (Pod Security Standards), Check 3

When kube-bench reports FAIL for a check, the next lines explain:
1. **What was checked** — the exact configuration element
2. **Why it matters** — the rationale
3. **Remediation** — what command or configuration change fixes it

### What the sections cover

| Section | Topic |
|---------|-------|
| 1 | Control Plane Components (API server, controller manager, scheduler) |
| 2 | etcd (k3s embeds this — some checks may not apply) |
| 3 | Control Plane Configuration |
| 4 | Worker Nodes (kubelet configuration) |
| 5 | Policies (RBAC, PSS, network policies, secrets) |

On k3s, many section 1-3 checks will show as WARN because k3s uses non-standard
paths and configurations. Focus on sections 4 and 5 — these apply to any
Kubernetes distribution.

---

## Step 2: Run kubescape

kubescape scans workload manifests and running configuration against security
frameworks (NSA/CISA, MITRE ATT&CK, CIS). It gives you a compliance score and
identifies specific control failures per workload.

```bash
~/bin/kubescape scan namespace anthra --format pretty 2>/dev/null
```

For JSON output (machine-readable, good for evidence):
```bash
~/bin/kubescape scan namespace anthra --format json --output /tmp/kubescape-$(date +%Y%m%d).json 2>/dev/null
```

### Reading kubescape output

kubescape uses control IDs to identify findings:

| Control ID | What It Checks |
|------------|---------------|
| C-0001 | Forbidden container registries |
| C-0013 | Non-root containers |
| C-0017 | Immutable container filesystem |
| C-0020 | Running containers as root user |
| C-0030 | Ingress and egress blocked (NetworkPolicy) |
| C-0031 | Limit root capabilities |
| C-0038 | Host PID/IPC sharing |
| C-0041 | HostNetwork |
| C-0042 | SSH server running inside container |
| C-0044 | Container resource limits |
| C-0046 | Insecure capabilities |
| C-0055 | Linux hardening (seccomp, AppArmor) |
| C-0056 | Unsafe sysctls |

The compliance score at the end of the report is a percentage: 100% means zero
control failures in the scanned namespace. A score below 80% in a production
cluster is a significant finding for CM-6.

---

## Step 3: Count and categorize findings

After running both tools, categorize what you found:

```bash
# kube-bench fail count
grep -c "^\[FAIL\]" /tmp/kube-bench-*.txt

# kube-bench warn count (needs human review)
grep -c "^\[WARN\]" /tmp/kube-bench-*.txt

# List all FAIL check IDs
grep "^\[FAIL\]" /tmp/kube-bench-*.txt | awk '{print $2}'
```

For kubescape, the pretty output table shows which controls failed and which
resources are affected. Note the resource names — if all three Portfolio
deployments appear in the failure list, the issue is systemic, not isolated.

---

## Step 4: Prioritize — can an attacker exploit this?

Not all FAIL findings are equal. The CIS benchmark is comprehensive, and some
checks matter much more than others in a real attack scenario. Use this mental
model:

### High priority (attacker can directly exploit)

- **No securityContext** — container runs as root, can write anywhere in its
  filesystem, may be able to escape
- **allowPrivilegeEscalation: true** — process inside container can gain more
  privileges than its parent
- **No NetworkPolicy** — compromised pod can freely reach any other pod in the
  cluster, including the API server
- **Service account tokens auto-mounted** — every pod gets a token it may not
  need; a compromised pod can use it to query the Kubernetes API
- **readOnlyRootFilesystem: false** — attacker can modify files inside the
  container, including scripts that get executed

### Medium priority (reduces blast radius, required for compliance)

- **No resource limits** — a compromised pod can consume all node resources
  (DoS against other workloads)
- **No PSS labels on namespace** — the cluster is not enforcing Pod Security
  Standards at admission time
- **Capabilities not dropped** — container retains Linux capabilities it does
  not need (CAP_NET_RAW, etc.)

### Lower priority (hardening depth, important but not immediately exploitable)

- **Audit logging configuration** — cannot fix without cluster admin access
- **Control plane TLS settings** — k3s manages these; check but likely
  compensated by the distribution
- **etcd access controls** — embedded in k3s; applies differently than
  standalone clusters

---

## Step 5: Check for compensating controls

Before writing up a finding as unmitigated, check whether an existing control
already addresses it.

```bash
# Check if Kyverno policies enforce securityContext
kubectl get clusterpolicy -o name 2>/dev/null

# Check if PSS admission is blocking non-compliant pods
kubectl get namespace anthra -o jsonpath='{.metadata.labels}' | python3 -m json.tool

# Check if NetworkPolicies exist
kubectl get networkpolicy -n anthra

# Check if resource quotas exist (compensates for missing per-pod limits)
kubectl get resourcequota -n anthra
kubectl get limitrange -n anthra
```

If Kyverno has a policy that enforces `runAsNonRoot: true` at admission, a
kube-bench FAIL for "pods running as root" is compensated — document both the
finding and the compensating control. The assessor needs to see both.

---

## What to do next

After completing detection:

1. You have a count of FAIL findings from kube-bench
2. You have a compliance score and failing control list from kubescape
3. You know which findings have compensating controls
4. You know which findings are immediately exploitable vs. hardening depth

Move to `investigate.md` to classify these findings and build the remediation plan.
