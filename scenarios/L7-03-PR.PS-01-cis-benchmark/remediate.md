# L7-03 — Remediate: CIS Kubernetes Benchmark

## The CIS Kubernetes Benchmark Structure

The CIS Kubernetes Benchmark is organized into five sections. Each section maps
to a set of configuration checks with PASS/FAIL/WARN outcomes. Understanding the
structure helps you prioritize remediation and communicate findings to stakeholders.

### Section Map

| Section | Title | Applies To | Key Controls |
|---------|-------|-----------|--------------|
| 1 | Control Plane Components | API server, controller manager, scheduler | TLS config, authentication, authorization |
| 2 | Etcd | etcd data store | TLS, peer auth, data encryption |
| 3 | Control Plane Configuration | API server config files | kubeconfig permissions, cluster-admin bindings |
| 4 | Worker Nodes | kubelet configuration | Authentication, authorization, certificate rotation |
| 5 | Policies | Workloads, RBAC, PSS, network | Pod security, ServiceAccounts, NetworkPolicy, Secrets |

### Level 1 vs Level 2 Checks

The benchmark labels each check as Level 1 or Level 2:

- **Level 1** — Minimal impact on functionality. Should be implemented by all
  organizations. Required for most compliance frameworks (FedRAMP Moderate, SOC 2,
  HIPAA). Assessors will ask for evidence that these are addressed.

- **Level 2** — May impact functionality or require additional tooling. Recommended
  for high-security environments (FedRAMP High, DoD IL4+, financial services).
  Implement after Level 1 is stable.

On k3s, some checks in sections 1-3 will report WARN or N/A because k3s embeds
and manages control plane components differently. Focus on sections 4 and 5 —
these apply universally.

---

## Section-to-CSF Mapping

| CIS Section | CSF Function | CSF Category | NIST 800-53 |
|-------------|-------------|--------------|-------------|
| 1 — Control Plane | PROTECT | PR.PS-01 | CM-6, CM-7 |
| 2 — Etcd | PROTECT | PR.DS-02 | SC-28, SC-8 |
| 3 — Control Plane Config | PROTECT | PR.PS-01 | CM-6 |
| 4 — Worker Nodes | PROTECT | PR.PS-01 | CM-6, CM-7 |
| 5 — Policies | PROTECT | PR.PS-01, PR.AA-05 | CM-7, AC-3, AC-6 |

---

## Top 10 Most Common Failures

These are the findings that appear on almost every first-time benchmark scan. Each
entry includes the CIS check, the CSF subcategory, and the remediation command
where applicable.

| # | CIS Check | Description | CSF Subcategory | Fix Command |
|---|-----------|-------------|-----------------|-------------|
| 1 | 5.2.6 | Pods running as root | PR.PS-01 | `kubectl patch deployment ... -p '{"spec":{"template":{"spec":{"securityContext":{"runAsNonRoot":true}}}}}'` |
| 2 | 5.2.5 | allowPrivilegeEscalation not false | PR.PS-01 | `kubectl patch deployment ... -p '[{"op":"add","path":".../allowPrivilegeEscalation","value":false}]'` |
| 3 | 5.3.2 | No NetworkPolicy defined | PR.PS-01 | Apply default-deny-all NetworkPolicy (see fix.sh) |
| 4 | 5.2.1 | No PSS labels on namespace | PR.PS-01 | `kubectl label namespace anthra pod-security.kubernetes.io/enforce=baseline` |
| 5 | 5.1.6 | SA token auto-mounted | PR.PS-01 | `kubectl patch deployment ... -p '[{"op":"add","path":".../automountServiceAccountToken","value":false}]'` |
| 6 | 5.7.4 | No resource limits | PR.PS-01 | Set `resources.limits.cpu` and `resources.limits.memory` in deployment manifest |
| 7 | 4.2.1 | Kubelet anonymous auth enabled | PR.PS-01 | k3s config: `protect-kernel-defaults: true` in `/etc/rancher/k3s/config.yaml` |
| 8 | 5.2.4 | readOnlyRootFilesystem not true | PR.PS-01 | `kubectl patch deployment ... -p '[{"op":"add","path":".../readOnlyRootFilesystem","value":true}]'` |
| 9 | 5.4.1 | Secrets not in env vars | PR.DS-01 | Migrate `env.value` secrets to `secretKeyRef` or mounted volumes |
| 10 | 5.2.9 | Service using host network | PR.PS-01 | Verify `hostNetwork: false` (or absent) on all pod specs |

---

## NetworkPolicy: Required Allow Policies After Default-Deny

The default-deny-all policy in fix.sh blocks all traffic. You must add explicit
allow policies for your application to function. Apply these after testing in a
non-production environment.

### DNS egress (required for all pods)

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-dns-egress
  namespace: anthra
spec:
  podSelector: {}
  policyTypes:
  - Egress
  egress:
  - ports:
    - port: 53
      protocol: UDP
    - port: 53
      protocol: TCP
```

### API pod: allow ingress from ingress controller

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-api-ingress
  namespace: anthra
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/component: api
  policyTypes:
  - Ingress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: ingress-nginx
    ports:
    - port: 8000
      protocol: TCP
```

### API pod: allow egress to chroma

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-api-to-chroma-egress
  namespace: anthra
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/component: api
  policyTypes:
  - Egress
  egress:
  - to:
    - podSelector:
        matchLabels:
          app.kubernetes.io/component: chroma
    ports:
    - port: 8001
      protocol: TCP
```

---

## GRC Section: CIS Findings in a POA&M

### What is a POA&M?

A Plan of Action and Milestones (POA&M) is the formal document that tracks
security weaknesses that have been identified but not yet remediated. In FedRAMP,
POA&M entries are reviewed at every assessment. In HIPAA and SOC 2, they are
evidence of a functioning risk management process.

A POA&M entry for a CIS benchmark finding needs:

| Field | Content |
|-------|---------|
| Finding ID | Unique identifier (e.g., CIS-5.3.2-2026-04) |
| Finding Description | What was found (kube-bench output, check ID) |
| Risk Level | Critical, High, Medium, Low |
| Discovery Date | When the benchmark was first run |
| Scheduled Completion | Realistic date for remediation |
| Milestone 1 | First action (e.g., draft NetworkPolicy in staging) |
| Milestone 2 | Second action (e.g., test, apply to production) |
| Owner | Team or individual responsible |
| Compensating Control | If any (documented explicitly) |
| Status | Open, In Progress, Closed |

### Remediation timeline guidance

| Severity | Maximum POA&M Duration | Rationale |
|----------|----------------------|-----------|
| Critical (exploitable, no compensating control) | 30 days | Active risk to environment |
| High (significant hardening gap) | 90 days | Prioritized sprint work |
| Medium (best practice gap) | 180 days | Planned hardening cycle |
| Low (hardening depth, not exploitable) | 365 days | Next architecture review |

CIS benchmark findings are typically Medium or High. A finding like "no
NetworkPolicy" is Medium if there is no active threat, but should be High if
you know lateral movement is in your threat model (which it always is for
multi-tenant clusters).

### Compensating controls

A compensating control is an alternative security measure that provides equivalent
protection to what the CIS check recommends.

Examples:

- **CIS 5.2.6 (pods running as root)** — Compensating control: Kyverno
  ClusterPolicy `require-run-as-non-root` enforces `runAsNonRoot: true` at
  admission. Evidence: Kyverno audit log showing zero violations in last 90 days.

- **CIS 4.2.1 (kubelet anonymous auth)** — Compensating control: Node is not
  internet-accessible. Kubelet port 10250 is blocked by security group rules and
  by NetworkPolicy (no ingress to hostNetwork). Evidence: AWS security group
  rules screenshot, NetworkPolicy YAML.

- **CIS 5.4.1 (secrets in env vars)** — Compensating control: Secrets are
  managed by AWS Secrets Manager and injected via CSI driver at pod startup, not
  stored in Kubernetes Secrets at all. Evidence: SecretProviderClass manifest,
  pod spec showing CSI volume mount.

When documenting a compensating control, the assessor needs:
1. The CIS check that is not passing
2. The alternative control you implemented
3. Evidence that the alternative control is active and effective

---

## Kubelet Findings: k3s-Specific Remediation

Many kube-bench section 4 findings relate to kubelet configuration. On k3s,
the kubelet is embedded and configured through `/etc/rancher/k3s/config.yaml`
rather than a separate kubelet config file.

Common kubelet findings and k3s remediation:

```yaml
# /etc/rancher/k3s/config.yaml
# Add these to address common CIS 4.x findings:

protect-kernel-defaults: true        # CIS 4.2.6
streaming-connection-idle-timeout: 5m # CIS 4.2.5
make-iptables-util-chains: true       # CIS 4.2.7
event-qps: 0                          # CIS 4.2.9 (disable event rate limiting for audit)
```

After modifying this file, k3s must be restarted: `sudo systemctl restart k3s`

This is a B-rank change — it affects node operation and requires human approval
before applying to a production cluster. Document it as a POA&M item in a lab
environment.
