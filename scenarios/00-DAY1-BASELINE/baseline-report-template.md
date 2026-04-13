# Day 1 Baseline Report — Anthra-SecLAB

**Analyst Name:**
**Date:**
**Cluster:**         k3d-seclab
**Context verified:** [ ] Yes  [ ] No
**Script run:**      [ ] Yes — evidence dir: ________________________________
**Checklist walked:** [ ] Yes  [ ] No

---

## Section 1 — Cluster Health (ID.AM-01)

### 1.1 Node Status

| Node Name | Role | Status | K8s Version | Notes |
|-----------|------|--------|-------------|-------|
| | server | | | |
| | agent | | | |
| | agent | | | |

**All nodes Ready:** [ ] Yes  [ ] No — if No, describe:

---

### 1.2 Required Namespaces

| Namespace | Present | Status | Notes |
|-----------|---------|--------|-------|
| anthra | | | |
| falco | | | |
| kyverno | | | |
| logging | | | |
| monitoring | | | |

---

### 1.3 Application Pods (anthra namespace)

| Deployment | Pod Status | Ready | Restarts | Notes |
|-----------|-----------|-------|----------|-------|
| portfolio-anthra-portfolio-app-api | | | | |
| portfolio-anthra-portfolio-app-ui | | | | |
| portfolio-anthra-portfolio-app-chroma | | | | |

**All application pods Running 1/1:** [ ] Yes  [ ] No

---

## Section 2 — Security Stack (DE.CM-03)

### 2.1 Falco

| Check | Result | Notes |
|-------|--------|-------|
| Pod status | | |
| Pod count (expect 3 for 3-node cluster) | | |
| Producing log output | | |

**Falco healthy:** [ ] Yes  [ ] No

---

### 2.2 Kyverno

| Check | Result | Notes |
|-------|--------|-------|
| Pod status | | |
| ClusterPolicy count | | |
| Policies in Enforce mode | | |
| Policies in Audit mode | | |

**List any critical policies in Audit mode (not blocking violations):**

| Policy Name | Enforcement Mode | Risk If Not Enforced |
|-------------|-----------------|---------------------|
| | | |
| | | |

**Kyverno healthy:** [ ] Yes  [ ] No

---

### 2.3 Fluent Bit

| Check | Result | Notes |
|-------|--------|-------|
| Pod status | | |
| Pod count (expect 3 for 3-node cluster) | | |

**Fluent Bit healthy:** [ ] Yes  [ ] No

---

### 2.4 Prometheus + Grafana

| Check | Result | Notes |
|-------|--------|-------|
| Prometheus pod status | | |
| Grafana pod status | | |

**Monitoring healthy:** [ ] Yes  [ ] No

---

## Section 3 — Application Security Posture (PR.PS-01)

### 3.1 Security Contexts

| Deployment | runAsNonRoot | allowPrivilegeEscalation | readOnlyRootFilesystem | capabilities.drop | Result |
|-----------|-------------|------------------------|----------------------|------------------|--------|
| portfolio-anthra-portfolio-app-api | | | | | |
| portfolio-anthra-portfolio-app-ui | | | | | |
| portfolio-anthra-portfolio-app-chroma | | | | | |

For each field, write the actual value found (true/false/missing).

---

### 3.2 NetworkPolicies

| Check | Result | Notes |
|-------|--------|-------|
| NetworkPolicies present in anthra | | |
| Default-deny policy present | | |
| Ingress restricted | | |
| Egress restricted | | |

**NetworkPolicy coverage adequate:** [ ] Yes  [ ] No  [ ] Partial

---

### 3.3 Service Types

| Service Name | Type | Port | Finding |
|-------------|------|------|---------|
| | | | |
| | | | |
| | | | |

**All services ClusterIP:** [ ] Yes  [ ] No — if No, list exposed services:

---

### 3.4 Service Account Token Automount

| Pod | automountServiceAccountToken | Finding |
|-----|---------------------------|---------|
| portfolio-anthra-portfolio-app-api | | |
| portfolio-anthra-portfolio-app-ui | | |
| portfolio-anthra-portfolio-app-chroma | | |

Expected value: `false`. Any `true` or blank value is a finding.

---

## Section 4 — Vulnerability Baseline (ID.RA-01)

### 4.1 Trivy Image Scan Results

| Image | CRITICAL CVEs | HIGH CVEs | Most Severe CVE | Notes |
|-------|--------------|-----------|----------------|-------|
| | | | | |
| | | | | |
| | | | | |

---

### 4.2 kube-bench Results

| Category | PASS | FAIL | WARN | Notes |
|----------|------|------|------|-------|
| Master Node (if applicable) | | | | |
| Worker Nodes | | | | |
| etcd (if applicable) | | | | |
| **Total** | | | | |

**kube-bench ran successfully:** [ ] Yes  [ ] No — if No: ____________________

---

### 4.3 Kubescape Score

| Framework | Risk Score | Grade | Notes |
|-----------|-----------|-------|-------|
| NSA | | | |
| MITRE | | | |
| Overall | | | |

**Kubescape ran successfully:** [ ] Yes  [ ] No — if No: ____________________

---

## Section 5 — RBAC (PR.AA-05)

### 5.1 Cluster-Admin Bindings

| Binding Name | Subject Kind | Subject Name | Namespace | Expected | Finding |
|-------------|-------------|-------------|-----------|----------|---------|
| | | | | | |
| | | | | | |
| | | | | | |

**Unexpected cluster-admin bindings found:** [ ] Yes  [ ] No

---

### 5.2 Wildcard Roles (Non-System)

| ClusterRole Name | Wildcard Verbs | Wildcard Resources | Finding |
|-----------------|---------------|--------------------|---------|
| | | | |

**Result:** [ ] None found (good baseline)  [ ] Findings documented above

---

### 5.3 Anthra Namespace Role Bindings

| Binding Name | Subject | Role | Finding |
|-------------|---------|------|---------|
| | | | |

**Excessive permissions in anthra namespace:** [ ] Yes  [ ] No  [ ] None present

---

## Pre-Existing Issues

Document anything that looked wrong during the baseline walk that was NOT introduced by a scenario.
These are pre-existing conditions in the environment.

| # | Component | Issue Description | Severity | CSF Control |
|---|-----------|-----------------|----------|-------------|
| 1 | | | | |
| 2 | | | | |
| 3 | | | | |

Severity: LOW / MEDIUM / HIGH / CRITICAL

If no pre-existing issues were found, write: "None identified during Day 1 baseline."

---

## Tool Availability

| Tool | Found on PATH | Version | Notes |
|------|--------------|---------|-------|
| kubectl | | | |
| trivy | | | |
| kube-bench | | | |
| kubescape | | | |
| semgrep | | | |
| gitleaks | | | |

---

## Summary Assessment

**Overall cluster health:** [ ] PASS  [ ] FAIL  [ ] DEGRADED
**Security stack health:** [ ] PASS  [ ] FAIL  [ ] DEGRADED
**Application security posture:** [ ] PASS  [ ] FAIL  [ ] NEEDS IMPROVEMENT
**RBAC posture:** [ ] PASS  [ ] FAIL  [ ] NEEDS IMPROVEMENT

**Ready to proceed with break/fix scenarios:** [ ] Yes  [ ] No

If No, explain why (e.g., Falco down, nodes NotReady, pods not starting):

---

## Analyst Sign-Off

By signing this report, I confirm that I personally ran each command in the checklist and verified
the results listed above. I did not modify any configuration during this baseline walkthrough.

**Analyst Name (print):** ________________________________________________

**Date:** ______________________    **Time:** ______________________

**Evidence directory:** ________________________________________________

---

*This report serves as the Day 1 baseline for Anthra-SecLAB. All future scenario findings are
compared against the state documented here.*
