# L7-03 — Report Template: CIS Benchmark Findings

**Analyst:** ___________________________
**Date:** ___________________________
**Environment:** k3d-seclab / namespace anthra
**Tools used:** kube-bench, kubescape
**Scenario:** L7-03 PR.PS-01 — CIS Benchmark Failures Unremediated

---

## 1. Audit Summary

### kube-bench Results

| Metric | Before Fix | After Fix | Delta |
|--------|-----------|-----------|-------|
| PASS   | _____ | _____ | _____ |
| FAIL   | _____ | _____ | _____ |
| WARN   | _____ | _____ | _____ |

### kubescape Results

| Metric | Before Fix | After Fix |
|--------|-----------|-----------|
| Compliance score | ____% | ____% |
| Failing controls | _____ | _____ |
| Resources checked | _____ | _____ |

---

## 2. Top 5 Findings

List the five findings addressed by fix.sh. Fill in the actual observed state
before the fix was applied.

| # | CIS Check | Description | Observed State Before Fix | Risk |
|---|-----------|-------------|--------------------------|------|
| 1 | 5.2.5 | allowPrivilegeEscalation not false | ___________________________ | High |
| 2 | 5.2.6 | Pods running as root | ___________________________ | High |
| 3 | 5.3.2 | No NetworkPolicy in namespace | ___________________________ | Medium |
| 4 | 5.2.1 | No PSS labels on namespace | ___________________________ | Medium |
| 5 | 5.1.6 | SA token auto-mounted | ___________________________ | Medium |

---

## 3. POA&M Entries

For findings NOT fixed by fix.sh, document them here. Each entry requires:
finding ID, description, risk, owner, scheduled completion, and compensating
controls.

### POA&M Entry 1

| Field | Value |
|-------|-------|
| Finding ID | CIS-[check]-[YYYY-MM] |
| CIS Check | |
| Description | |
| Risk Level | Critical / High / Medium / Low |
| Discovery Date | |
| Scheduled Completion | |
| Milestone 1 | |
| Milestone 2 | |
| Owner | |
| Compensating Control | None / [describe] |
| Status | Open |

### POA&M Entry 2

| Field | Value |
|-------|-------|
| Finding ID | CIS-[check]-[YYYY-MM] |
| CIS Check | |
| Description | |
| Risk Level | Critical / High / Medium / Low |
| Discovery Date | |
| Scheduled Completion | |
| Milestone 1 | |
| Milestone 2 | |
| Owner | |
| Compensating Control | None / [describe] |
| Status | Open |

Add additional entries as needed for remaining failures.

---

## 4. Compensating Controls Documented

For any CIS finding where an existing control provides equivalent protection,
document it here. The assessor needs to see both the finding and evidence that
the compensating control is active.

| CIS Check | Finding Description | Compensating Control | Evidence |
|-----------|--------------------|--------------------|---------|
| | | | |
| | | | |

---

## 5. GRC Section: Evidence for an Auditor

An assessor asking about CM-6 (Configuration Settings) will want answers to
these questions. Fill in your answers based on what you observed in this scenario.

**Question 1: How do you know your cluster configuration matches your security
baseline?**

> We ran kube-bench version _____ against node targets on [date]. The tool
> produced [N] FAIL findings. We remediated [N] of them on [date] and documented
> [N] as POA&M items. The kube-bench output is attached as Exhibit A. The
> kubescape scan (Exhibit B) shows a compliance score of ____% against the NSA
> Kubernetes Hardening framework.

**Question 2: How frequently is this benchmark run?**

> [Current state. State the plan to make this continuous: scheduled kube-bench
> run in CI/CD, kubescape in pipeline, weekly scan with findings exported to
> POA&M tracker.]

**Question 3: Who owns remediation of benchmark findings?**

> [Describe the team and process. Who runs the scan? Who reviews findings?
> Who approves configuration changes? What is the SLA for High vs Medium findings?]

**Question 4: Are there any findings you chose not to remediate? Why?**

> [List accepted risks. For each, state the compensating control or business
> reason for acceptance. Accepted risks without compensating controls are audit
> findings themselves.]

---

## 6. Evidence Package

Attach or reference the following artifacts:

| Artifact | File Path | Notes |
|----------|-----------|-------|
| kube-bench output (before) | /tmp/L7-03-baseline-*/kube-bench-output.txt | Raw tool output |
| kube-bench output (after) | /tmp/L7-03-verify-*/kube-bench-output.txt | Post-fix scan |
| kubescape JSON (before) | /tmp/L7-03-baseline-*/kubescape-output.json | Machine-readable |
| kubescape summary (before) | /tmp/L7-03-baseline-*/kubescape-summary.txt | Human-readable |
| kubescape summary (after) | /tmp/L7-03-verify-*/kubescape-summary.txt | Post-fix scan |
| fix log | /tmp/L7-03-fix-*.log | What was changed and why |
| NetworkPolicy YAML | kubectl get networkpolicy -n anthra -o yaml | Live cluster state |
| Namespace PSS labels | kubectl get namespace anthra --show-labels | Live cluster state |

---

## 7. Lessons Learned

**What was the root cause of the failures?**

> [Example: The cluster was deployed with default configuration. No CIS benchmark
> run was scheduled post-deployment. No automated scanning was in place to detect
> configuration drift.]

**What would have caught this sooner?**

> [Example: A kubescape scan in CI/CD would have flagged securityContext gaps
> before workloads were deployed. A weekly kube-bench job would provide ongoing
> visibility.]

**What did you learn about reading kube-bench output?**

> [Your reflection here.]

**What is the difference between kube-bench and kubescape findings?**

> [kube-bench = node-level (kubelet config, OS settings). kubescape = workload-level
> (pod specs, RBAC, NetworkPolicy). Both are needed for a complete CIS picture.]

**One thing that surprised you about the cluster's default state:**

> [Your reflection here.]

---

## Certification

I, _________________________, certify that:

- [ ] I ran kube-bench and kubescape against the k3d-seclab cluster
- [ ] I reviewed all FAIL findings and assessed risk for each
- [ ] I applied fix.sh and verified that targeted findings were remediated
- [ ] I documented remaining findings as POA&M items
- [ ] I identified and documented any compensating controls
- [ ] The evidence files listed above are retained and available for review

Date: _____________________________
