# L7-08 — Report Template: Unpatched CVE in Container Image

**Scenario:** L7-08-ID.RA-01-unpatched-cve
**Analyst:** [Your name]
**Date:** [YYYY-MM-DD]
**System:** Anthra-SecLAB / k3d-seclab / namespace: anthra
**Classification:** [Internal / Confidential]

---

## Executive Summary

A container image with known CRITICAL vulnerabilities was deployed to the Portfolio
API workload in the `anthra` namespace. The image (`python:3.9-slim`) was swapped
without passing through a vulnerability scan gate in CI/CD. Trivy identified
[CRITICAL_COUNT] CRITICAL CVEs and [HIGH_COUNT] HIGH CVEs in the deployed image.

**Availability impact:** [Running / CrashLoopBackOff -- fill in what you observed]

The immediate finding was remediated by rolling back to the previously validated image.
The root cause -- absence of a CI scanning gate and image digest pinning -- requires
structural remediation tracked in the POA&M below.

---

## CVE Findings Table

*Fill in from Trivy output. Run: `trivy image python:3.9-slim --severity CRITICAL,HIGH`*

| CVE ID | CVSS Base | Severity | Affected Package | Installed Version | Fixed Version | EPSS (30d) | Exploitable in Context? |
|--------|-----------|----------|------------------|-------------------|---------------|------------|------------------------|
| CVE-XXXX-XXXXX | 9.8 | CRITICAL | [package] | [version] | [fixed] | [score] | [Yes/No/Unknown] |
| CVE-XXXX-XXXXX | 7.5 | HIGH | [package] | [version] | [fixed] | [score] | [Yes/No/Unknown] |

**Total CRITICAL:** [N]
**Total HIGH:** [N]
**Total with Fixed Version available:** [N] / [total]

---

## Triage Notes

**Attack Surface:** [Describe -- is the API exposed to the internet? behind a load balancer? mTLS?]

**Compensating Controls in Place:**
- [ ] NetworkPolicy restricts ingress to anthra namespace
- [ ] mTLS or JWT authentication on API endpoints
- [ ] WAF in front of the API
- [ ] None -- full network exposure

**Environmental Score Adjustment:**
- Base CVSS: [highest score found, e.g., 9.8]
- Environmental CVSS: [adjusted score based on compensating controls]
- Reasoning: [one sentence]

**EPSS Analysis:**
- Highest EPSS found: [score] (CVE: [ID])
- Assessment: [Active exploitation / Below active-exploitation threshold]

---

## Blast Radius Assessment

| Asset | Reachable from Compromised API Pod? | Impact if Reached |
|-------|-------------------------------------|-------------------|
| ChromaDB (vector DB) | [Yes/No] | [Data exfiltration / vector poisoning] |
| Portfolio UI pod | [Yes/No] | [Content injection] |
| Kubernetes API server | [Yes/No] | [Cluster takeover] |
| Mounted secrets | [Yes/No -- list them] | [Credential theft] |
| Other namespaces | [Yes/No] | [Lateral movement] |

**Overall blast radius:** [Low / Medium / High / Critical]

---

## Plan of Action and Milestones (POA&M)

### Item 1 -- CRITICAL CVEs in Deployed Container Image

| Field | Value |
|-------|-------|
| POAM-ID | L7-08-[DATE]-001 |
| Control | SI-2 (Flaw Remediation) / RA-5 (Vulnerability Scanning) |
| CSF Subcategory | ID.RA-01 |
| CIS v8 | 7.4 -- Automated Application Patch Management |
| Finding | CRITICAL CVEs in python:3.9-slim deployed to portfolio-anthra-portfolio-app-api |
| Severity | CRITICAL |
| Date Identified | [YYYY-MM-DD] |
| Remediation Due | [YYYY-MM-DD + 15 days] |
| Remediation Action | Roll back to previously validated image; scan before redeployment |
| Date Remediated | [YYYY-MM-DD] |
| Verification Method | Trivy scan of restored image showing 0 CRITICAL CVEs |
| Status | [Open / Closed] |

### Item 2 -- Missing CI Vulnerability Scan Gate (Root Cause)

| Field | Value |
|-------|-------|
| POAM-ID | L7-08-[DATE]-002 |
| Control | SI-2 (Flaw Remediation) / RA-5 (Vulnerability Scanning) |
| CIS v8 | 7.4 -- Automated Application Patch Management |
| Finding | No trivy scan gate in CI/CD pipeline; images can be deployed without scan |
| Severity | HIGH (process gap) |
| Date Identified | [YYYY-MM-DD] |
| Remediation Due | [YYYY-MM-DD + 30 days] |
| Remediation Action | Add trivy image --exit-code 1 --severity CRITICAL,HIGH to CI pipeline |
| Status | Open |

### Item 3 -- Unpinned Image Tags (Root Cause)

| Field | Value |
|-------|-------|
| POAM-ID | L7-08-[DATE]-003 |
| Control | CM-2 (Baseline Configuration) |
| CIS v8 | 7.4 -- Automated Application Patch Management |
| Finding | Container images not pinned by digest; tags can drift silently |
| Severity | MEDIUM |
| Date Identified | [YYYY-MM-DD] |
| Remediation Due | [YYYY-MM-DD + 30 days] |
| Remediation Action | Pin all production images by digest in deployment manifests |
| Status | Open |

---

## Before / After Comparison

| Metric | Before (python:3.9-slim) | After (restored image) |
|--------|--------------------------|------------------------|
| CRITICAL CVEs | [N] | [N] |
| HIGH CVEs | [N] | [N] |
| Pod Status | [Running / CrashLoopBackOff] | Running |
| Image Digest Pinned | No | [Yes/No] |
| Scan in CI | No | No (POA&M Item 2) |

---

## GRC Section: Risk Committee Presentation

**Q: How did a CRITICAL CVE make it to production?**
A: There was no automated vulnerability scan gate in the CI/CD pipeline. An operator
changed the image manually without triggering a scan. The gap is a process control
failure, not a tool failure. Trivy found the CVE in minutes when run manually. The
fix is implementing Trivy as a blocking CI gate.

**Q: How long was the vulnerable image running?**
A: [Time between break.sh and fix.sh]. During that window, the application [was /
was not] serving traffic. The vulnerability required [local / network] access to exploit.

**Q: What is the residual risk after rollback?**
A: Residual risk is LOW for the immediate finding -- the vulnerable image is no longer
running. Residual risk is MEDIUM for the process gap -- two POA&M items remain open.
Interim compensating control: manual scan required and documented before any image change.

---

## Recommendations

1. Immediate: Add Trivy to CI pipeline as blocking gate (CIS 7.4)
2. Immediate: Pin all production images by digest
3. Short-term: Implement periodic image re-scan CronJob for running workloads (RA-5)
4. Short-term: Add Kyverno policy to reject images without scan attestation
5. Long-term: Implement image signing with Cosign; require verified signature at admission

---

## References

- NIST 800-53 Rev 5: SI-2, RA-5, CM-2
- NIST CSF 2.0: ID.RA-01
- CIS Controls v8: 7.4
- FedRAMP Vulnerability Scanning Requirements
- FIRST EPSS: https://www.first.org/epss/
- CompTIA CySA+ OBJ 1.3
