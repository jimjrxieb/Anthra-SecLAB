# L7-08 — Remediate: Unpatched CVE in Container Image

**Phase:** REMEDIATE
**CySA+ Reference:** OBJ 1.3 — Explain the importance of vulnerability management
**Objective:** Understand the full vulnerability management lifecycle and NIST SI-2 requirements

---

## The Vulnerability Management Lifecycle

Rolling back the image was the emergency response. Remediation means preventing this
from happening again. There are six phases. Running `kubectl rollout undo` addresses
phase 4. The other five phases are where most organizations fail.

```
IDENTIFY → TRIAGE → PRIORITIZE → REMEDIATE → VERIFY → DOCUMENT
```

---

## Phase 1 — Identify

**What it means:** Vulnerabilities must be found before they can be fixed.

Sources of identification in a container environment:
- CI pipeline: Trivy scans the image before it is pushed to the registry
- Admission control: Kyverno or OPA Gatekeeper blocks images with CRITICAL CVEs from deploying
- Periodic re-scan: a scheduled job re-scans all running images against the current CVE database
- Supply chain attestation: Cosign verifies that the image was scanned and signed before admission

In this scenario, none of these existed. The operator deployed an unscanned image with
no gate to catch it. ID.RA-01 requires identification. Without a CI scan gate, the
identification step only happens after something goes wrong — which is too late.

**Required control:** Add `trivy image --exit-code 1 --severity CRITICAL,HIGH` to
every CI pipeline that builds or deploys a container image.

---

## Phase 2 — Triage

**What it means:** Not every CVE on the scanner report requires immediate action.
Validate that the vulnerability is real and applicable in your environment.

Triage questions:
1. Is the vulnerable library actually loaded by this application?
2. Is the vulnerable code path reachable from outside the container?
3. Is there a compensating control (NetworkPolicy, mTLS, WAF) that reduces exposure?
4. Does the CVE affect confidentiality, integrity, or availability — or all three?

Triage output: a priority assignment (Immediate / Scheduled / Accept Risk).

---

## Phase 3 — Prioritize

**What it means:** Given a list of validated vulnerabilities, determine the order
of remediation based on risk, not just severity score.

**CVSS vs EPSS — the two lenses:**

| Metric | Question Answered                                      | When to Weight It Heavily                            |
|--------|--------------------------------------------------------|------------------------------------------------------|
| CVSS   | How bad is this if exploited?                          | When sizing blast radius and compliance requirements |
| EPSS   | How likely is this to be exploited in the next 30 days?| When prioritizing between two CRITICAL CVEs          |

Prioritization model used in FedRAMP:
- CRITICAL CVE + EPSS > 0.5: Remediate within 15 days. No exceptions.
- CRITICAL CVE + EPSS < 0.1: Remediate within 15 days. No exceptions. (CVSS wins)
- HIGH CVE + EPSS > 0.5: Treat as CRITICAL — active exploitation in progress
- HIGH CVE + EPSS < 0.1: Remediate within 30 days. Document compensating controls.
- MEDIUM and below: Scheduled patch cycle. Accept risk with documented justification.

**What does "timely" mean under SI-2?**

NIST SI-2 requires remediation within "organizationally defined time periods." For
FedRAMP Moderate, those time periods are defined in the NIST 800-53 SI-2 control
parameters:

| Severity  | Maximum Remediation Time (FedRAMP Moderate) |
|-----------|---------------------------------------------|
| CRITICAL  | 15 calendar days from identification        |
| HIGH      | 30 calendar days from identification        |
| MODERATE  | 180 calendar days from identification       |
| LOW       | 365 calendar days from identification       |

The clock starts when the vulnerability is identified — not when you decide to start
working on it. If you ran the Trivy scan today and found a CRITICAL CVE, the POA&M
must show remediation complete within 15 days from today.

---

## Phase 4 — Remediate

**What it means:** Apply the fix. In this case, two levels of fix are required.

**Immediate fix (done):** `kubectl rollout undo` restored the previous image.
The vulnerability is no longer running in production.

**Structural fix (required — this is the real remediation):**

1. Pin all images by digest in the deployment manifests
2. Add Trivy to CI as a blocking gate before image push
3. Enable admission control to reject images without a scan attestation
4. Add a periodic re-scan CronJob for all running images

Without the structural fix, the next operator who swaps an image will face the same
situation. The emergency rollback only fixed this instance. It did not close the root
cause.

---

## Phase 5 — Verify

**What it means:** Prove that the fix worked. Re-scan. Compare before and after.
Do not close a POA&M item without evidence of remediation.

Run `verify.sh` to:
- Scan the restored image and count CRITICAL CVEs
- Confirm the count is lower than the baseline before the break
- Confirm the pod is Running and healthy

A POA&M item is not closed by saying "we rolled it back." It is closed by showing
a scan report with CRITICAL count = 0 and a pod health check showing Running.

---

## Phase 6 — Document

**What it means:** Record the full lifecycle in the risk register.

Required documentation for SI-2 compliance:
- Date vulnerability was identified (scan timestamp)
- CVE IDs and CVSS scores at time of identification
- Triage decision and rationale
- Remediation action taken
- Date remediation was completed
- Post-remediation scan showing fix was effective
- Signature of responsible party (GRC owner or system owner)

This documentation goes into the POA&M and is presented to the auditor at the next
ATO review. Missing any of these elements means the control cannot be marked as
"satisfied" — only "partially implemented."

---

## GRC: What Would You Present to the Risk Committee?

If this were a production system, what would you say to leadership?

"We identified a CRITICAL vulnerability in the Portfolio API container image at
[timestamp]. The image was deployed without passing through our CI scanning gate.
We contained the exposure by rolling back to the previously scanned image within
[X hours] of identification. The root cause is a missing Trivy gate in our
deployment pipeline. We are implementing that gate now, with an expected completion
date of [date]. Until the gate is in place, we are manually scanning all image
changes before deployment. The SI-2 remediation clock for the specific CVEs is
satisfied — the vulnerable image is no longer running. The process gap has a
completion date in the POA&M."

That is a mature response. It addresses the immediate finding, the root cause, the
timeline, and the interim compensating control. It does not minimize or overstate.

---

## CIS 7.4 Gap: What "Automated Patch Management" Means

CIS v8 Control 7.4 requires automated application patch management. In a container
environment, this means:
- Images are rebuilt from updated base images on a schedule (weekly or on CVE publication)
- CI fails the build if CRITICAL CVEs are present
- The registry contains only scanned, signed images
- Admission control prevents unsigned or unscanned images from deploying

Using `python:3.9-slim` as a mutable tag fails CIS 7.4 because:
- There is no automation — the tag may drift without triggering a rebuild or scan
- There is no audit trail — you cannot prove what version ran on what date
- There is no gate — nothing prevents a CVE-laden image from being deployed

---

## References

- NIST 800-53 Rev 5: SI-2 Flaw Remediation
- NIST 800-53 Rev 5: RA-5 Vulnerability Scanning
- NIST CSF 2.0: ID.RA-01 — Vulnerabilities identified, validated, and recorded
- CIS Controls v8: 7.4 Perform Automated Application Patch Management
- FedRAMP Vulnerability Scanning Requirements
- FIRST EPSS: https://www.first.org/epss/
- Trivy: https://aquasecurity.github.io/trivy/
- CompTIA CySA+ Exam Objective 1.3: Explain the importance of vulnerability management
