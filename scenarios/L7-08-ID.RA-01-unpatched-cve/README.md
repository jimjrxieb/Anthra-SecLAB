# L7-08 — ID.RA-01: Unpatched CVE in Container Image

## Scenario Summary

The Portfolio API deployment is running a pinned production image. During a routine
change, an operator swaps the base image to `python:3.9-slim` — an unversioned,
unpinned tag that pulls whatever the Docker Hub maintainer last pushed. That image
carries known CRITICAL and HIGH CVEs in core packages (openssl, glibc, pip, setuptools)
that have public exploits and EPSS scores above 0.5.

The application may still respond — or it may crash entirely because the Python
runtime version differs from what the application expects. Either outcome is a
finding. A vulnerability that causes availability impact is not better than one that
doesn't. It is worse: you have two problems instead of one.

The scenario teaches the full vulnerability management lifecycle:
identify (Trivy scan), validate (CVSS + EPSS scoring), record (POA&M entry),
remediate (rollback + pin), verify (rescan). This is the cycle CySA+ OBJ 1.3
expects every analyst to execute without prompting.

---

## Control Mapping

| Field            | Value                                                                          |
|------------------|--------------------------------------------------------------------------------|
| CSF Function     | IDENTIFY                                                                       |
| CSF Category     | ID.RA — Risk Assessment                                                        |
| CSF Subcategory  | ID.RA-01 — Vulnerabilities identified, validated, and recorded                 |
| CIS v8 Control   | 7.4 — Perform Automated Application Patch Management                           |
| NIST 800-53      | SI-2 — Flaw Remediation; RA-5 — Vulnerability Scanning                        |
| OSI Layer        | Layer 7 — Application                                                          |
| Severity         | CRITICAL                                                                       |
| Rank             | C — Analyst confirms context before rollback; auto-rollback requires approval  |
| Difficulty       | Level 1                                                                        |

---

## What Breaks

The `portfolio-anthra-portfolio-app-api` deployment has its container image swapped
to `python:3.9-slim`. This tag:

- Is not pinned by digest — it drifts silently when Docker Hub pushes a new manifest
- Carries 20+ known CVEs in system packages (openssl, libssl, glibc, zlib)
- May have a different Python minor version than what the application's requirements
  were built against, causing import errors or startup failures
- Has no Trivy scan provenance — there is no CI gate that ran before it was deployed

The finding exists whether the pod is Running or CrashLoopBackOff. A running pod with
CRITICAL CVEs is a vulnerability. A crashed pod with CRITICAL CVEs is a vulnerability
and an availability incident.

---

## Affected Assets

- **Namespace:** anthra
- **Deployment:** portfolio-anthra-portfolio-app-api
- **Container:** api
- **Image (broken):** python:3.9-slim (unpinned, unscanned)
- **Image (production):** the original pinned image (visible in rollout history)

---

## Scenario Lifecycle

| Phase       | File                 | What Happens                                                        |
|-------------|----------------------|---------------------------------------------------------------------|
| Baseline    | `baseline.sh`        | Scan current production images, record CVE counts as baseline       |
| Break       | `break.sh`           | Swap API image to python:3.9-slim, wait for rollout                 |
| Detect      | `detect.md`          | L1: Trivy scan the new image, read CVSS scores, check pod health    |
| Investigate | `investigate.md`     | Triage CVEs by exploitability, calculate blast radius, draft POA&M  |
| Fix         | `fix.sh`             | Rollback to original image, show proper pin-by-digest pattern       |
| Remediate   | `remediate.md`       | Vulnerability management lifecycle, CVSS vs EPSS, SI-2 timelines    |
| Verify      | `verify.sh`          | Rescan restored image, compare CRITICAL count, confirm pod health    |
| Report      | `report-template.md` | CVE table, POA&M with SI-2/CIS 7.4, risk committee summary          |

---

## Why This Matters

NIST SI-2 (Flaw Remediation) requires that organizations identify, report, and
correct software flaws. The control explicitly requires that flaw-related updates be
tested and installed within organizationally defined time periods. For FedRAMP Moderate,
those time periods are: CRITICAL within 15 days, HIGH within 30 days.

RA-5 (Vulnerability Scanning) requires that vulnerability scans occur at a defined
frequency — not just once at image build time. An image that passes a scan today can
fail next week when new CVEs are published against its packages.

CIS 7.4 requires automated patch management for applications. Using an unpinned image
tag like `python:3.9-slim` defeats automated patch management — you cannot track what
changed, cannot audit what version was deployed when, and cannot verify a fix was
applied without re-scanning from scratch.

ID.RA-01 closes the loop: vulnerabilities must be identified, validated (not just
flagged — confirmed to be real and relevant), and recorded in the risk register or
POA&M. Running a scan and closing the terminal without documenting the finding is not
compliance. It is theater.

---

## CySA+ OBJ 1.3 Teaching Point

Vulnerability management is not scanning. Scanning is the input. Triage is the work.

OBJ 1.3 expects the analyst to know:

- CVSS v3.1 Base Score: what the vulnerability looks like in isolation
- CVSS Environmental Score: what it looks like in this specific environment
- EPSS: probability that this CVE will be exploited in the next 30 days
- Compensating controls: does a WAF, network policy, or authentication layer reduce
  the exposure even if the CVE cannot be patched immediately?
- Remediation priority: not all CRITICAL CVEs are equal; prioritize by exploitability
  and exposure

The exam will ask you to differentiate between these. This scenario makes the
distinction concrete with real output from a real scanner.

---

## References

- NIST 800-53 Rev 5: SI-2 Flaw Remediation
- NIST 800-53 Rev 5: RA-5 Vulnerability Scanning
- NIST CSF 2.0: ID.RA-01
- CIS Controls v8: 7.4 Perform Automated Application Patch Management
- Trivy documentation: https://aquasecurity.github.io/trivy/
- EPSS documentation: https://www.first.org/epss/
- FedRAMP vulnerability scanning requirements: https://www.fedramp.gov/assets/resources/documents/CSP_Vulnerability_Scanning_Requirements.pdf
- CompTIA CySA+ Exam Objective 1.3: Explain the importance of vulnerability management
