# L7-02 PR.PS-01 — Report Template: Missing Security Headers

**Analyst:** ___________________________
**Date:** ___________________________
**Cluster:** k3d-seclab
**Namespace:** anthra
**Scenario:** L7-02-PR.PS-01-security-headers

---

## Executive Summary

> Fill in one paragraph. Example:
>
> The Portfolio UI nginx deployment was found to be missing all HTTP security
> response headers. The hardened headers (CSP, X-Frame-Options, X-Content-Type-Options,
> HSTS, Referrer-Policy, X-XSS-Protection, Permissions-Policy) that are baked
> into the Dockerfile were absent from live HTTP responses, indicating the nginx
> config was overwritten at runtime. This exposed users to clickjacking,
> cross-site scripting, MIME sniffing, and TLS downgrade attacks. The headers
> were restored and the deployment was reverted to its hardened state.

---

## Finding Table

| Field                | Value                                                        |
|----------------------|--------------------------------------------------------------|
| Finding ID           | L7-02-YYYY-MM-DD                                             |
| Title                | Missing HTTP Security Headers -- Portfolio UI nginx           |
| Asset                | portfolio-anthra-portfolio-app-ui (anthra namespace)         |
| Component            | nginx-unprivileged, /etc/nginx/conf.d/default.conf           |
| CSF Control          | PR.PS-01 -- Configuration management                         |
| CIS v8               | 16.12 -- Implement Code-Level Security Checks                |
| NIST 800-53          | SI-10 -- Information Input Validation, SC-8 -- Transmission Confidentiality |
| Severity             | Medium                                                       |
| Rank                 | D -- Deterministic fix                                        |
| Status               | [ ] Open   [ ] In Remediation   [ ] Closed                   |

---

## HTTP Response -- Before and After

### Before Remediation (Vulnerable State)

Paste the output of:

    kubectl exec -n anthra <UI_POD> -- curl -sI http://localhost:8080/ 2>/dev/null

    [paste curl -sI output here]

Missing headers confirmed:
- [ ] Content-Security-Policy
- [ ] X-Frame-Options
- [ ] X-Content-Type-Options
- [ ] X-XSS-Protection
- [ ] Referrer-Policy
- [ ] Permissions-Policy
- [ ] Strict-Transport-Security

### After Remediation (Hardened State)

Paste the output of verify.sh or a fresh curl:

    [paste verify.sh output here]

Headers confirmed present:
- [ ] Content-Security-Policy
- [ ] X-Frame-Options
- [ ] X-Content-Type-Options
- [ ] X-XSS-Protection
- [ ] Referrer-Policy
- [ ] Permissions-Policy
- [ ] Strict-Transport-Security

---

## Timeline

| Time (UTC)          | Event                                                         |
|---------------------|---------------------------------------------------------------|
| ___________         | Ticket received / anomaly noticed                            |
| ___________         | Ran baseline.sh -- confirmed headers present or absent        |
| ___________         | Ran break.sh -- headers stripped for training scenario        |
| ___________         | Followed detect.md -- confirmed finding via curl              |
| ___________         | Followed investigate.md -- scoped, ranked as D-rank           |
| ___________         | Ran fix.sh -- headers restored, nginx reloaded                |
| ___________         | Ran verify.sh -- all 7 headers PASS, HTTP 200 PASS            |
| ___________         | Report completed                                             |

---

## Root Cause

Select one and describe:

[ ] Runtime config overwrite -- Someone exec'd into the pod and overwrote
    /etc/nginx/conf.d/default.conf with a stripped config. Possible causes:
    operator error, unauthorized access, or a misconfigured automated tool.

[ ] Image build gap -- The Dockerfile did not include the security headers
    when the image was built. The current Dockerfile does include them -- this
    would indicate the image in production was built from an older revision.

[ ] Break scenario (training) -- This was intentionally introduced by
    break.sh for training purposes.

Root cause detail:

    [describe what you found -- config file content, pod start time, rollout history]

---

## Remediation Checklist

- [ ] Ran fix.sh -- hardened config restored to running pod
- [ ] Confirmed nginx reloaded successfully (nginx -t passed)
- [ ] Ran verify.sh -- all 7 headers PASS, HTTP 200 PASS
- [ ] Deployment patch reverted -- readOnlyRootFilesystem: true restored
- [ ] No nginx-conf-d emptyDir volume remaining in deployment spec
- [ ] Confirmed deployment rollout completed cleanly

---

## POA&M Entry

Use this section if the finding is being tracked in a Plan of Action and
Milestones for a compliance framework (FedRAMP, NIST, etc.).

| Field                  | Value                                                      |
|------------------------|------------------------------------------------------------|
| POA&M ID               | POAM-L7-02-YYYY-MM-DD                                      |
| Control                | PR.PS-01 / CIS 16.12 / NIST SI-10 / SC-8                 |
| Weakness               | HTTP security response headers absent from UI origin server |
| Asset                  | portfolio-anthra-portfolio-app-ui                          |
| Scheduled Completion   | ___________                                                |
| Corrective Action      | Restore hardened nginx config; re-enable readOnlyRootFilesystem |
| Responsible Entity     | ___________________________                                |
| Status                 | [ ] Planned   [ ] In Progress   [ ] Completed              |
| Evidence               | verify.sh output, curl -sI before/after, deployment yaml  |

---

## GRC Section -- What Would You Document for an Auditor?

Answer each question in one to two sentences.

1. What control was being tested?

CIS 16.12 requires that code-level security checks be implemented. For a web
application, this includes the security headers set in the nginx configuration
that is part of the container image (the code artifact).

2. What was the finding?

    [Your answer here]

3. What is the evidence that the finding existed?

    [Paste evidence file paths and key output here]

4. What is the evidence that it was remediated?

    [Paste verify.sh output or curl output here]

5. Why is this finding Medium severity and not High?

    [Consider: is the service internet-facing? What is the realistic attack path?
     What mitigating controls are in place? The service is ClusterIP. Write your
     assessment here.]

6. What is the permanent preventive control?

The Dockerfile bakes the hardened nginx config at build time. The Helm chart
sets readOnlyRootFilesystem: true to prevent runtime overwrite. Together,
these controls make it structurally difficult to serve responses without the
security headers. The scenario demonstrated what happens when those controls
are bypassed -- and why they should not be bypassed.

---

## Lessons Learned

Write one to three sentences on what this scenario taught you.

    [Example: I learned that security headers are invisible to users and monitoring
     systems -- the page loads identically whether or not they are present. Detection
     requires explicit header checks in CI/CD, periodic config audits, or external
     scanner runs. Missing headers are a silent vulnerability.]

---

## CySA+ Analyst Notes

Detection method used: Manual header inspection via curl inside the pod

Tool limitation noted: Grafana/Falco does not detect missing response headers.
This is a configuration gap, not a runtime event. External scanners check this
at the HTTP layer.

OWASP reference: OWASP Secure Headers Project -- all seven headers in this
scenario are documented there with attack scenarios and recommended values.

Attack technique prevented by CSP: MITRE ATT&CK T1059.007 -- JavaScript
execution via injected script tags (XSS prerequisite).

Attack technique prevented by HSTS: MITRE ATT&CK T1557.002 -- ARP cache
poisoning enabling SSL stripping as part of adversary-in-the-middle.

---

Report completed by: ___________________________
Reviewed by: ___________________________
Date closed: ___________________________
