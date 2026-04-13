# L7-01 PR.AA-05 — Incident Report Template

**Finding:** Unauthenticated API Documentation Endpoint Exposure
**Date:** [YYYY-MM-DD]
**Analyst:** [Name / Badge]
**Status:** [ ] Open  [ ] Remediated  [ ] Verified  [ ] Closed

---

## Finding Summary

| Field               | Value                                                        |
|---------------------|--------------------------------------------------------------|
| Asset               | portfolio-anthra-portfolio-app-api                           |
| Namespace           | anthra                                                       |
| Cluster             | k3d-seclab                                                   |
| Affected endpoints  | /docs, /redoc, /openapi.json                                 |
| HTTP status (before) | [200 / ERR — fill in from baseline.sh output]               |
| HTTP status (after)  | [404 / ERR — fill in from verify.sh output]                 |
| Authentication required | No (before fix)                                         |
| Exposure scope      | [ClusterIP / NodePort / LoadBalancer — fill in]              |
| Prior exploitation  | [Yes / No — fill in from access log review]                  |
| CSF                 | PR.AA-05 — Access permissions managed                        |
| CIS v8              | 3.3 — Configure Data Access Control Lists                    |
| NIST 800-53         | AC-3 — Access Enforcement                                    |
| Severity            | Medium                                                       |
| Rank                | D                                                            |

---

## Timeline

| Time (UTC)         | Event                                                        |
|--------------------|--------------------------------------------------------------|
| [YYYY-MM-DDTHH:MM] | Baseline captured (baseline.sh)                             |
| [YYYY-MM-DDTHH:MM] | Break confirmed — /docs returning 200 (break.sh)            |
| [YYYY-MM-DDTHH:MM] | Detection completed — endpoints tested (detect.md Step 3)   |
| [YYYY-MM-DDTHH:MM] | Exposure scope determined — [ClusterIP / other]              |
| [YYYY-MM-DDTHH:MM] | OpenAPI schema downloaded — [N] routes enumerated            |
| [YYYY-MM-DDTHH:MM] | Access logs reviewed — prior hits: [Yes/No]                  |
| [YYYY-MM-DDTHH:MM] | Fix applied (fix.sh) — DISABLE_DOCS=true set                 |
| [YYYY-MM-DDTHH:MM] | Rollout complete — new pod running                           |
| [YYYY-MM-DDTHH:MM] | Verification passed (verify.sh) — all checks PASS            |
| [YYYY-MM-DDTHH:MM] | Report completed                                            |

---

## Root Cause

FastAPI enables interactive documentation (/docs), ReDoc (/redoc), and the
OpenAPI schema (/openapi.json) by default when a FastAPI application is
instantiated with FastAPI(). These endpoints were not explicitly disabled
when the application was deployed to the cluster.

The root cause is a missing secure default in the application code. The FastAPI
constructor was called without docs_url=None, redoc_url=None, openapi_url=None,
and no compensating control (environment variable check, ingress rule, or WAF
policy) was in place to block access.

This is a configuration default issue, not a vulnerability in FastAPI itself.
FastAPI documents how to disable these endpoints. The configuration was simply
never applied.

---

## Remediation Applied

- [ ] baseline.sh ran — pre-fix endpoint status captured
- [ ] break.sh ran — vulnerability confirmed pre-existing
- [ ] Exposure scope verified — service type checked, ingress reviewed
- [ ] Access logs reviewed — prior documentation endpoint hits checked
- [ ] fix.sh ran — DISABLE_DOCS=true set on deployment
- [ ] Rollout completed — deployment rolled to new pod
- [ ] verify.sh ran — all four checks PASS (/docs 404, /redoc 404, /openapi.json 404, /health 200)
- [ ] Evidence package saved to: /tmp/L7-01-evidence-[timestamp]/
- [ ] Code change tracked in backlog (permanent fix: FastAPI(docs_url=None, ...))

---

## Evidence Artifacts

| Artifact                     | Location                                            |
|------------------------------|-----------------------------------------------------|
| Baseline endpoint status     | /tmp/L7-01-baseline-[timestamp].txt                 |
| OpenAPI schema (exposure)    | /tmp/L7-01-evidence-[timestamp]/openapi.json        |
| Deployment YAML (before)     | /tmp/L7-01-evidence-[timestamp]/deployment.yaml     |
| Verify output                | [paste verify.sh output here]                       |

---

## POA&M Entry

| Field               | Value                                                        |
|---------------------|--------------------------------------------------------------|
| POA&M ID            | POA&M-L7-01-[YYYY-MM-DD]                                    |
| Control             | AC-3 / PR.AA-05 / CIS 3.3                                   |
| Weakness            | Unauthenticated API documentation endpoint exposure          |
| Asset               | portfolio-anthra-portfolio-app-api                           |
| Risk Level          | Medium                                                       |
| Mitigation Applied  | DISABLE_DOCS=true set via kubectl set env (runtime)          |
| Scheduled Completion | [Date for code-level fix in main.py]                        |
| Responsible Party   | [Engineer responsible for code change]                       |
| Status              | [ ] Open  [ ] In Progress  [ ] Completed                     |
| Notes               | Runtime fix applied. Code-level fix (docs_url=None) required for permanent remediation. See remediate.md. |

---

## Lessons Learned

**What went well:**

[Fill in: What detection method was most effective? What was the fastest path to confirmation?]

**What was missed or delayed:**

[Fill in: Was Falco useful here? No — and that gap is documented. Was log review useful?]

**What to do differently next time:**

[Fill in: Should this be a pre-deployment gate in CI? Should baseline.sh run on every deployment?]

**Tool gaps identified:**

- Falco does not detect application-layer access control defaults. This finding
  required manual configuration audit. Runtime detection is not a compensating
  control for application-layer exposure.
- [Fill in any other gaps observed during this scenario]

**Improvement actions:**

- [ ] Add a CI check that fails the pipeline if docs_url=None is not set in main.py
- [ ] Add /docs and /openapi.json to automated endpoint scans in 01-APP-SEC
- [ ] Document this pattern in the FastAPI golden path template in 00-PLATFORM-SETUP
