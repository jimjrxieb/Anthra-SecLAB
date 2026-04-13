# L7-01 — PR.AA-05: Admin API Endpoint Exposed

## Scenario Summary

The Portfolio FastAPI application exposes its interactive documentation endpoints
(`/docs`, `/redoc`, `/openapi.json`) by default. These endpoints reveal the full
API surface — every route, every parameter, every response schema — without
authentication. A threat actor who reaches port 8000 can enumerate all endpoints,
understand data flows, and craft targeted attacks without any credentials.

This is a configuration default, not a code vulnerability. FastAPI enables Swagger
UI and ReDoc out of the box. The fix is explicit — disable them in code, or block
them in the API layer. This scenario walks through discovering, investigating,
remediating, and verifying the fix.

---

## Control Mapping

| Field          | Value                                                        |
|----------------|--------------------------------------------------------------|
| CSF Function   | PROTECT                                                      |
| CSF Category   | PR.AA — Identity Management, Authentication, and Access Control |
| CSF Subcategory | PR.AA-05 — Access permissions, entitlements, and authorizations managed |
| CIS v8 Control | 3.3 — Configure Data Access Control Lists                    |
| NIST 800-53    | AC-3 — Access Enforcement                                    |
| OSI Layer      | Layer 7 — Application                                        |
| Severity       | Medium                                                       |
| Rank           | D — Deterministic fix, auto-remediate with logging           |
| Difficulty     | Level 1                                                      |

---

## What Breaks

FastAPI ships with documentation enabled by default:

- `/docs` — Swagger UI (interactive, can issue live requests)
- `/redoc` — ReDoc viewer (read-only API reference)
- `/openapi.json` — Machine-readable schema (full API surface in one file)

None of these require authentication. Anyone who can reach port 8000 gets a
complete map of the API. In this lab, the API is ClusterIP — not internet-facing.
That reduces risk, but does not eliminate it. A compromised pod inside the cluster
can reach it. A misconfigured ingress can expose it. Defense-in-depth means
closing this regardless of current network posture.

---

## Affected Assets

- **Namespace:** anthra
- **Deployment:** portfolio-anthra-portfolio-app-api
- **Service:** portfolio-anthra-portfolio-app-api (ClusterIP, port 8000)
- **Endpoints:** /docs, /redoc, /openapi.json

---

## Scenario Lifecycle

| Phase       | File              | What Happens                                        |
|-------------|-------------------|-----------------------------------------------------|
| Baseline    | `baseline.sh`     | Capture endpoint status before any changes          |
| Break       | `break.sh`        | Verify the vulnerability pre-exists (realistic)     |
| Detect      | `detect.md`       | L1 analyst discovers the exposure                   |
| Investigate | `investigate.md`  | Scope, classify, rank, decide                       |
| Remediate   | `fix.sh`          | Disable docs via environment variable               |
| Verify      | `verify.sh`       | Confirm endpoints are blocked, /health still works  |
| Report      | `report-template.md` | Fill-in evidence template                        |

---

## Why This Matters

NIST AC-3 requires that the system enforce approved authorizations for accessing
system resources. An unauthenticated documentation endpoint is not an approved
authorization — it is a default that nobody explicitly permitted.

CIS 3.3 requires that data access control lists be configured to deny by default.
The API schema is data about the system. It should not be readable without
authorization.

In a FedRAMP Moderate environment, this finding would appear in the AC family
gap analysis and require a POA&M entry if not remediated before assessment.

---

## References

- NIST 800-53 Rev 5: AC-3 Access Enforcement
- CIS Controls v8: 3.3 Configure Data Access Control Lists
- NIST CSF 2.0: PR.AA-05
- FastAPI Security docs: https://fastapi.tiangolo.com/tutorial/security/
