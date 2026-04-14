# L7-02 — PR.PS-01: Security Headers Stripped from UI

## Scenario Summary

The Portfolio UI runs nginx-unprivileged on port 8080. The Dockerfile bakes in
six hardened security headers that protect users from clickjacking, cross-site
scripting, MIME sniffing, protocol downgrade, and unwanted resource access. They
are set in `/etc/nginx/conf.d/default.conf` at image build time.

In this scenario, a misconfiguration or unauthorized change has overwritten that
config with a minimal, header-free nginx block. The headers are gone. The UI
still loads and looks identical to a user, but the browser receives no security
directives. Every user visiting the page is exposed.

This scenario walks through discovering the gap, investigating scope and impact,
restoring the headers, and writing the evidence an auditor needs.

---

## Control Mapping

| Field              | Value                                                                 |
|--------------------|-----------------------------------------------------------------------|
| CSF Function       | PROTECT                                                               |
| CSF Category       | PR.PS — Platform Security                                             |
| CSF Subcategory    | PR.PS-01 — Configuration management practices are established and applied |
| CIS v8 Control     | 16.12 — Implement Code-Level Security Checks                         |
| NIST 800-53        | SI-10 — Information Input Validation, SC-8 — Transmission Confidentiality |
| OSI Layer          | Layer 7 — Application                                                 |
| Severity           | Medium                                                                |
| Rank               | D — Deterministic fix, auto-remediate with logging                   |
| Difficulty         | Level 1                                                               |

---

## What Breaks

The original Dockerfile bakes these six headers into the nginx config:

| Header                      | Protects Against                            |
|-----------------------------|---------------------------------------------|
| Content-Security-Policy     | XSS, inline script injection                |
| X-Frame-Options             | Clickjacking via iframe embedding           |
| X-Content-Type-Options      | MIME type sniffing attacks                  |
| X-XSS-Protection            | Legacy browser XSS filter bypass           |
| Referrer-Policy             | Referrer header data leakage                |
| Permissions-Policy          | Unauthorized camera, mic, geolocation access |
| Strict-Transport-Security   | HTTP downgrade attacks                      |

When the config is overwritten, all seven headers disappear from every HTTP
response. The UI serves pages with no browser security policy in place. A user
visiting from a phishing link could have their session hijacked. An iframe on an
attacker page could frame the entire portfolio site.

---

## Affected Assets

- **Namespace:** anthra
- **Deployment:** portfolio-anthra-portfolio-app-ui
- **Service:** portfolio-anthra-portfolio-app-ui (ClusterIP, port 80 → targetPort 8080)
- **Container:** nginx-unprivileged (port 8080)
- **Config path:** /etc/nginx/conf.d/default.conf

---

## Dual Lens

This scenario is designed for two analyst roles. Both paths are documented.

**CySA+ Analyst:** Technical discovery via curl, header-by-header gap analysis,
understanding what each missing header enables an attacker to do.

**GRC Analyst:** Control testing for CIS 16.12, CSF PR.PS-01 documentation,
POA&M entry template, auditor evidence packaging.

Both roles reach the same finding. The framing and output artifacts differ.

---

## Scenario Lifecycle

| Phase       | File                 | What Happens                                           |
|-------------|----------------------|--------------------------------------------------------|
| Baseline    | `baseline.sh`        | Capture current header state before any changes        |
| Break       | `break.sh`           | Overwrite nginx config to strip all security headers   |
| Detect      | `detect.md`          | L1 analyst discovers the missing headers               |
| Investigate | `investigate.md`     | Scope, classify, rank, decide                          |
| Fix         | `fix.sh`             | Restore hardened nginx config with all headers         |
| Remediate   | `remediate.md`       | Why each header matters, permanent fix guidance        |
| Verify      | `verify.sh`          | Confirm all headers present, page still loads          |
| Report      | `report-template.md` | Fill-in evidence template for auditors                 |

---

## Why This Matters

NIST SI-10 requires that the system validate information inputs. HTTP response
headers are the primary mechanism by which a web server communicates security
policy to the browser. Stripping them is a configuration failure that removes
browser-enforced controls entirely.

NIST SC-8 requires confidentiality and integrity protection for transmissions.
HSTS is the header that enforces HTTPS at the browser level. Without it, a
network attacker can strip TLS and serve HTTP. The data crosses the wire in
plaintext.

CIS 16.12 requires that code-level security checks be implemented as part of
the software development process. Security headers baked into the Dockerfile
are exactly this — a code-level security check. Overwriting that config
bypasses the control at the point it was applied.

In a FedRAMP Moderate environment, missing security headers appear in the SI and
SC control families and require a POA&M entry if not remediated before assessment.

---

## References

- NIST 800-53 Rev 5: SI-10 Information Input Validation
- NIST 800-53 Rev 5: SC-8 Transmission Confidentiality and Integrity
- NIST CSF 2.0: PR.PS-01
- CIS Controls v8: 16.12 Implement Code-Level Security Checks
- OWASP Secure Headers Project: https://owasp.org/www-project-secure-headers/
- MDN Web Docs — HTTP Security Headers: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers
