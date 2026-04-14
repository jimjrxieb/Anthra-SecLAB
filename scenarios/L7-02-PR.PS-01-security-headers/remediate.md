# L7-02 PR.PS-01 — Remediate: Why Security Headers Matter

**Role:** L1 Security Analyst
**CSF:** PROTECT / PR.PS-01
**CIS v8:** 16.12
**NIST 800-53:** SI-10, SC-8

This document explains why each security header matters, what attack it prevents,
and why baking it into the Dockerfile is the correct long-term approach. Use this
when writing your report or explaining the finding to a developer or manager.

---

## The OWASP Secure Headers Project

The OWASP Secure Headers Project maintains the authoritative reference for HTTP
security headers. Every header in this scenario is on that list. When a control
framework asks whether security headers are configured, this is what they mean.

CIS Controls v8 Control 16.12 — "Implement Code-Level Security Checks" — covers
exactly this: the developer is responsible for outputting correct security
headers. Not the ops team, not the CDN, not the load balancer. The application.

---

## Header Reference Table

| Header                      | Attack Prevented                         | Without This Header                              | CIS / NIST Control |
|-----------------------------|------------------------------------------|--------------------------------------------------|--------------------|
| Content-Security-Policy     | Cross-site scripting (XSS)               | Browser executes injected scripts from any source | SI-10, CIS 16.12  |
| X-Frame-Options             | Clickjacking                             | Attacker embeds page in iframe, harvests clicks  | SC-8               |
| X-Content-Type-Options      | MIME type sniffing                       | Browser may execute text/plain as JavaScript     | SI-10              |
| X-XSS-Protection            | Legacy browser XSS                       | Older browsers skip built-in XSS filter          | SI-10              |
| Referrer-Policy             | Referrer URL leakage                     | Full URL with tokens sent to third-party servers | SC-8               |
| Permissions-Policy          | Unauthorized browser feature access     | Scripts can request camera/mic without indication| SI-10              |
| Strict-Transport-Security   | HTTP downgrade / TLS stripping           | Network attacker silently downgrades HTTPS to HTTP | SC-8             |

---

## Deep Dive — Each Header

### Content-Security-Policy (CSP)

CSP tells the browser where it is allowed to load resources from. Without it,
any script tag — injected via XSS, compromised dependency, or ad network — runs
with full page privileges. CSP is the primary defense against XSS after output
encoding fails.

The Portfolio CSP is:
```
default-src 'self';
script-src 'self' 'unsafe-inline' 'unsafe-eval';
style-src 'self' 'unsafe-inline' https://fonts.googleapis.com;
font-src 'self' https://fonts.gstatic.com;
img-src 'self' data: https:;
connect-src 'self' https://linksmlm.com wss://linksmlm.com;
frame-ancestors 'self';
```

`unsafe-inline` and `unsafe-eval` are present because the React SPA requires
them. This is a common trade-off. A tighter CSP would use nonces for inline
scripts, but that requires server-side rendering. The current policy still
blocks third-party script loading and framing by external sites.

Without CSP: any stored XSS payload in the portfolio data runs with no
restriction. Session cookies, API tokens, and user actions are all accessible.

### X-Frame-Options

Prevents the page from being embedded in an `<iframe>` on another domain.
Without this, an attacker creates a page at `evil.example.com/click-me` that
loads the Portfolio UI in a transparent iframe and layers fake buttons over the
real interface. The user thinks they are clicking a game button. They are
actually clicking "Transfer funds" or "Export API key."

The value `SAMEORIGIN` allows iframes from the same origin (needed for some SPA
routing patterns). `DENY` is stricter if no iframes are needed.

CSP `frame-ancestors 'self'` provides the same protection in modern browsers.
Both are set for compatibility with older browsers that do not support CSP
frame-ancestors.

### X-Content-Type-Options: nosniff

IE and some legacy browsers will "sniff" the content type of a response if the
`Content-Type` header is missing or generic. This means a file served as
`text/plain` could be executed as JavaScript if the browser decides it looks
like a script. With `nosniff`, the browser strictly uses the declared content
type and does not guess.

The attack scenario: an attacker tricks the app into storing and serving a file
with a benign content type declaration that actually contains executable code.
Without `nosniff`, the browser may execute it.

### X-XSS-Protection: 1; mode=block

This header activates the built-in XSS filter in Internet Explorer 8-11 and
early Chrome/Safari. Modern browsers have deprecated it in favor of CSP. It is
included for defense in depth — if an old browser is used, the legacy filter
engages.

In `mode=block`, if the filter detects an XSS attempt it stops the entire page
from rendering rather than attempting sanitization (which can sometimes be
bypassed).

### Referrer-Policy: strict-origin-when-cross-origin

Controls what is sent in the `Referer` header when a user clicks a link to
another site. Without a policy, the full URL is sent, including path and query
parameters. If a page URL contains a password reset token or an API key in the
query string, that token is leaked to every external resource (analytics, CDN,
third-party fonts).

`strict-origin-when-cross-origin` sends only the scheme and hostname (e.g.,
`https://portfolio.example.com`) when navigating cross-origin, and nothing on
HTTP-to-HTTPS transitions.

### Permissions-Policy

Restricts which browser features the page is allowed to use. Without it, any
JavaScript on the page (including injected third-party scripts) can call
`getUserMedia()` to request camera and microphone access, or `getCurrentPosition()`
for geolocation — and the browser permission prompt may appear as if the trusted
site is asking, not an injected script.

The value `geolocation=(), microphone=(), camera=()` explicitly disables all
three for this page. If the portfolio app does not use these features, there is
no reason to allow them.

### Strict-Transport-Security (HSTS)

Tells the browser that this site must only ever be accessed over HTTPS, for the
next `max-age` seconds (31536000 = 1 year). After the first HTTPS visit, the
browser will not follow an HTTP link to this site — it will automatically upgrade
to HTTPS before making the request.

Without HSTS, a network attacker (on the same WiFi, or an ISP with malicious
routing) can perform an SSL stripping attack: they intercept the initial HTTP
request before the redirect to HTTPS happens, and serve a fake HTTP version of
the site. The user's browser shows HTTP, the padlock is gone, and credentials
are sent in plaintext.

`includeSubDomains` extends the policy to all subdomains, preventing an attacker
from setting a cookie on a subdomain over HTTP that poisons the parent domain.

---

## The Permanent Fix — Bake Headers into the Dockerfile

The correct fix is already in place in the source code. The Dockerfile writes
the hardened config at build time:

```dockerfile
RUN echo 'server { \
    listen 8080; \
    ... \
    add_header Content-Security-Policy "..." always; \
    add_header X-Frame-Options "SAMEORIGIN" always; \
    ...
}' > /etc/nginx/conf.d/default.conf
```

This means:
- Every container built from this image has the headers
- readOnlyRootFilesystem: true prevents runtime overwrite
- A config audit can verify by reading the Dockerfile, not checking a running pod

This scenario simulates what happens when someone bypasses those protections
by patching readOnlyRootFilesystem: false and exec-ing into the pod. The fix
is to restore the protections — which fix.sh does.

**For production hardening beyond this scenario:**

1. Mount `/etc/nginx/conf.d/` from a ConfigMap (immutable config, auditable in git)
2. Use a Kyverno policy that alerts on deployments setting `readOnlyRootFilesystem: false`
3. Add a CI check that scans the built image for the presence of security headers
   in the nginx config before pushing to registry

---

## GRC Analyst Notes — CIS 16.12 and PR.PS-01

**CIS 16.12:** "Implement Code-Level Security Checks" — the security headers
baked into the Dockerfile ARE the code-level security check. They are part of
the build artifact. Auditing this control means checking whether the build
process includes header configuration, not whether an operator remembered to
configure it at runtime.

**PR.PS-01:** "Configuration management practices are established and applied"
— the finding is that an established configuration (hardened headers in the
Dockerfile) was not applied to the running system. The remediation is restoring
the established configuration, and the permanent control is ensuring the runtime
cannot deviate from it (readOnlyRootFilesystem + no writable mounts for conf.d/).

When writing the POA&M entry, the corrective action is:
1. Restore hardened nginx config (done — fix.sh)
2. Re-enable readOnlyRootFilesystem (done — fix.sh revert)
3. Add monitoring or policy to detect future deviations (enhancement — Kyverno)

---

## References

- OWASP Secure Headers Project: https://owasp.org/www-project-secure-headers/
- MDN Content-Security-Policy: https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP
- MDN Strict-Transport-Security: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security
- CIS Controls v8, Control 16.12
- NIST 800-53 Rev 5: SI-10, SC-8
- NIST CSF 2.0: PR.PS-01
