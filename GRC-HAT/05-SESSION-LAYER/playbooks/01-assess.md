# 01-assess.md — L5 Session Layer Assessment

| Field | Value |
|---|---|
| **NIST Controls** | AC-12, SC-23, IA-2, IA-8, AC-6 |
| **Tools** | Browser DevTools, Burp Suite, jwt.io, kubectl, az CLI, Keycloak admin |
| **Enterprise Equiv** | Qualys Web App Scanning ($80K+/yr), Tenable.io ($100K+/yr) |
| **Time** | 3 hours |
| **Rank** | B (requires human interpretation of session behavior) |

---

## Purpose

Document the current session management posture before implementing any controls. This assessment establishes the baseline for measuring improvement. Resist the urge to fix — map first.

---

## Assessment Checklists

### AC-12 Session Termination (10 items)

Verify sessions end when they should. Attacker persistence depends on long-lived or non-terminating sessions.

- [ ] What is the idle timeout for standard user sessions? (Target: 15 minutes or less)
- [ ] What is the idle timeout for privileged/admin sessions? (Target: 2-5 minutes)
- [ ] What is the maximum session lifetime regardless of activity? (Target: 8-24 hours)
- [ ] Do sessions terminate when the browser is closed? (Session cookies vs persistent cookies)
- [ ] Does the application expose a logout function on every authenticated page?
- [ ] Does logout destroy the session server-side, not just clear the cookie? (Test: capture cookie, logout, replay cookie — server should reject it)
- [ ] Are all sessions invalidated on password change? (Test: log in two browsers, change password in one, check if second session is revoked)
- [ ] Are all sessions invalidated on MFA enrollment change? (Entra ID: check Continuous Access Evaluation)
- [ ] Is there a limit on concurrent sessions per user? (Target: 3-5 max)
- [ ] Can an admin forcibly terminate another user's active sessions? (Keycloak admin → User → Sessions)

**Priority:** Items 6 (server-side logout) and 7 (password change revocation) are the highest-impact gaps. They enable credential-stuffing and session takeover persistence.

---

### SC-23 Session Authenticity (6 items)

Verify session identifiers cannot be predicted, forged, or reused after authentication upgrade.

- [ ] Is the session ID regenerated on login? (Test: compare session cookie before and after submitting credentials — must differ)
- [ ] Is the session ID regenerated on privilege escalation? (e.g., elevating to admin view, sudo mode, step-up auth)
- [ ] Does the application accept externally-set session IDs? (Test: send a request with a made-up session ID — server must reject it, not create a new session for it)
- [ ] Are URL-based session IDs disabled? (Check: is JSESSIONID or token appearing in URLs? — exposed in browser history, server logs, referrer headers)
- [ ] What is the session ID length and entropy? (Target: 128+ bits — measure with `wc -c` on base64-decoded value)
- [ ] Is the session ID cryptographically random? (Sequential or time-based IDs can be guessed — check for patterns across multiple sessions)

---

### Token Handling (7 items)

Session tokens are the credential after login. Their properties determine what an attacker can do with a stolen token.

- [ ] What type of tokens are used? (Session cookies / JWT / OAuth access token / SAML assertion — document each)
- [ ] Do JWTs include an `exp` (expiration) claim? (Decode at jwt.io — missing exp = token never expires)
- [ ] Do JWTs include a `jti` (JWT ID) claim for per-token revocation?
- [ ] Is the JWT signing algorithm RS256 or ES256? (HS256 with a weak secret is crackable; `alg: none` is a known bypass)
- [ ] Are refresh tokens rotated on each use? (New refresh token issued per exchange — reuse should return error)
- [ ] Is refresh token reuse detection enabled? (If old refresh token is replayed after rotation, revoke the entire token family)
- [ ] Are access tokens short-lived? (Target: 5-15 minutes — check `exp` claim delta)

**Priority:** Items 3 (alg check) and 5 (refresh rotation) — algorithm confusion and refresh token reuse are the two most exploited JWT vulnerabilities in CTF and real-world incidents.

---

### Cookie Security (6 items)

Session cookies are the primary credential for browser-based apps. Cookie attributes control theft and injection vectors.

- [ ] Are session cookies marked `Secure`? (Check in browser DevTools → Application → Cookies — missing Secure = cookie sent over HTTP)
- [ ] Are session cookies marked `HttpOnly`? (Missing HttpOnly = XSS can steal the session cookie with `document.cookie`)
- [ ] Are session cookies marked `SameSite=Strict` or `SameSite=Lax`? (Missing SameSite = CSRF risk)
- [ ] Do cookies use the `__Host-` prefix? (Requires Secure + no Domain attribute — origin-bound, cannot be set by subdomains)
- [ ] Is `Cache-Control: no-store` set on authenticated responses? (Prevents proxy caches from caching authenticated page content)
- [ ] Is the `Clear-Site-Data: "cookies", "storage"` header sent on logout? (Clears browser cache + cookie on logout)

---

### MFA and Conditional Access (6 items)

MFA is the highest-ROI control in identity security. These items verify enforcement, not just availability.

- [ ] Is MFA enabled (registered) for all users? (Entra ID: check authentication methods report; Keycloak: check TOTP credentials)
- [ ] Is MFA required (enforced) for all admin accounts? (Registration ≠ enforcement — check CA policy or required actions)
- [ ] Is Conditional Access configured in the identity provider? (Entra ID: CA policies; Keycloak: required actions + authentication flows)
- [ ] Are sign-in frequency policies enforced? (Entra ID: session controls in CA policy; Keycloak: ssoSessionIdleTimeout)
- [ ] Is Continuous Access Evaluation (CAE) enabled? (Entra ID only — near-real-time token revocation on risk events)
- [ ] Are risky sign-in locations handled? (Block or require step-up MFA for unfamiliar geolocations, anonymous proxies, Tor exit nodes)

---

### Session Monitoring (5 items)

You cannot detect session-based attacks without logging. These items verify the observability layer.

- [ ] Are failed login attempts logged with source IP, timestamp, and username? (Required for brute force and spray detection)
- [ ] Are session creation and destruction events logged? (Who logged in, when, from where — and when they logged out)
- [ ] Are concurrent session violations logged and alerting? (New login from different IP while session is active = potential session hijack)
- [ ] Is there a session anomaly detection mechanism? (New device fingerprint, new geolocation, impossible travel detection)
- [ ] How long are session logs retained? (Target: 90+ days for compliance; NIST AU-11 requires retention per policy)

---

## Output

Complete the checklist above and produce:

1. **Session management inventory** — token types, timeout settings, and cookie attributes per application
2. **Gap analysis** — which AC-12 and SC-23 controls have findings, sorted by risk
3. **Risk ranking** using 5x5 matrix (likelihood × impact)
4. **Token and cookie attribute matrix** for all in-scope applications

Feed gaps into:
- K8s RBAC: `01a-iam-audit.md`, then `02-fix-AC6-rbac.md`
- Session timeouts: `01b-session-policy-audit.md`, then `02a-fix-AC12-session.md`
- MFA: `02b-fix-IA2-mfa.md`
