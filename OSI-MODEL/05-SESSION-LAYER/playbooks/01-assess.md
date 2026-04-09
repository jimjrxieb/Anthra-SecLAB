# Layer 5 Session — Assess Current State

## Purpose

Document the current session management posture before implementing any controls. This assessment establishes the baseline for measuring improvement.

## Assessment Checklist

### AC-12 Session Termination

- [ ] What is the idle timeout for standard user sessions? (Target: 15 minutes or less)
- [ ] What is the idle timeout for privileged/admin sessions? (Target: 2-5 minutes)
- [ ] What is the maximum session lifetime? (Target: 8-24 hours)
- [ ] Do sessions terminate when the browser is closed? (Session cookies vs persistent)
- [ ] Does the application provide a logout function on every authenticated page?
- [ ] Does logout destroy the session server-side (not just clear the cookie)?
- [ ] Are all sessions invalidated on password change?
- [ ] Are all sessions invalidated on MFA enrollment change?
- [ ] Is there a limit on concurrent sessions per user? (Target: 3-5)
- [ ] Can an admin forcibly terminate another user's sessions?

### SC-23 Session Authenticity

- [ ] Is the session ID regenerated on login? (Test: compare cookie before and after auth)
- [ ] Is the session ID regenerated on privilege escalation? (e.g., sudo mode, admin panel)
- [ ] Does the application accept externally-set session IDs? (strict mode test)
- [ ] Are URL-based session IDs disabled? (no JSESSIONID in URLs)
- [ ] What is the session ID length and entropy? (Target: 128+ bits of entropy)
- [ ] Is the session ID cryptographically random? (Not sequential, not predictable)

### Token Handling

- [ ] What type of tokens are used? (Session cookies, JWT, OAuth, SAML)
- [ ] Do JWTs include an `exp` (expiration) claim?
- [ ] Do JWTs include a `jti` (token ID) claim for revocation?
- [ ] Is the JWT signing algorithm RS256 or ES256? (Not HS256 with weak secrets)
- [ ] Are refresh tokens rotated on each use? (New refresh token per exchange)
- [ ] Is refresh token reuse detection enabled? (Revoke family on reuse)
- [ ] Are access tokens short-lived? (Target: 5-15 minutes)

### Cookie Security

- [ ] Are session cookies marked `Secure`? (HTTPS only)
- [ ] Are session cookies marked `HttpOnly`? (No JavaScript access)
- [ ] Are session cookies marked `SameSite=Strict` or `SameSite=Lax`?
- [ ] Do cookies use the `__Host-` prefix? (Origin-bound)
- [ ] Is `Cache-Control: no-store` set on authenticated responses?
- [ ] Is the `Clear-Site-Data` header sent on logout?

### MFA and Conditional Access

- [ ] Is MFA enabled for all users? (Microsoft: 99.9% of compromised accounts lack MFA)
- [ ] Is MFA required for admin accounts? (Non-negotiable)
- [ ] Is Conditional Access configured in the identity provider? (Entra ID, Okta, etc.)
- [ ] Are sign-in frequency policies enforced?
- [ ] Is Continuous Access Evaluation (CAE) enabled? (Near real-time token revocation)
- [ ] Are risky sign-in locations handled? (Block or require MFA for unfamiliar locations)

### Session Monitoring

- [ ] Are failed login attempts logged with source IP and timestamp?
- [ ] Are session creation and destruction events logged?
- [ ] Are concurrent session violations alerting?
- [ ] Is there a session anomaly detection mechanism? (New device, new location, impossible travel)
- [ ] How long are session logs retained? (Target: 90+ days for compliance)

## Output

Complete the checklist above and produce:
1. Session management inventory (token types, timeout settings, cookie attributes per application)
2. Gap analysis: which AC-12 and SC-23 controls have findings?
3. Risk ranking of findings using 5x5 matrix
4. Token and cookie attribute matrix for all applications in scope
