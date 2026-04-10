# Layer 5 Session — Implement Controls

## Purpose

Implement session management controls based on assessment findings. Start with highest-risk gaps from the 01-assess output.

## Implementation Order

Priority by risk and cost-efficiency:

### Priority 1: Session Timeout Configuration (Week 1, ~$1,200)
1. Configure 15-minute idle timeout for standard user sessions
2. Configure 2-minute idle timeout for privileged/admin sessions
3. Set 8-hour maximum session lifetime
4. Ensure sessions do not persist after browser close (session cookies, not persistent)
5. Implement server-side session destruction on logout
6. Add `Clear-Site-Data` header to logout response

### Priority 2: Session Fixation Prevention (Week 1-2, ~$3,600)
1. Implement session ID regeneration on every authentication event
2. Enable strict session mode (reject uninitialized session IDs)
3. Disable URL-based session IDs (no JSESSIONID in URLs)
4. Add session regeneration on privilege escalation events
5. Add automated tests to verify session ID changes on login

### Priority 3: Cookie and Token Hardening (Week 2, ~$1,200)
1. Add `Secure` flag to all session cookies
2. Add `HttpOnly` flag to all session cookies
3. Set `SameSite=Strict` (or `Lax` if cross-site functionality required)
4. Use `__Host-` prefix on session cookies
5. Set `Cache-Control: no-store` on all authenticated responses
6. Set access token lifetime to 15 minutes
7. Implement refresh token rotation with reuse detection

### Priority 4: Entra ID Conditional Access (Week 2-3, ~$2,400)
1. Create Conditional Access policy for standard users (8-hour sign-in frequency)
2. Create Conditional Access policy for privileged users (1-hour sign-in frequency, MFA required)
3. Set persistent browser session to "Never persistent"
4. Configure token lifetime policy (15-min access, 15-min idle, 8-hour max)
5. Enable Continuous Access Evaluation (CAE)
6. Configure idle session timeout for Microsoft 365 apps (15 minutes)
7. Deploy in Report-only mode for 7 days before enforcing

### Priority 5: MFA and Monitoring (Week 3-4, ~$1,800)
1. Enable MFA for all users (if not already enabled)
2. Require MFA for all admin accounts (non-negotiable)
3. Configure session creation/destruction logging
4. Set up concurrent session violation alerting
5. Enable impossible travel detection
6. Set session log retention to 90+ days

### Priority 6: Advanced Session Controls (Month 2, ~$3,000)
1. Implement session binding (user-agent fingerprinting)
2. Add session guard middleware for continuous validation
3. Implement session anomaly detection (new device, location change)
4. Limit concurrent sessions to 3 per user
5. Invalidate all sessions on password change and MFA enrollment change

## Verification After Each Implementation

After each control is implemented, run the corresponding scenario's `validate.sh` to confirm it works. Do not proceed to the next priority without validation.

## Cost Summary

| Priority | Scope | Estimated Cost | Timeline |
|----------|-------|---------------|----------|
| 1 | Session timeouts | $1,200 | Week 1 |
| 2 | Session fixation prevention | $3,600 | Week 1-2 |
| 3 | Cookie and token hardening | $1,200 | Week 2 |
| 4 | Entra ID Conditional Access | $2,400 | Week 2-3 |
| 5 | MFA and monitoring | $1,800 | Week 3-4 |
| 6 | Advanced session controls | $3,000 | Month 2 |
| **Total** | | **$13,200** | **6 weeks** |
