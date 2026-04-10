# Layer 5 — Session

## What This Layer Covers

Session management, authentication state, token handling, session termination. This is where the application tracks who you are between requests.

## Why It Matters

A session that never expires means a stolen token works forever. Session fixation lets an attacker hijack an authenticated user. Weak session management is in the OWASP Top 10 and is the root cause of most account takeover attacks.

## NIST 800-53 Controls

| Control ID | Control Name | What It Requires |
|-----------|-------------|-----------------|
| AC-12 | Session Termination | Terminate sessions after inactivity or max lifetime |
| SC-23 | Session Authenticity | Protect session tokens from hijacking |
| IA-2 | Identification and Authentication | Verify identity of users |
| IA-8 | Identification and Authentication (Non-Org) | Authenticate external users |

## Tools

| Tool | Type | Cost | Purpose |
|------|------|------|---------|
| Microsoft Entra ID | Microsoft | Free tier | Conditional access, session policies |
| Burp Suite Community | Free | Free | Session analysis, cookie inspection |
| Browser DevTools | Built-in | Free | Token inspection, cookie analysis |
| OWASP ZAP | Open source | Free | Session management testing |

## Scenarios

| Scenario | Control | Format |
|----------|---------|--------|
| [AC-12 No Session Timeout](scenarios/AC-12-no-session-timeout/) | AC-12 | Mix (.sh + .md) |
| [SC-23 Session Fixation](scenarios/SC-23-session-fixation/) | SC-23 | Mix (.sh + .md) |
