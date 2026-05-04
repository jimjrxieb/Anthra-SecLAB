# Layer 5 Session — Control Map

| NIST Control | Control Name | Tool | Enterprise Equivalent | What Misconfiguration Looks Like |
|-------------|-------------|------|----------------------|--------------------------------|
| AC-12 | Session Termination | Burp Suite CE, Entra ID | Okta, Ping Identity | No idle timeout, tokens never expire, no max session lifetime |
| SC-23 | Session Authenticity | Burp Suite CE, ZAP | F5 ASM, Imperva | Session ID not regenerated on login, predictable tokens, no binding |
| IA-2 | Identification and Authentication | Entra ID, browser DevTools | Okta, Duo, CyberArk | No MFA, weak password policy, no account lockout |
| IA-8 | Non-Organizational User Auth | Entra ID (B2B/B2C) | Okta, Auth0 | External users same auth as internal, no conditional access |
