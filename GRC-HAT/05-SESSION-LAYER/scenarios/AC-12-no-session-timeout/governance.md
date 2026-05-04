# AC-12 No Session Timeout — CISO Governance Brief

## Executive Summary

Session management audit confirmed critical gaps: application tokens have no expiration, no idle timeout is configured, and session lifetime is unlimited. A stolen session token grants the attacker permanent authenticated access until the user manually logs out or the application is restarted. Microsoft Security Intelligence reports that 99.9% of compromised accounts lacked MFA, and session token theft is the second most common account takeover vector after credential stuffing. OWASP ranks Identification and Authentication Failures as the #7 vulnerability category. Estimated annual loss exposure from unlimited sessions: $585,000. Recommended remediation (session timeouts, token rotation, Entra ID conditional access) costs $8,500 one-time + $2,400/year. ROSI: 52x in year one.

## NIST 800-53 Control Requirement

**AC-12 Session Termination:** "The information system automatically terminates a user session after [organization-defined conditions or trigger events requiring session disconnect]."

**AC-12(1) User-Initiated Logouts:** "The information system provides a logout capability for user-initiated communications sessions whenever authentication is used to gain access to [organization-defined information resources]."

**Required by:** FedRAMP (all baselines — AC-12 is required at Low, Moderate, and High), NIST 800-171 (3.1.11 — Terminate sessions after inactivity), HIPAA (Section 164.312(a)(2)(iii) — Automatic logoff), PCI-DSS (Requirement 8.2.8 — Session idle timeout of 15 minutes or less), SOC 2 (CC6.1 — Logical Access Security), ISO 27001 (A.9.4.2 — Secure log-on procedures), CMMC Level 2 (AC.L2-3.1.11).

## Attack History

### Microsoft Token Theft Campaign — 2023
Microsoft Threat Intelligence documented a surge in adversary-in-the-middle (AiTM) phishing attacks targeting session tokens. Attackers used proxy servers (EvilProxy, Evilginx) to capture session cookies during legitimate MFA-authenticated logins. The stolen session token bypassed MFA entirely because the attacker replayed the post-authentication cookie. Sessions without expiry gave attackers persistent access for weeks. Microsoft reported this affected tens of thousands of organizations.

### Lapsus$ Group — 2022
The Lapsus$ threat group systematically targeted session tokens and authentication cookies. They purchased stolen session cookies from underground markets and used them to access corporate environments at Microsoft, Okta, Nvidia, and Samsung. Okta disclosed that 2.5% of customers were affected. The attack succeeded because session tokens remained valid long after the initial authentication event.

### GitHub OAuth Token Theft — April 2022
Attackers stole OAuth tokens issued to Heroku and Travis CI, two third-party OAuth integrators with GitHub. The stolen tokens provided access to private repositories of dozens of organizations, including npm. GitHub revoked all affected tokens, but the incident demonstrated that long-lived OAuth tokens create persistent access risk.

### SolarWinds SAML Token Forging — December 2020
The Nobelium threat group (Russian SVR) forged SAML tokens after compromising the SolarWinds Orion build system. By stealing the ADFS token-signing certificate, they created SAML assertions with arbitrary claims and unlimited lifetimes. This gave them persistent, undetectable access to any federated application. Sessions with no maximum lifetime meant forged tokens worked indefinitely.

## Risk Assessment

- **Likelihood: 4 (Likely)** — Token theft attacks are automated and commoditized. AiTM phishing kits (EvilProxy: $400/month) are sold as-a-service. Microsoft detected 10,000+ AiTM attacks per month in 2023. Session tokens without expiry are the highest-value target because a single stolen token provides permanent access.
- **Impact: 4 (Major)** — Unlimited session lifetime means a stolen token works until the user explicitly logs out or an admin revokes it. Most users never log out of web applications. Attacker maintains access through password changes, MFA enrollment changes, and security alerts — because the existing session token remains valid.
- **Inherent Risk Score: 16** (4 x 4)
- **Risk Level: High**

## 5x5 Risk Matrix

```
        Impact ->
        1    2    3    4    5
  5   |    |    |    |    |    |
L 4   |    |    |    |[X] |    |   <- AC-12 No Session Timeout (L:4, I:4 = 16 HIGH)
i 3   |    |    |    |    |    |
k 2   |    |    |    |    |    |
e 1   |    |    |    |    |    |
```

Risk Score 16 = High. Remediation required within 30 days per most vulnerability management SLAs.

## Business Impact

- **Attack path:** AiTM phishing or malware captures session cookie → attacker replays cookie from any location → no expiry means access persists indefinitely → lateral movement, data exfiltration, email forwarding rules, mailbox delegation
- **Data exposure:** Everything the compromised user can access. For admin accounts: entire tenant. For standard users: email, SharePoint, Teams, OneDrive, line-of-business applications. For API service accounts: all integrated systems.
- **Estimated breach cost:** IBM Cost of a Data Breach 2024: stolen credentials (which includes session tokens) cost **$4.81M** per breach — the most expensive initial attack vector. For Anthra-SecLAB: assuming 3,000 affected records at $165/record = **$495,000** direct cost + **$90,000** incident response and notification = **$585,000**
- **Regulatory exposure:** PCI-DSS Requirement 8.2.8 explicitly mandates 15-minute idle timeout. Non-compliance: $5,000-$100,000/month until remediated. HIPAA requires automatic logoff (164.312(a)(2)(iii)) — violations: $100-$50,000 per violation, up to $2.13M/year per category. FedRAMP: AC-12 is required at all baselines — missing session timeout blocks authorization.
- **Compliance gap:** AC-12 is a binary control — either sessions terminate after inactivity or they do not. There is no partial credit. An auditor who sees tokens with no expiry will flag this as "Other Than Satisfied" with a POA&M entry requiring 30-day remediation.

## Proportionality Analysis (Gordon-Loeb)

- **Asset value protected:** All data accessible via authenticated sessions. For a typical organization: email (executive communications worth $10M+ in litigation), SharePoint (IP, contracts), financial systems, HR data. Estimated asset value: **$8M**
- **Annualized Loss Expectancy (ALE):** Likelihood 12% (AiTM attacks are common, but require successful phishing delivery) x $4.88M (IBM average breach cost for credential theft) = **$585,600/year**
- **Control implementation cost:** $8,500 one-time (Entra ID conditional access configuration: 8 hours at $150/hr = $1,200; application session refactoring: 24 hours at $150/hr = $3,600; token rotation implementation: 16 hours at $150/hr = $2,400; testing and validation: 8 hours at $150/hr = $1,200; documentation: $100) + $2,400/year (monitoring, policy maintenance, quarterly review) = **$10,900 first year**
- **ROSI:** ($585,600 x 0.85 risk_reduction - $10,900) / $10,900 = **44.7x return**
- **Gordon-Loeb ceiling:** 37% of $585,600 = **$216,672** — our $10,900 cost is 5% of the ceiling
- **Verdict: Highly Proportional** — Session timeout configuration is primarily a settings change. The cost is dominated by application refactoring for token rotation. Even at the high end of engineering time, the investment returns 44x.

## Remediation Summary

- **What was fixed:** Implemented 15-minute idle timeout for standard sessions and 2-minute timeout for privileged sessions. Set 8-hour maximum session lifetime. Enabled refresh token rotation with reuse detection. Configured secure cookie attributes (__Host- prefix, Secure, HttpOnly, SameSite=Strict). Limited concurrent sessions to 3 per user. Enabled Continuous Access Evaluation in Entra ID. Configured Clear-Site-Data header on logout endpoint.
- **Time to remediate:** Entra ID configuration: 2 hours. Application session config: 4 hours. Token rotation implementation: 8 hours. Testing: 4 hours. Total: **18 hours across 5 business days**
- **Residual risk score:** Likelihood drops from 4 to 2 (Unlikely — tokens expire in 15 minutes, rotation detects theft, CAE revokes on risk events), Impact drops from 4 to 3 (Moderate — window of exposure limited to 15 minutes maximum) = **6 (Medium-Low)**

## Metrics Impact

- **MTTD for this finding:** Configuration audit identifies missing timeouts in **2 minutes**. Continuous monitoring via Entra ID sign-in logs and Conditional Access insights provides ongoing detection.
- **MTTR:** Entra ID policies: 30 minutes to configure. Application config: 4 hours to refactor. Full deployment: **5 business days** (including testing and staged rollout)
- **Control coverage change:** AC-12 session termination: 0% (no timeouts) → 100% (idle timeout, max lifetime, token rotation, forced re-auth)
- **Vulnerability SLA status:** Within 30-day SLA for High findings

## Recommendation to Leadership

**Decision: Mitigate — High Priority**
Justification: Session tokens without expiry are the equivalent of leaving the front door key under the mat — permanently. Microsoft's own data shows that AiTM phishing kits now routinely steal session cookies, and those cookies work until someone notices. The $10,900 investment in session timeout controls against $585,600 annual exposure delivers a 44x return. PCI-DSS and HIPAA both explicitly require automatic session termination — this is not optional for any regulated organization. Entra ID Conditional Access provides the enforcement mechanism at the identity provider level, and application-level token rotation provides defense-in-depth. The highest-impact action is enabling Conditional Access sign-in frequency — it takes 30 minutes and immediately enforces session lifetime limits across all cloud applications. Implement within 30 days. Start with Conditional Access (immediate), then application token rotation (sprint 2).
