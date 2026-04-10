# Layer 5 Session — CISO Report

## Purpose

Compile scenario results into a governance report suitable for CISO or board presentation. This playbook teaches you how to translate session management findings into business language.

## Report Structure

### 1. Executive Summary (1 paragraph)

Template: "Session management assessment of [application name] identified [N] findings across [N] controls (AC-12, SC-23). The highest-risk finding is [description] with an estimated annual loss exposure of $[X]. Total remediation cost: $[X]. Overall ROSI: [X]x. [N] findings require immediate action to maintain [compliance framework] compliance. Microsoft reports that 99.9% of compromised accounts lacked MFA and session token theft is the #2 account takeover vector."

### 2. Risk Heatmap

Plot each finding on the 5x5 matrix:

```
        Impact ->
        1    2    3    4    5
  5   |    |    |    | !! | !! |
L 4   |    |    | !  | !! | !! |
i 3   |    |    | !  | !  | !! |
k 2   |    |    |    | !  |  ! |
e 1   |    |    |    |    |    |
```

Legend: blank = Low, ! = Medium, !! = High/Very High

### 3. Financial Summary

| Finding | ALE | Fix Cost | ROSI | Gordon-Loeb Check |
|---------|-----|----------|------|-------------------|
| AC-12 No Session Timeout | $585,600 | $10,900 | 44.7x | Under ceiling |
| SC-23 Session Fixation | $732,000 | $6,600 | 98.3x | Under ceiling |

### 4. Compliance Impact

| Framework | Control | Status | Impact if Not Remediated |
|-----------|---------|--------|------------------------|
| FedRAMP | AC-12 | Other Than Satisfied | ATO blocked |
| FedRAMP | SC-23 | Other Than Satisfied | ATO blocked |
| PCI-DSS | 8.2.8 | Gap | Idle timeout >15min = non-compliant |
| PCI-DSS | 6.2.4 | Gap | Session fixation = non-compliant |
| HIPAA | 164.312(a)(2)(iii) | Gap | No automatic logoff |
| HIPAA | 164.312(c)(1) | Gap | Session integrity not enforced |
| SOC 2 | CC6.1 | Gap | Logical access controls deficient |
| OWASP ASVS | 3.7.1 | Fail | Session not regenerated on auth |

### 5. Attack Landscape Context

| Statistic | Source | Relevance |
|-----------|--------|-----------|
| 99.9% of compromised accounts lacked MFA | Microsoft Security Intelligence 2023 | Session controls are the last defense |
| 10,000+ AiTM attacks per month | Microsoft Threat Intelligence 2023 | Session token theft is industrialized |
| $4.81M average breach cost (stolen credentials) | IBM Cost of a Data Breach 2024 | Most expensive attack vector |
| 44.7% of breaches involve stolen credentials | Verizon DBIR 2024 | Nearly half of all breaches |
| 292 days average breach lifecycle (credential theft) | IBM Cost of a Data Breach 2024 | Attackers have ~10 months of access |

### 6. Recommendation Summary

| Finding | Decision | Priority | Timeline |
|---------|----------|----------|----------|
| AC-12 No Session Timeout | Mitigate | High | 30 days |
| SC-23 Session Fixation | Mitigate | High | 14 days |

### 7. Remediation Roadmap

| Week | Action | Cost | Risk Reduction |
|------|--------|------|----------------|
| 1 | Session timeouts + fixation prevention | $4,800 | 60% of exposure eliminated |
| 2 | Cookie hardening + Entra ID policies | $3,600 | 80% of exposure eliminated |
| 3-4 | MFA + monitoring | $1,800 | 90% of exposure eliminated |
| 5-6 | Advanced controls (binding, anomaly detection) | $3,000 | 95% of exposure eliminated |

## How to Present

**Do:** Lead with the Microsoft statistic. "99.9% of compromised accounts lacked MFA, and session token theft is the second most common account takeover method. Our session tokens currently never expire." That gets attention.

**Do:** Show the ROSI. "A $6,600 fix delivers 98x return by preventing session fixation attacks." Business language, not technical.

**Do:** Connect to compliance. "PCI-DSS requires a 15-minute idle timeout. We currently have no timeout. This is a binary pass/fail." Creates urgency.

**Do:** Reference the AiTM threat. "Microsoft detects 10,000 adversary-in-the-middle attacks per month targeting session tokens. Tokens without expiry are the highest-value target because they work forever."

**Don't:** Explain how session fixation works technically. The CISO cares that it enables account takeover, not that the session ID persists through the authentication boundary.

**Don't:** Present more than 5-8 findings. Prioritize by risk score. Detail the top 3, summarize the rest.

**Don't:** Make recommendations without cost and ROI. Every "we should do X" needs "it costs $Y and saves $Z."

**Don't:** Forget the timeline. Executives want to know when the risk will be reduced, not just what the risk is.
