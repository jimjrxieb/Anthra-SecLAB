# Layer 7 Application — CISO Report

## Purpose

Compile scenario results into a governance report suitable for CISO or board presentation. This playbook teaches you how to translate application security findings into business language.

## Report Structure

### 1. Executive Summary (1 paragraph)

Template: "Application security assessment of [environment name] identified [N] findings across [N] controls (SI-10, AU-2). The highest-risk finding is SQL injection (Critical, risk score 25/25) with an estimated annual loss exposure of $[X]. Total remediation cost: $[X]. Overall ROSI: [X]x. SQL injection has been in the OWASP Top 10 for over 20 years and caused $140M in damages at Heartland Payment Systems alone. Missing audit logging means breaches go undetected — IBM reports the cost difference between early and late detection is $3.93M per incident."

### 2. Risk Heatmap

Plot each finding on the 5x5 matrix:

```
        Impact ->
        1    2    3    4    5
  5   |    |    |    |    |!!! |   SI-10 SQL Injection
L 4   |    |    |    |    |!!  |   AU-2 Missing Logging
i 3   |    |    |    |    |    |
k 2   |    |    |    |    |    |
e 1   |    |    |    |    |    |
```

Legend: blank = Low, ! = Medium, !! = High, !!! = Critical

### 3. Financial Summary

| Finding | ALE | Fix Cost | ROSI | Gordon-Loeb Check |
|---------|-----|----------|------|-------------------|
| SI-10 SQL Injection | $1,464,000 | $4,800 | 289x | Under ceiling (0.33%) |
| AU-2 Missing Logging | $1,952,000 | $7,200 | 229x | Under ceiling (1.0%) |
| **Combined** | **$3,416,000** | **$12,000** | **255x** | **Under ceiling** |

### 4. Compliance Impact

| Framework | Control | Status | Impact if Not Remediated |
|-----------|---------|--------|------------------------|
| FedRAMP | SI-10 | Other Than Satisfied | ATO blocked |
| FedRAMP | AU-2 | Other Than Satisfied | ATO blocked |
| PCI-DSS | Req 6.5.1 | Non-Compliant | SQL injection protection required since PCI 1.0 (2004) |
| PCI-DSS | Req 10.1 | Non-Compliant | Audit trail required for all access to cardholder data |
| HIPAA | 164.312(a)(1) | Gap | Access control technical safeguard |
| HIPAA | 164.312(b) | Gap | Audit controls — willful neglect: $50K minimum per violation |
| SOC 2 | CC6.1 | Gap | Logical access controls |
| SOC 2 | CC7.1, CC7.2 | Gap | Detection and monitoring |
| ISO 27001 | A.14.2.5 | Gap | Secure system engineering principles |
| ISO 27001 | A.12.4.1 | Gap | Event logging |
| NIST 800-171 | 3.13.1 | Gap | Communication protection at system boundaries |
| NIST 800-171 | 3.3.1 | Gap | System audit logging and records |
| CMMC Level 2 | SI.L2-3.14.1 | Gap | Flaw remediation |
| CMMC Level 2 | AU.L2-3.3.1 | Gap | System auditing |
| GDPR | Art 32, 33 | Risk | Security of processing + breach notification impossible without logs |

### 5. Precedent Cases

| Incident | Year | Root Cause | Cost | Relevance |
|----------|------|-----------|------|-----------|
| Heartland Payment Systems | 2008 | SQL injection in corporate website | $140M fines, 130M cards | SI-10: String concatenation in SQL |
| TalkTalk | 2015 | SQL injection in legacy web app | GBP 60M total, GBP 400K ICO fine | SI-10: Known vulnerability, easily preventable |
| MOVEit Transfer | 2023 | SQL injection (CVE-2023-34362) | $10B+ estimated across 2,500 orgs | SI-10: Web application SQL injection |
| SolarWinds | 2020 | Insufficient monitoring, 14-month dwell | $40M+ (SolarWinds alone) | AU-2: Logging gaps enabled extended access |
| Equifax | 2017 | Detection failure (expired cert + no logging) | $1.4B total | AU-2: 76-day undetected exfiltration |
| Capital One | 2019 | No access pattern monitoring | $190M | AU-2: Unusual data access not detected |
| Marriott | 2014-2018 | Four-year undetected access | GBP 18.4M GDPR fine | AU-2: No monitoring detected compromise |
| Target | 2013 | Alerts fired but not reviewed | $292M | AU-6: Logging without review is insufficient |

### 6. Recommendation Summary

| Finding | Decision | Priority | Timeline | Cost | Return |
|---------|----------|----------|----------|------|--------|
| SI-10 SQL Injection | Mitigate | Immediate | 7 days | $4,800 | 289x ROSI |
| AU-2 Missing Logging | Mitigate | Immediate | 14 days | $7,200 | 229x ROSI |

## How to Present

**Do:** Lead with the numbers. "$3.4 million annual exposure, $12,000 to fix, 255x return." That is the language of capital allocation. Every board member understands ROI.

**Do:** Use Heartland as the SQL injection anchor. "$140 million because someone concatenated a string into a SQL query." Then: "Our code does exactly the same thing." Pause. Let them process that.

**Do:** Use SolarWinds as the logging anchor. "14 months of Russian intelligence in the network, and nobody knew because the logging was not there." Then: "Our application does not log a single authentication event." Pause.

**Do:** Show the fix is simple. "Parameterized queries have existed for 20 years. Structured logging is a code change. These are not technology problems — they are process failures." This frames it as unacceptable, not complex.

**Do:** Emphasize the cascade effect. "Without logging, every other security investment is blind. Firewalls, endpoint protection, SIEM — they all depend on having events to analyze. Logging is the foundation."

**Don't:** Get into code details. The CISO does not need to see `cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))`. They need to know "we fixed the code so attackers cannot extract the database."

**Don't:** Present SQL injection and logging as separate issues. They are connected: SQL injection is the attack, logging is how you detect it. Frame them together: "An attacker could extract our entire database via SQL injection, and we would never know because we have no logging."

**Don't:** Downplay the risk because "we are not Heartland." Every application that accepts user input is a target. SQLMap is free. A script kiddie can extract your database in 5 minutes. The attack is fully automated.

**Don't:** Present without a timeline. "SQL injection fixed in Week 1, audit logging operational in Week 2, SIEM integration in Week 3, detection rules tuned in Week 4" is actionable. "We will address these findings" is not.

**Don't:** Forget the ongoing cost. The one-time fix is cheap, but SAST/DAST scanning, SIEM ingestion, and log management require budget. Present it: "$12,600/year ongoing to maintain application security across the environment."
