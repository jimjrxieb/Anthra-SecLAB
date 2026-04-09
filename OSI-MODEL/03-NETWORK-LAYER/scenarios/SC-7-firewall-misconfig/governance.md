# SC-7 Firewall Misconfiguration — CISO Governance Brief

## Executive Summary

Firewall misconfiguration was confirmed on the target host: management ports SSH (22) and RDP (3389) were accessible from 0.0.0.0/0 with no source IP restriction, no connection logging, and no rate limiting. This is the primary ransomware entry vector — Sophos reports the average ransomware recovery cost is $1.82M per incident, and exposed RDP is the initial access method in 40% of ransomware cases. Estimated annual loss exposure: $1,456,000. Recommended remediation (source IP restriction, logging, rate limiting) costs $800 one-time + $400/year in staff time. ROSI: 1,213x in year one.

## NIST 800-53 Control Requirement

**SC-7 Boundary Protection:** "The information system monitors and controls communications at the external boundary of the system and at key internal boundaries within the system; connects to external networks or information systems only through managed interfaces consisting of boundary protection devices arranged in accordance with an organizational security architecture."

SC-7(5) Deny by Default / Allow by Exception: "The information system at managed interfaces denies network communications traffic by default and allows network communications traffic by exception (i.e., deny all, permit by exception)."

**Required by:** FedRAMP (all baselines), NIST 800-171 (3.13.1, 3.13.6), HIPAA (§164.312(e)(1) Transmission Security), PCI-DSS (Requirement 1.2 — Restrict connections between untrusted networks and system components), SOC 2 (CC6.1, CC6.6), ISO 27001 (A.13.1.1 Network Controls), CMMC Level 2 (SC.L2-3.13.1).

## Risk Assessment

- **Likelihood: 5 (Almost Certain)** — Internet-facing management ports are scanned within minutes of exposure. Shodan, Censys, and Masscan continuously index open SSH and RDP ports. Automated brute-force botnets begin credential stuffing within hours. No sophistication required — this is the lowest-hanging fruit for any attacker.
- **Impact: 5 (Critical)** — Successful SSH or RDP access gives the attacker interactive shell or desktop access to the host. From there: credential harvesting, lateral movement, data exfiltration, ransomware deployment. RDP is the #1 initial access vector for ransomware (Sophos 2024). SSH gives root-equivalent access on Linux infrastructure.
- **Inherent Risk Score: 25** (5 x 5)
- **Risk Level: Critical**

## Business Impact

- **Attack path:** Internet scan → open management port → credential brute force or exploit → interactive access → lateral movement → ransomware/exfiltration
- **Data exposure:** Full host compromise — all data on the host, all credentials cached on the host, all network segments reachable from the host. A single compromised management port is the entry point for a full-environment breach.
- **Estimated breach cost:** IBM Cost of a Data Breach 2024 reports the global average breach cost is **$4.88M**. Sophos State of Ransomware 2024 reports the average ransomware recovery cost is **$1.82M** (excluding ransom payment). With exposed management ports as the initial vector, the probability-weighted annual cost is **$1,456,000** (80% likelihood x $1.82M).
- **Ransomware economics:** The average ransom payment in 2024 was $1.54M (Sophos 2024). Only 65% of organizations that paid the ransom recovered their data. Mean recovery time: 34 days of degraded operations.
- **Regulatory exposure:** HIPAA: failure to implement access controls on management interfaces — up to $2.13M/violation category/year. PCI-DSS: exposed management ports on systems in the cardholder data environment — immediate non-compliance, potential fines of $5,000-$100,000/month. FedRAMP: SC-7 finding at this severity blocks authorization.
- **Compliance gap:** SC-7 with management ports open to 0.0.0.0/0 is an automatic "Other Than Satisfied" finding on any FedRAMP assessment. Auditors specifically test for this — it is line item 1 on every external penetration test scope.

## 5x5 Risk Matrix

```
        Impact ->
        1    2    3    4    5
  5   |    |    |    |    |[X]|   <- SC-7 Firewall Misconfig (L:5, I:5 = 25 CRITICAL)
L 4   |    |    |    |    |    |
i 3   |    |    |    |    |    |
k 2   |    |    |    |    |    |
e 1   |    |    |    |    |    |
```

Risk Score 25 = Critical. Maximum possible score. Immediate action required.

## Proportionality Analysis (Gordon-Loeb)

- **Asset value protected:** The host itself plus all data, credentials, and network segments reachable from it. For a typical server in a production environment, the asset value includes customer data, application code, and infrastructure access. Estimated: **$10M** (conservative, based on breach cost and business disruption).
- **Annualized Loss Expectancy (ALE):** Likelihood 80% (exposed management ports are actively exploited within days) x $1.82M (Sophos average ransomware recovery) = **$1,456,000/year**
- **Control implementation cost:** $800 one-time (staff time for firewall rule updates, logging configuration, and validation) + $400/year (log review, rule maintenance, periodic revalidation) = **$1,200 first year**
- **ROSI:** ($1,456,000 x 0.95 risk_reduction - $1,200) / $1,200 = **1,151x return**
- **Gordon-Loeb ceiling:** 37% of $1,456,000 = **$538,720** — our $1,200 cost is 0.22% of the ceiling
- **Verdict: Extremely Proportional** — this is a trivial-cost control that eliminates a critical risk. Restricting source IP on firewall rules is a 30-minute configuration change. Not implementing this control is negligent.

## Remediation Summary

- **What was fixed:** Removed 0.0.0.0/0 inbound rules on SSH (22) and RDP (3389). Restricted source IP to admin CIDR. Enabled connection logging for all management port access. Added rate limiting to prevent brute force (5 connections/min per source). Set default INPUT policy to DROP.
- **Time to remediate:** 30 minutes for firewall rule changes, 15 minutes for logging configuration, 15 minutes for validation. Total: **1 hour**
- **Residual risk score:** Likelihood drops from 5 to 1 (Rare — management ports are not reachable from outside admin CIDR, brute force is rate-limited, all attempts are logged), Impact stays 5 = **5 (Medium)**

## Metrics Impact

- **MTTD for this finding:** Management ports were open to the internet with no logging — effective MTTD was **infinite** (no detection capability existed for unauthorized access attempts)
- **MTTD after remediation:** All connection attempts are logged. Failed attempts trigger rate limiting. MTTD drops to **seconds** with SIEM integration or **minutes** with manual log review.
- **MTTR:** Pre-fix: N/A (undetected). Post-fix: **0 seconds** for automated blocking (rate limit drops the connection) + minutes for incident response on repeated attempts.
- **Control coverage change:** SC-7 management port protection: 0% → 100% on this host

## Recommendation to Leadership

**Decision: Mitigate — Emergency Priority**
Justification: Exposed management ports are the single most common ransomware entry vector. This is not a theoretical risk — it is an active, exploited vulnerability class that costs organizations an average of $1.82M per incident (Sophos 2024) and $4.88M when it leads to a full breach (IBM 2024). The fix is a 30-minute firewall configuration change that costs $800 in staff time. At $1,200 total first-year cost against $1,456,000 annual exposure, this has a 1,151x return on investment. Every hour this remains unfixed, the host is being scanned and probed by automated attack infrastructure. Implement within 24 hours. This is not a maintenance window item — this is an emergency change.
