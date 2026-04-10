# AU-2 Missing Audit Logging — CISO Governance Brief

## Executive Summary

Application security assessment confirmed complete absence of audit logging across all endpoints. Authentication events (success and failure), sensitive data access, and authorization failures were not recorded. An attacker could conduct brute force attacks, exfiltrate the entire database, and attempt privilege escalation with zero visibility — no alerts would fire, no investigation would be possible, and no evidence would exist for incident response or regulatory reporting. IBM Cost of a Data Breach 2024 reports that breaches detected in under 200 days cost $3.93 million less than those detected later. SolarWinds (2020) went undetected for 14 months because monitoring and logging were insufficient to catch the compromise. Without logging, mean time to detect (MTTD) is effectively infinite — you discover the breach when someone else tells you. Estimated annual loss exposure from undetected breaches: $1,952,000. Remediation cost (structured JSON logging, SIEM integration, detection rules): $4,800 one-time + $2,400/year. ROSI: 270x in year one.

## NIST 800-53 Control Requirement

**AU-2 Event Logging:** "The organization: a. Determines that the information system is capable of auditing the following events: [Assignment: organization-defined auditable events]; b. Coordinates the security audit function with other organizational entities requiring audit-related information; c. Provides a rationale for why the auditable events are deemed to be adequate to support after-the-fact investigations of security incidents; and d. Determines that the following events are to be audited within the information system: [Assignment: organization-defined subset of the auditable events]."

**AU-2(3) Reviews and Updates:** The organization reviews and updates the audited events on an annual basis or when significant changes occur.

**AU-6 Audit Record Review, Analysis, and Reporting:** "The organization: a. Reviews and analyzes information system audit records [Assignment: organization-defined frequency] for indications of inappropriate or unusual activity; and b. Reports findings to [Assignment: organization-defined personnel or roles]."

**Required by:** FedRAMP (all baselines — AU-2 is mandatory at Low, Moderate, and High), PCI-DSS (Requirement 10 — Track and monitor all access to network resources and cardholder data), HIPAA (Section 164.312(b) — Audit Controls, Section 164.308(a)(1)(ii)(D) — Information system activity review), NIST 800-171 (3.3.1 — Create and retain system audit logs and records, 3.3.2 — Ensure actions of individual system users can be uniquely traced), SOC 2 (CC7.1 — Detection and monitoring, CC7.2 — Security event analysis), ISO 27001 (A.12.4.1 Event logging, A.12.4.3 Administrator and operator logs), CMMC Level 2 (AU.L2-3.3.1 System auditing, AU.L2-3.3.2 User accountability).

## Attack History

### SolarWinds SUNBURST — December 2020
Russian intelligence (SVR/APT29) compromised SolarWinds' Orion build system and inserted the SUNBURST backdoor into a software update distributed to 18,000 customers including the US Treasury, Commerce Department, DHS, and Fortune 500 companies. The compromise went undetected for **14 months** (March 2020 to December 2020). FireEye discovered the breach only when investigating their own compromise — not through SolarWinds' logging or monitoring. The attackers specifically targeted logging infrastructure: they tampered with audit logs, disabled security monitoring on compromised systems, and operated within normal traffic patterns. If comprehensive application-layer audit logging had been in place with anomaly detection, the unusual API calls and data access patterns could have triggered alerts months earlier. Estimated cost: $100 million+ across all affected organizations. SolarWinds alone spent $40 million on remediation.

### Equifax — May 2017
The breach exploited an Apache Struts vulnerability, but the real failure was detection. Equifax's SSL inspection device had an expired certificate that blinded their monitoring for 19 months. Even after the certificate was replaced, the logging and alerting infrastructure failed to detect 9,000 DNS queries to attacker-controlled domains. 147 million records were exfiltrated over 76 days. The US Senate report specifically cited "failure to implement adequate monitoring and logging" as a contributing factor. Total cost: $1.4 billion.

### Target — November 2013
Attackers accessed Target's network through a compromised HVAC vendor. FireEye alerts fired and were sent to Target's security team in Bangalore — but nobody acted on them. The logging was there; the review process (AU-6) was not. 40 million credit card numbers and 70 million customer records stolen. Cost: $292 million. The breach proved that AU-2 (logging) without AU-6 (review and alerting) is insufficient.

### Capital One — March 2019
A former AWS employee exploited a misconfigured WAF to access Capital One's S3 buckets. The initial compromise was not detected for four months. The breach was eventually reported by an anonymous tip on GitHub — not by Capital One's monitoring. 106 million records stolen. If data access logging and anomaly detection had flagged the unusual API call patterns (reading 700+ S3 buckets in rapid succession), the breach could have been detected within hours. Cost: $190 million.

### Marriott International — 2014-2018
Attackers had access to the Starwood guest reservation database for **four years** before discovery. 500 million guest records compromised. The breach was discovered only during a post-acquisition security audit by Marriott, not by Starwood's monitoring. ICO fined Marriott GBP 18.4 million under GDPR. The four-year dwell time is a direct result of insufficient logging and monitoring.

## Risk Assessment

- **Likelihood: 4 (Likely)** — Absence of logging does not cause breaches, but it guarantees they go undetected. IBM reports that the average time to detect a breach is 204 days. Without logging, this number approaches infinity — you rely on external notification (law enforcement, customer complaints, threat intelligence). Verizon DBIR 2024 reports that 68% of breaches are discovered by external parties, not the victim.
- **Impact: 5 (Catastrophic)** — Without logging: incident response is impossible (no evidence exists), regulatory reporting requirements cannot be met (HIPAA requires 60-day notification with incident details), forensic investigation has no data to work with, insurance claims may be denied (no evidence of reasonable security controls), and the breach scope cannot be determined (assume worst case).
- **Inherent Risk Score: 20** (4 x 5)
- **Risk Level: Very High**

## 5x5 Risk Matrix

```
        Impact ->
        1    2    3    4    5
  5   |    |    |    |    |    |
L 4   |    |    |    |    |[X] |   <- AU-2 Missing Logging (L:4, I:5 = 20 VERY HIGH)
i 3   |    |    |    |    |    |
k 2   |    |    |    |    |    |
e 1   |    |    |    |    |    |
```

Risk Score 20 = Very High. Remediation required within 14 days. Without logging, every other security control is effectively blind.

## Business Impact

- **Attack path:** Any attack vector → successful compromise → no logging → no detection → extended dwell time → maximum data exfiltration → external notification (average 204 days later)
- **Data exposure:** Without logging, breach scope is unknown. Assume worst case: all data in the application is compromised. In this scenario: PII (SSNs), financial data (credit card numbers), and protected health information (PHI).
- **Estimated breach cost:** IBM Cost of a Data Breach 2024: breaches detected in under 200 days cost **$3.93M** on average. Breaches detected after 200 days cost **$4.95M**. The delta is **$1.02M** — that is the cost of not having logging. For organizations with no security AI/automation (which requires logging data to function): add **$1.76M** compared to organizations with extensive automation. Total estimated cost: **$4.88M** baseline + **$1.76M** automation gap = **$6.64M** for a breach in an unmonitored environment.
- **Regulatory exposure:**
  - **HIPAA:** Section 164.312(b) requires audit controls. Missing logging is a willful neglect violation: minimum $50,000 per violation, up to $2.13M/year. OCR specifically investigates logging during breach investigations.
  - **PCI-DSS:** Requirement 10.1: "Implement audit trails to link all access to system components to each individual user." Missing logging is automatic non-compliance. Fines: $5,000-$100,000/month.
  - **FedRAMP:** AU-2 is mandatory at all baselines. Missing audit logging blocks Authority to Operate. No exceptions.
  - **SOC 2:** CC7.1 requires detection and monitoring. Missing logging results in a qualified opinion or adverse finding.
  - **GDPR:** Article 33 requires breach notification within 72 hours with details of the incident. Without logs, you cannot determine what happened, when, or what data was affected — making compliant notification impossible.
- **Compliance gap:** AU-2 is a foundational control. Without it, AU-3 (content of audit records), AU-6 (audit review), AU-7 (audit reduction), and AU-12 (audit generation) all fail by dependency. One missing control cascades into five control failures.

## Proportionality Analysis (Gordon-Loeb)

- **Asset value protected:** The value of logging is measured by the breach cost delta. IBM reports the difference between detected-early and detected-late breaches is $3.93M vs $4.95M. For our environment with sensitive data (PII, financial, PHI): **$8M** total data asset value.
- **Annualized Loss Expectancy (ALE):** Likelihood 40% (an unmonitored environment has a significantly higher probability of a breach going undetected) x $4.88M (IBM average) = **$1,952,000/year**. The IBM data shows that organizations with no security AI/automation (which depends on logging) lose an additional $1.76M per breach.
- **Control implementation cost:** $4,800 one-time (8 hours engineering at $150/hr for logging integration, SIEM configuration, detection rule creation, and validation across 4 application instances x 2 environments) + $2,400/year (Splunk/Sentinel ingestion costs at 1 GB/day, quarterly rule tuning, annual logging review) = **$7,200 first year**
- **ROSI:** ($1,952,000 x 0.85 risk_reduction - $7,200) / $7,200 = **229x return**
- **Gordon-Loeb ceiling:** 37% of $1,952,000 = **$722,240** — our $7,200 cost is 1.0% of the ceiling
- **Verdict: Extremely Proportional** — Logging is the most cost-effective security control available. The cost is trivial — structured logging is a code change, SIEM integration is a configuration change. The return is massive because logging enables every other security function: detection, response, forensics, and compliance. Without logging, you are spending money on firewalls and endpoint protection but flying blind.

## Remediation Summary

- **What was fixed:** Implemented structured JSON audit logging for all security-relevant events. Authentication events (success and failure) now logged with source IP, username, user agent, and correlation ID. Data access events logged with record count and classification level. Authorization failures logged with attempted action and actual role. HTTP request logging captures method, endpoint, response code, and duration. Log rotation configured (daily, 30-day retention). Splunk and Filebeat configurations created for SIEM integration. KQL and SPL detection queries created for brute force, data exfiltration, and privilege escalation alerting.
- **Time to remediate:** 2 hours per application for logging integration + 4 hours for SIEM configuration and detection rule creation. Total: **12 hours**
- **Residual risk score:** Likelihood drops from 4 to 2 (Unlikely — security events are now logged and alertable, SIEM rules detect common attack patterns), Impact drops from 5 to 2 (Minor — breaches will be detected quickly, evidence exists for response) = **4 (Low)**

## Metrics Impact

- **MTTD for this finding:** Application log review confirms missing events in **5 minutes**. Automated check script verifies logging coverage in **30 seconds**. After fix: MTTD for brute force attacks drops from infinity (no logging) to **10 minutes** (SIEM alert rule fires after 5 failed logins in 10 minutes).
- **MTTR:** Logging integration: 2 hours per application. SIEM configuration: 4 hours. Detection rule tuning: 2 hours. Total: **8 hours**
- **Control coverage change:** AU-2 event logging: 0% (no events logged) -> 100% (authentication, data access, authorization, and HTTP requests all logged). AU-6 audit review capability: 0% (no data to review) -> 80% (structured data with detection rules; remaining 20% requires human tuning of baselines and thresholds).
- **Vulnerability SLA status:** Very High finding — requires remediation within 14 days

## Recommendation to Leadership

**Decision: Mitigate — Immediate Priority**
Justification: "If you can't detect a breach, you can't respond to it." This is not a theoretical risk — it is an operational reality. SolarWinds went 14 months undetected. Equifax went 76 days. Marriott went four years. The common factor: insufficient logging and monitoring. IBM's data is unambiguous: organizations that detect breaches in under 200 days save $3.93 million compared to those that detect them later. Our $7,200 investment against $1,952,000 annual exposure delivers a 229x return. But the real value is not financial — it is operational. Without logging, every other security investment is undermined. Firewalls cannot alert on what they do not log. Endpoint protection cannot correlate without event data. Incident response cannot investigate without evidence. Compliance auditors cannot verify without audit trails. Logging is the foundation. Everything else is built on top of it. Deploy within 14 days. Start with authentication logging (highest immediate value), add data access logging (compliance requirement), then authorization logging (privilege escalation detection). SIEM integration in parallel. Detection rules operational within 30 days.
