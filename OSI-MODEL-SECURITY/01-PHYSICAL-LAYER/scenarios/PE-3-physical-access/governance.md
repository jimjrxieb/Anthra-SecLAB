# PE-3 Physical Access Control — CISO Governance Brief

## Executive Summary

Physical access control at badge-controlled entry points was tested via social engineering (tailgating). An unauthorized individual successfully entered a controlled area without badge authentication, bypassing PE-3 controls. Estimated annual loss exposure from unauthorized physical access: $480,000. Recommended remediation (anti-tailgating controls + policy) costs $20,000 one-time + $1,700/year. ROSI: 13.6x in year one.

## NIST 800-53 Control Requirement

**PE-3 Physical Access Control:** "The organization enforces physical access authorizations at entry/exit points to the facility where the information system resides by verifying individual access authorizations before granting access to the facility and controlling ingress/egress with physical access control systems/devices or guards."

**Required by:** FedRAMP (all baselines), HIPAA (Physical Safeguards §164.310), PCI-DSS (Requirement 9), SOC 2 (CC6.4), ISO 27001 (A.11.1).

## Risk Assessment

- **Likelihood: 4 (Likely)** — social engineering pen tests show 60-80% tailgating success rate in corporate environments without anti-tailgating hardware
- **Impact: 4 (Major)** — unauthorized physical access to server room enables data theft, hardware tampering, or malicious device installation
- **Inherent Risk Score: 16** (4 x 4)
- **Risk Level: High**

## Business Impact

- **Attack path:** Unauthorized entry → server room access → direct hardware access → data exfiltration via USB, network tap installation, or server shutdown
- **Data exposure:** All data on physically accessible servers. For Anthra-SecLAB: customer portfolio data, API keys, database credentials
- **Estimated breach cost:** Assuming 10,000 customer records at $164/record (IBM 2024 global average) = **$1,640,000 per breach event**
- **Regulatory exposure:** HIPAA: up to $2.13M/violation category/year. PCI-DSS: $5,000-$100,000/month until compliant. SOC 2: loss of report, customer attrition
- **Compliance gap:** PE-3 finding prevents FedRAMP ATO. Auditor will flag as "Other Than Satisfied" — requires POA&M entry with 90-day remediation deadline

## Proportionality Analysis (Gordon-Loeb)

- **Asset value protected:** All servers in the controlled area — estimated $2M replacement + $1.64M data value = **$3.64M**
- **Annualized Loss Expectancy (ALE):** Likelihood 40% (tailgating success rate) x $1.2M (Ponemon avg unauthorized access cost) = **$480,000/year**
- **Control implementation cost:** $20,000 one-time (turnstile + policy + training) + $1,700/year maintenance = **$21,700 first year**
- **ROSI:** ($480,000 x 0.65 risk_reduction - $21,700) / $21,700 = **13.4x return**
- **Gordon-Loeb ceiling:** 37% of $480,000 = **$177,600** — well above our $21,700 cost
- **Verdict: Proportional** — control cost is 4.5% of ALE, significantly under the 37% ceiling

## Remediation Summary

- **What was fixed:** Anti-tailgating policy published, security awareness training delivered, turnstile installed at data center entry
- **Time to remediate:** Policy/training: 2 weeks. Hardware: 60 days
- **Residual risk score:** Likelihood drops from 4 to 2 (Unlikely with hardware), Impact stays 4 = **8 (Medium)**

## Metrics Impact

- **MTTD for this finding:** Physical pen test identified in 4 hours
- **MTTR:** Policy remediation: 14 days. Hardware: 60 days
- **Control coverage change:** PE-3 coverage 0% → 100% for data center entry points
- **Vulnerability SLA status:** Within 90-day SLA for High findings

## Recommendation to Leadership

**Decision: Mitigate**
Justification: The $21,700 investment in anti-tailgating controls eliminates a $480K/year exposure with a 13.4x return. This is a compliance requirement for FedRAMP, HIPAA, and PCI-DSS — not implementing it blocks certification and puts $2M+ in regulated revenue at risk.
