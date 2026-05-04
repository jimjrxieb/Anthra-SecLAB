# PE-14 Environmental Controls — CISO Governance Brief

## Executive Summary

Server room environmental controls were assessed. No redundant HVAC, no temperature monitoring, and no automated alerting were found. A single HVAC failure would cause server shutdowns within 30 minutes, with estimated downtime cost of $270,000 per incident. Recommended remediation (sensors + alerts + redundant HVAC) costs $20,000-$51,000 one-time + $3,200/year. ROSI: 2.8x-7.6x in year one depending on hardware tier.

## NIST 800-53 Control Requirement

**PE-14 Environmental Controls:** "The organization controls the temperature and humidity levels within the facility where the information system resides and monitors environmental conditions at a frequency that provides for the detection of changes or conditions that could adversely affect the operation of the information system."

**Required by:** FedRAMP (Moderate and High baselines), HIPAA (Physical Safeguards §164.310(a)(2)(ii)), SOC 2 (A1.2), ISO 27001 (A.11.2.2).

## Risk Assessment

- **Likelihood: 3 (Moderate)** — HVAC systems have a 15-20 year lifespan; failure rate increases after year 10. Without monitoring, failures go undetected during off-hours
- **Impact: 4 (Major)** — server shutdown causes service outage, potential data corruption on hard shutdown, recovery time 4-8 hours
- **Inherent Risk Score: 12** (3 x 4)
- **Risk Level: Medium-High**

## Business Impact

- **Attack path:** Not an attack — operational failure. HVAC fails → temperature rises → servers throttle (10 min) → servers auto-shutdown (30 min) → service outage → data corruption risk on hard shutdown
- **Data exposure:** No direct data exposure, but hard shutdown risks database corruption and potential data loss
- **Estimated downtime cost:** Uptime Institute (2023): average unplanned downtime costs $9,000/minute. 30-minute outage = **$270,000**. 4-hour recovery = **$2,160,000**
- **Regulatory exposure:** SOC 2 A1.2 requires environmental safeguards for availability. Finding results in qualified audit opinion
- **Compliance gap:** PE-14 finding on FedRAMP assessment requires POA&M entry. Repeated incidents demonstrate lack of due diligence

## Proportionality Analysis (Gordon-Loeb)

- **Asset value protected:** Server infrastructure replacement $500K + downtime revenue impact $2.16M = **$2.66M**
- **Annualized Loss Expectancy (ALE):** 1 incident/5 years probability = 20% x $270,000 minimum = **$54,000/year** (conservative, rises to $432,000/year if recovery extends to 4 hours)
- **Control implementation cost:** Sensors + alerts + redundant HVAC = $20,000-$51,000 one-time + $3,200/year = **$23,200-$54,200 first year**
- **ROSI (conservative):** ($54,000 x 0.90 - $23,200) / $23,200 = **1.1x return** (minimum HVAC option)
- **ROSI (with 4-hour recovery scenario):** ($432,000 x 0.90 - $54,200) / $54,200 = **6.2x return**
- **Gordon-Loeb ceiling:** 37% of $54,000 = $19,980 (conservative) to 37% of $432,000 = $159,840 (full impact)
- **Verdict: Proportional** — even conservative estimate justifies sensors and alerting. Redundant HVAC justified when full-impact scenario is considered

## Remediation Summary

- **What was fixed:** Temperature sensors installed, alerting configured to NOC + on-call, redundant HVAC unit installed with automatic failover
- **Time to remediate:** Sensors/alerts: 1 week. Redundant HVAC: 60-90 days
- **Residual risk score:** Likelihood drops from 3 to 1 (Rare with redundancy + monitoring), Impact stays 4 = **4 (Low)**

## Metrics Impact

- **MTTD for this finding:** Assessment identified during environmental audit (Day 1)
- **MTTR:** Sensors/alerts: 7 days. Full remediation: 90 days
- **Control coverage change:** PE-14 coverage 0% → 100% for primary server room
- **Vulnerability SLA status:** Within 90-day SLA for Medium findings

## Recommendation to Leadership

**Decision: Mitigate**
Justification: Environmental monitoring (sensors + alerts) is a $700 investment that eliminates blind-spot risk for $270K+ outage events. Redundant HVAC at $15-50K is justified by the $54K-$432K annual loss expectancy range. This is also a compliance requirement — PE-14 gaps block FedRAMP Moderate authorization.
