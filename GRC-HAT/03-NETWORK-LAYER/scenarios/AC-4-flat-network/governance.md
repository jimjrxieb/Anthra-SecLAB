# AC-4 Flat Network — CISO Governance Brief

## Executive Summary

Network segmentation assessment confirmed a flat network topology: all subnets communicate freely with no firewall rules enforcing zone boundaries. Any attacker or compromised host on any subnet can reach every service on every other subnet — databases, management interfaces, file shares, everything. This is the primary enabler of lateral movement, which IBM reports increases average breach cost by 28% ($1.37M premium). Estimated annual loss exposure from lateral-movement-enabled breaches: $1,920,000. Recommended remediation (zone-based firewall with iptables/pfSense segmentation + logging) costs $3,500 one-time + $1,200/year in staff time. ROSI: 387x in year one.

## NIST 800-53 Control Requirement

**AC-4 Information Flow Enforcement:** "The information system enforces approved authorizations for controlling the flow of information within the system and between interconnected systems based on applicable policy."

AC-4 Enhancement (6): "The information system enforces information flow control based on explicit security attributes on information, source, and destination objects as a basis for flow control decisions."

**Required by:** FedRAMP (all baselines), NIST 800-171 (3.1.3 Control Information Flow), HIPAA (§164.312(e)(1) Transmission Security), PCI-DSS (Requirement 1.2 — Restrict connections between untrusted networks; Requirement 11.3.4 — Segmentation penetration testing), SOC 2 (CC6.1, CC6.6), ISO 27001 (A.13.1.3 Segregation in Networks), CMMC Level 2 (AC.L2-3.1.3).

## Risk Assessment

- **Likelihood: 5 (Almost Certain)** — A flat network requires zero additional exploitation to move laterally. Once an attacker compromises any host (phishing, vulnerable service, stolen credentials), they have direct network access to every other host. No firewall rules to bypass. No segmentation to hop. Lateral movement is free.
- **Impact: 5 (Critical)** — Without segmentation, a single compromised workstation can reach production databases, management interfaces, file shares, and backup systems. The blast radius of any breach is the entire network. Ransomware spreads to every reachable host. Data exfiltration includes every accessible database.
- **Inherent Risk Score: 25** (5 x 5)
- **Risk Level: Critical**

## 5x5 Risk Matrix

```
        Impact ->
        1    2    3    4    5
  5   |    |    |    |    |[X]|   <- AC-4 Flat Network (L:5, I:5 = 25 CRITICAL)
L 4   |    |    |    |    |    |
i 3   |    |    |    |    |    |
k 2   |    |    |    |    |    |
e 1   |    |    |    |    |    |
```

Risk Score 25 = Critical. Maximum possible score. Immediate action required.

## Business Impact

- **Attack path:** Initial compromise (any vector) → unrestricted lateral movement → access all subnets → escalate privileges on reachable hosts → data exfiltration + ransomware deployment across entire network
- **Data exposure:** Every database, file share, management interface, and service on the network. In a flat network, the compromised host can directly connect to every service — no pivoting required, no firewall rules to bypass.
- **Estimated breach cost:** IBM Cost of a Data Breach 2024 reports the average breach cost is $4.88M. Breaches involving lateral movement cost 28% more — **$6.25M average**. With a flat network enabling unrestricted lateral movement, probability-weighted annual cost: 40% likelihood of breach with lateral movement x $4.8M (inclusive of lateral premium) = **$1,920,000/year**.
- **Lateral movement cost amplifier:** IBM 2024 data shows breaches where attackers moved laterally took 292 days to identify vs. 197 days for contained breaches — 48% longer MTTD. Every additional day of dwell time increases breach cost by approximately $1,500/day (Ponemon 2024).
- **Ransomware blast radius:** In a segmented network, ransomware is contained to the compromised zone. In a flat network, ransomware can reach every host. Sophos 2024: average ransomware recovery cost is **$1.82M** — in a flat network, this is the minimum because every host is in the blast radius.
- **Regulatory exposure:** PCI-DSS: flat network means the entire environment is in scope for PCI assessment — not just the cardholder data environment. This typically increases assessment costs by $50,000-$200,000/year and increases the number of controls that must be validated. HIPAA: failure to segment PHI systems from general network — up to $2.13M/violation category/year. FedRAMP: AC-4 finding blocks authorization.
- **Compliance gap:** PCI-DSS explicitly requires network segmentation (Requirement 1.2) and segmentation penetration testing (Requirement 11.3.4). A flat network fails both. The entire network becomes in-scope for PCI, dramatically increasing audit cost and control count.

## Proportionality Analysis (Gordon-Loeb)

- **Asset value protected:** All data and systems on the network — the segmentation boundary defines the blast radius. In a flat network, all assets are at risk from any single compromise. Estimated combined asset value: **$15M** (based on data classification, IP value, infrastructure replacement cost, and regulatory exposure).
- **Annualized Loss Expectancy (ALE):** Likelihood 40% (breaches are common; flat networks amplify every one) x $4.8M (average lateral-movement-enabled breach) = **$1,920,000/year**
- **Control implementation cost:** $3,500 one-time (staff time for zone design, firewall rule creation, testing, and validation) + $1,200/year (rule maintenance, log review, periodic revalidation) = **$4,700 first year**
- **ROSI:** ($1,920,000 x 0.95 risk_reduction - $4,700) / $4,700 = **387x return**
- **Gordon-Loeb ceiling:** 37% of $1,920,000 = **$710,400** — our $4,700 cost is 0.66% of the ceiling
- **Verdict: Extremely Proportional** — zone-based segmentation using existing firewall capabilities (iptables, pfSense, Azure NSGs) is a configuration exercise, not a procurement exercise. The cost is staff time. The risk reduction is transformative.

## Remediation Summary

- **What was fixed:** Implemented zone-based firewall segmentation with four zones (MGMT, APP, DATA, USER). Created explicit allow rules for approved cross-zone traffic flows. Set default FORWARD policy to DROP. Enabled logging for denied cross-zone traffic. Blocked direct USER-to-DATA access (users must go through APP tier). Blocked DATA zone from initiating outbound connections.
- **Time to remediate:** Zone design: 2 hours. Rule implementation: 2 hours. Testing and validation: 2 hours. Total: **1 business day**
- **Residual risk score:** Likelihood drops from 5 to 2 (Unlikely — lateral movement is now constrained to the compromised zone, attackers must find and exploit zone-crossing paths), Impact drops from 5 to 3 (Moderate — blast radius is limited to one zone) = **6 (Medium)**

## Metrics Impact

- **MTTD for this finding:** Lateral movement was unrestricted and unlogged — effective MTTD for cross-zone movement was **infinite** (no detection capability existed)
- **MTTD after remediation:** Denied cross-zone traffic is logged. Unusual traffic patterns between zones trigger alerts. MTTD for lateral movement attempts drops to **minutes** with SIEM integration.
- **MTTR:** Pre-fix: N/A (undetected, unrestricted). Post-fix: **0 seconds** for blocked traffic (firewall drops it automatically) + minutes for incident response on persistent attempts.
- **Control coverage change:** AC-4 information flow enforcement: 0% → 100% for inter-zone traffic

## Recommendation to Leadership

**Decision: Mitigate — Emergency Priority**
Justification: A flat network is the force multiplier behind every breach. It turns a single compromised workstation into a full-environment breach. It turns a contained ransomware incident into a company-wide encryption event. It turns a $500K incident into a $4.8M incident. Network segmentation is the single most impactful control in any security program because it limits the blast radius of everything that goes wrong. The fix is firewall rules — iptables on Linux, pfSense for dedicated firewalls, or Azure NSGs in the cloud. All of these are free or already licensed. The $4,700 first-year cost is entirely staff time. Against $1.92M in annual exposure, that is a 387x return. PCI-DSS requires it. NIST requires it. Every framework requires it. Implement within 7 days. Start with the DATA zone (protect databases first), then segment USER from APP, then harden MGMT.
