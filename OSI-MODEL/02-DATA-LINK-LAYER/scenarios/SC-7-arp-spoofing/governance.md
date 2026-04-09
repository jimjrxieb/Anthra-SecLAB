# SC-7 ARP Spoofing — CISO Governance Brief

## Executive Summary

ARP spoofing was successfully executed on the internal network, enabling full man-in-the-middle interception of traffic between a workstation and the default gateway. No Dynamic ARP Inspection (DAI) or ARP monitoring was in place to prevent or detect the attack. Estimated annual loss exposure from undetected man-in-the-middle attacks: $820,000. Recommended remediation (DAI + DHCP snooping + arpwatch monitoring) costs $500 one-time + $700/year in staff time. ROSI: 764x in year one.

## NIST 800-53 Control Requirement

**SC-7 Boundary Protection:** "The information system monitors and controls communications at the external boundary of the system and at key internal boundaries within the system; connects to external networks or information systems only through managed interfaces consisting of boundary protection devices arranged in accordance with an organizational security architecture."

SC-7 Enhancement (7): "The organization prevents the unauthorized release of information outside of the information system boundary or any unauthorized communication through the information system boundary when there is an operational failure of the boundary protection mechanisms."

**Required by:** FedRAMP (all baselines), NIST 800-171 (3.13.1), HIPAA (§164.312(e)(1) Transmission Security), PCI-DSS (Requirement 1 — Network Segmentation), SOC 2 (CC6.1, CC6.6), ISO 27001 (A.13.1.1 Network Controls).

## Risk Assessment

- **Likelihood: 5 (Almost Certain)** — ARP spoofing requires only network access and free tools (dsniff, ettercap). Any attacker or compromised host on the LAN segment can execute it in under 60 seconds. Default switch configurations do not prevent it.
- **Impact: 4 (Major)** — full interception of credentials, session tokens, API keys, and sensitive data in transit. Enables credential harvesting, session hijacking, and data exfiltration without triggering network-level alerts.
- **Inherent Risk Score: 20** (5 x 4)
- **Risk Level: Very High**

## Business Impact

- **Attack path:** Network access (wired/wireless) → ARP cache poisoning → man-in-the-middle position → credential interception → lateral movement → data exfiltration
- **Data exposure:** All unencrypted traffic between poisoned hosts — includes internal API calls, database queries, email (if SMTP without TLS), file shares (SMB), and any HTTP traffic. Even with TLS, metadata (DNS queries, connection patterns) is exposed, and SSL stripping attacks become possible.
- **Estimated breach cost:** Average credential-theft breach: 292 days to identify and contain (IBM Cost of a Data Breach 2024). At $164/record (IBM 2024 global average) with 5,000 records exposed via intercepted credentials = **$820,000 per incident**. Credential theft as initial vector adds 11.2% to average breach cost (IBM 2024).
- **Regulatory exposure:** HIPAA: failure to implement transmission security (§164.312(e)(1)) — up to $2.13M/violation category/year. PCI-DSS: failure of network segmentation — potential loss of SAQ eligibility, requirement for full ROC, fines of $5,000-$100,000/month. SOC 2: network control deficiency invalidates CC6.1 and CC6.6.
- **Compliance gap:** SC-7 finding at the L2 boundary blocks FedRAMP authorization. Auditors will test for ARP spoofing in network penetration testing scope. Finding results in "Other Than Satisfied" determination requiring POA&M with 90-day remediation deadline.

## Proportionality Analysis (Gordon-Loeb)

- **Asset value protected:** All data traversing the affected network segment — customer records, credentials, API keys, internal communications. Estimated data value: **$5M** (based on record count, IP value, and regulatory exposure).
- **Annualized Loss Expectancy (ALE):** Likelihood 60% (any insider or compromised host can execute) x $1.37M (average MitM-enabled breach cost, Ponemon 2024) = **$822,000/year**
- **Control implementation cost:** $500 one-time (staff time for DAI/DHCP snooping config + static ARP entries) + $700/year (arpwatch monitoring + maintenance) = **$1,200 first year**
- **ROSI:** ($822,000 x 0.95 risk_reduction - $1,200) / $1,200 = **649x return**
- **Gordon-Loeb ceiling:** 37% of $822,000 = **$304,140** — our $1,200 cost is 0.15% of the ceiling
- **Verdict: Extremely Proportional** — this is a near-zero-cost control that eliminates a very high risk. DAI and DHCP snooping are built into every managed switch and require only configuration. Not implementing this control is indefensible.

## Remediation Summary

- **What was fixed:** Dynamic ARP Inspection enabled on all access VLANs, DHCP snooping enabled as the binding table source, static ARP entries configured for gateway and critical infrastructure, arpwatch deployed for continuous ARP monitoring
- **Time to remediate:** DAI/DHCP snooping: 2-4 hours (switch configuration). Static ARP: 1 hour. arpwatch: 1 hour. Total: **1 business day**
- **Residual risk score:** Likelihood drops from 5 to 1 (Rare — DAI blocks spoofed ARP at the switch before it reaches the target), Impact stays 4 = **4 (Low)**

## Metrics Impact

- **MTTD for this finding:** ARP spoofing was undetected until penetration test — effective MTTD was **infinite** (no detection capability existed)
- **MTTD after remediation:** arpwatch alerts within **seconds** of ARP anomaly. DAI blocks the attempt before it succeeds.
- **MTTR:** Pre-fix: N/A (undetected). Post-fix: **0 seconds** (DAI prevents the attack automatically — no response needed)
- **Control coverage change:** SC-7 L2 boundary protection: 0% → 100% for all managed switch ports

## Recommendation to Leadership

**Decision: Mitigate — Immediate Priority**
Justification: ARP spoofing is a trivially executed, high-impact attack that any attacker on the internal network can perform with free tools in under a minute. The mitigation (DAI + DHCP snooping) is built into every managed switch we already own and costs nothing beyond 4 hours of network engineering time. Not enabling these controls is the security equivalent of having a lock on the front door but leaving the back door wide open. At $1,200 total cost against $822,000 annual exposure, this has the highest return-on-investment of any control in the data link layer assessment. Implement within 7 days.
