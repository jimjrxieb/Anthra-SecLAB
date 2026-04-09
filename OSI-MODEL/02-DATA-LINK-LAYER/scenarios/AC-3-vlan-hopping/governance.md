# AC-3 VLAN Hopping — CISO Governance Brief

## Executive Summary

Network segmentation via VLANs was found to be bypassable through two attack methods: double tagging (exploiting native VLAN misconfiguration) and switch spoofing (exploiting DTP trunk negotiation). Both attacks allow an attacker on a user VLAN to send traffic to restricted segments including server, database, and management VLANs. The entire security architecture depends on VLAN segmentation as a primary control boundary. Estimated annual loss exposure from segmentation bypass: $1,230,000. Recommended remediation (DTP disable + native VLAN hardening + VLAN pruning) costs $2,000 one-time in staff time. ROSI: 369x in year one.

## NIST 800-53 Control Requirement

**AC-3 Access Enforcement:** "The information system enforces approved authorizations for logical access to information and system resources in accordance with applicable access control policies."

**SC-7 Boundary Protection (supporting):** "The information system monitors and controls communications at the external boundary of the system and at key internal boundaries within the system."

**AC-4 Information Flow Enforcement (supporting):** "The information system enforces approved authorizations for controlling the flow of information within the system and between interconnected systems based on applicable policy."

**Required by:** FedRAMP (all baselines), NIST 800-171 (3.1.3 Control Information Flow), HIPAA (§164.312(e)(1) Transmission Security), PCI-DSS (Requirement 1.2 — Restrict Connections, Requirement 1.3 — Prohibit Direct Public Access), SOC 2 (CC6.1 Logical and Physical Access Controls), ISO 27001 (A.13.1.3 Segregation in Networks).

## Risk Assessment

- **Likelihood: 4 (Likely)** — VLAN hopping requires network access and basic knowledge. DTP-based switch spoofing is automated by tools like yersinia. Default Cisco switch configurations ship with DTP enabled. Double tagging requires only scapy or a similar packet crafting tool.
- **Impact: 5 (Severe)** — VLAN segmentation is typically the primary control boundary between user workstations and server/database/management segments. Bypassing it gives an attacker access to every network zone: production databases, management interfaces, backup systems, and out-of-band management networks.
- **Inherent Risk Score: 20** (4 x 5)
- **Risk Level: Very High**

## Business Impact

- **Attack path:** User VLAN access → VLAN hopping (double tagging or switch spoofing) → server VLAN access → database server access → data exfiltration. Alternatively: → management VLAN → switch/router/firewall management interfaces → full network control
- **Data exposure:** All systems on the target VLAN. If the server VLAN is reached: production databases, application servers, internal APIs. If the management VLAN is reached: network device configurations, SNMP credentials, out-of-band management (iDRAC/ILO/IPMI).
- **Estimated breach cost:** Network segmentation bypass leading to lateral movement: average breach cost $4.88M (IBM Cost of a Data Breach 2024, global average). For organizations where segmentation was the primary control, breaches are 23.4% more expensive due to wider blast radius. Adjusted estimate: **$1,230,000** for a mid-size environment with 7,500 records at $164/record (IBM 2024).
- **Regulatory exposure:** PCI-DSS: network segmentation is a fundamental requirement. Failed segmentation means the entire network is in scope for PCI assessment — cost increase of $50,000-$200,000/year in assessment fees alone, plus potential fines of $5,000-$100,000/month. HIPAA: failure to segment PHI systems from general network — §164.312(e)(1) violation. FedRAMP: SC-7 failure blocks ATO.
- **Compliance gap:** AC-3/SC-7 finding at the network segmentation boundary. PCI-DSS assessors specifically test for VLAN hopping (Requirement 11.3.4 — penetration testing of segmentation controls). Failure results in expanded scope and potential loss of compliance certification.

## Proportionality Analysis (Gordon-Loeb)

- **Asset value protected:** All systems behind VLAN segmentation boundaries — production databases, application servers, management infrastructure. Estimated value: **$8M** (data value + infrastructure replacement + regulatory penalties).
- **Annualized Loss Expectancy (ALE):** Likelihood 30% (requires network access but tools are freely available) x $4.1M (average breach cost for segmentation failure, Ponemon/IBM 2024) = **$1,230,000/year**
- **Control implementation cost:** $2,000 one-time (network engineer time: 4 hours per switch x 10 switches x $50/hr) + $500/year (configuration auditing) = **$2,500 first year**
- **ROSI:** ($1,230,000 x 0.90 risk_reduction - $2,500) / $2,500 = **442x return**
- **Gordon-Loeb ceiling:** 37% of $1,230,000 = **$455,100** — our $2,500 cost is 0.2% of the ceiling
- **Verdict: Extremely Proportional** — these are zero-cost configuration changes on existing switches. Every dollar spent returns $442. Failure to implement is not a resource constraint — it is an oversight.

## Remediation Summary

- **What was fixed:** DTP disabled on all access ports (`switchport nonegotiate`), native VLAN changed from VLAN 1 to unused VLAN 999 on all trunks, native VLAN tagging enabled globally, unused VLANs pruned from trunk ports, unused switch ports shut down and assigned to black-hole VLAN
- **Time to remediate:** 4 hours per switch during maintenance window. 10-switch environment: **5 business days** (2 switches per maintenance window)
- **Residual risk score:** Likelihood drops from 4 to 1 (Rare — both attack vectors eliminated by configuration), Impact stays 5 = **5 (Low-Medium)**

## Metrics Impact

- **MTTD for this finding:** VLAN hopping was not detected by any existing control — effective MTTD was **infinite**. Configuration audit identified the vulnerability.
- **MTTD after remediation:** Switch spoofing: **0 seconds** (DTP frames ignored). Double tagging: **0 seconds** (native VLAN mismatch prevents attack). Configuration drift detected by quarterly switch audit.
- **MTTR:** Pre-fix: N/A (no detection). Post-fix: **0 seconds** (attacks are prevented at the switch level — no incident response needed)
- **Control coverage change:** AC-3 VLAN segmentation enforcement: 0% → 100% for all managed switch ports. All access ports hardened. All trunk ports pruned.

## Recommendation to Leadership

**Decision: Mitigate — Immediate Priority**
Justification: VLAN segmentation is the foundation of our network security architecture. Every firewall rule, every access control list, every security zone boundary assumes that VLANs provide isolation. If an attacker can hop between VLANs, every other network security control is bypassed. The fix is configuration-only — disable DTP, change the native VLAN, prune unused VLANs. Total cost: $2,500 in staff time against $1.23M annual exposure. This is not a discretionary investment; it is correcting a misconfiguration that should never have existed. Prioritize this alongside the SC-7 ARP spoofing remediation — both are data link layer controls that should be implemented in the same maintenance window. Implement within 14 days.
