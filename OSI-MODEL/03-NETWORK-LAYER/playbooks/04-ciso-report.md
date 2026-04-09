# Layer 3 Network — CISO Report

## Purpose

Compile scenario results into a governance report suitable for CISO or board presentation. This playbook teaches you how to translate network layer findings into business language that drives action.

## Report Structure

### 1. Executive Summary (1 paragraph)

Template: "Network layer assessment of [environment name] identified [N] findings across [N] controls (SC-7, AC-4). The highest-risk finding is [description] with an estimated annual loss exposure of $[X]. Total remediation cost: $[X]. Overall ROSI: [X]x. Remediation is firewall configuration changes plus zone-based segmentation rules — no new hardware or licensing required. [N] findings require emergency action to prevent ransomware entry and lateral movement."

### 2. Risk Heatmap

Plot each finding on the 5x5 matrix:

```
        Impact ->
        1    2    3    4    5
  5   |    |    |    |    |[!!]|
L 4   |    |    |    |    |    |
i 3   |    |    |    |    |    |
k 2   |    |    |    |    |    |
e 1   |    |    |    |    |    |
```

Legend: blank = Low, ! = Medium, !! = High/Very High, [!!] = Critical

Network Layer findings:
- **SC-7 Firewall Misconfiguration:** Likelihood 5, Impact 5 = **25 (Critical)** — top-right corner
- **AC-4 Flat Network:** Likelihood 5, Impact 5 = **25 (Critical)** — top-right corner

Both findings are at maximum risk score. This is unusual — most assessments have a distribution. Two critical findings at Layer 3 indicate a fundamental gap in network security architecture.

### 3. Financial Summary

| Finding | ALE | Fix Cost | ROSI | Gordon-Loeb Check |
|---------|-----|----------|------|-------------------|
| SC-7 Firewall Misconfiguration | $1,456,000 | $1,200 | 1,151x | 0.22% of ceiling |
| AC-4 Flat Network | $1,920,000 | $4,700 | 387x | 0.66% of ceiling |
| **Combined** | **$3,376,000** | **$5,900** | **543x** | **Under ceiling** |

Key message: **$5,900 in staff time eliminates $3.4M+ in annual exposure.** These are firewall rule changes on infrastructure we already own and operate.

### 4. Compliance Impact

| Framework | Control | Status | Impact if Not Remediated |
|-----------|---------|--------|------------------------|
| FedRAMP | SC-7 | Other Than Satisfied | ATO blocked — boundary protection missing |
| FedRAMP | AC-4 | Other Than Satisfied | ATO blocked — information flow enforcement missing |
| PCI-DSS | Req 1.2 | Gap | Network segmentation failed — entire network in scope |
| PCI-DSS | Req 11.3.4 | Gap | Segmentation pen test would fail |
| HIPAA | §164.312(e)(1) | Gap | Transmission security not enforced |
| HIPAA | §164.312(a)(1) | Gap | Access control on network layer missing |
| NIST 800-171 | 3.13.1 | Gap | Communications not monitored at boundaries |
| NIST 800-171 | 3.1.3 | Gap | Information flow not controlled |
| SOC 2 | CC6.1, CC6.6 | Gap | Logical access and network boundary controls missing |
| ISO 27001 | A.13.1.1, A.13.1.3 | Gap | Network controls and segregation missing |
| CMMC L2 | SC.L2-3.13.1 | Gap | Boundary protection deficient |
| CMMC L2 | AC.L2-3.1.3 | Gap | Information flow enforcement deficient |

### 5. Recommendation Summary

| Finding | Decision | Priority | Timeline | Cost |
|---------|----------|----------|----------|------|
| SC-7 Firewall Misconfiguration | Mitigate | Emergency | 24 hours | $1,200 |
| AC-4 Flat Network | Mitigate | Emergency | 7 days | $4,700 |

SC-7 is a 24-hour emergency because management ports are exposed to the internet right now. AC-4 is a 7-day priority because segmentation requires zone design and testing.

## How to Present

**Do:** Lead with the combined number. "$3.4 million in annual exposure, fixed for $5,900 in staff time" is the single most compelling sentence in this report.

**Do:** Emphasize the ransomware connection. "Exposed RDP is how ransomware gets in. Flat networks are how it spreads. We have both." This connects two technical findings into one business narrative: ransomware risk.

**Do:** Reference the Sophos $1.82M ransomware recovery figure. "The average ransomware recovery costs $1.82 million. Our network has an exposed entry point and no segmentation to contain it. The math is simple."

**Do:** Show the PCI-DSS segmentation impact. "Without network segmentation, our entire network is in PCI scope. That is a $50K-$200K/year increase in assessment costs alone — before we even talk about the security risk."

**Do:** Present the timeline urgency. "SC-7 is a 24-hour emergency change. Every hour those management ports are exposed, automated botnets are scanning them."

**Do:** Show the ROSI. "543x combined return. For every dollar we spend, we eliminate $543 in risk."

**Don't:** Explain how iptables or Nmap works. The CISO cares that management ports are exposed and that the network is flat — not the tool chain.

**Don't:** Present without dollar figures. Every finding needs ALE, fix cost, and ROSI.

**Don't:** Combine Layer 3 findings with other layers in the same presentation. Each layer gets its own brief — this prevents scope creep and keeps the ask focused.

**Don't:** Call it a recommendation. "This must be implemented within 24 hours / 7 days" is what moves the organization. "We recommend" is weak.

**Don't:** Minimize the flat network finding. Decision-makers often deprioritize "internal" findings because they seem less urgent than internet-facing exposure. The data says otherwise — lateral movement increases breach cost by 28% (IBM 2024). Frame it as "this is how a $500K incident becomes a $5M incident."

## Source Citations

All dollar figures in this report are sourced from:
- **IBM Cost of a Data Breach Report 2024** — $4.88M average breach cost, $164/record, lateral movement 28% cost premium
- **Sophos State of Ransomware 2024** — $1.82M average ransomware recovery cost, $1.54M average ransom payment, RDP as #1 entry vector
- **Ponemon Institute 2024** — dwell time cost analysis, ~$1,500/day additional cost per day of undetected breach
- **PCI Security Standards Council** — fine ranges for non-compliance ($5,000-$100,000/month), segmentation testing requirements
- **HHS Office for Civil Rights** — HIPAA penalty tiers (up to $2.13M/violation category/year)
- **Gordon-Loeb Model** — "The Economics of Information Security Investment" (2002), optimal security investment ceiling of 37% of expected loss
