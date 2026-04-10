# Layer 2 Data Link — CISO Report

## Purpose

Compile scenario results into a governance report suitable for CISO or board presentation. This playbook teaches you how to translate data link layer findings into business language that drives action.

## Report Structure

### 1. Executive Summary (1 paragraph)

Template: "Data link layer assessment of [network name] identified [N] findings across [N] controls (SC-7, AC-3, SI-4). The highest-risk finding is [description] with an estimated annual loss exposure of $[X]. Total remediation cost: $[X]. Overall ROSI: [X]x. All findings are configuration changes on existing infrastructure — no new hardware or licensing required. [N] findings require immediate action to maintain [compliance framework] compliance."

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

Data Link Layer findings:
- **SC-7 ARP Spoofing:** Likelihood 5, Impact 4 = **20 (Very High)** — top-right quadrant
- **AC-3 VLAN Hopping:** Likelihood 4, Impact 5 = **20 (Very High)** — top-right quadrant

### 3. Financial Summary

| Finding | ALE | Fix Cost | ROSI | Gordon-Loeb Check |
|---------|-----|----------|------|-------------------|
| SC-7 ARP Spoofing | $822,000 | $1,200 | 649x | 0.15% of ceiling |
| AC-3 VLAN Hopping | $1,230,000 | $2,500 | 442x | 0.2% of ceiling |
| **Combined** | **$2,052,000** | **$3,700** | **527x** | **Under ceiling** |

Key message: **$3,700 in staff time eliminates $2M+ in annual exposure.** These are configuration changes on switches we already own.

### 4. Compliance Impact

| Framework | Control | Status | Impact if Not Remediated |
|-----------|---------|--------|------------------------|
| FedRAMP | SC-7 | Other Than Satisfied | ATO blocked — L2 boundary protection missing |
| FedRAMP | AC-3 | Other Than Satisfied | ATO blocked — access enforcement at L2 missing |
| PCI-DSS | Req 1.2 | Gap | Network segmentation failed — entire network in scope |
| PCI-DSS | Req 11.3.4 | Gap | Segmentation pen test would fail |
| HIPAA | §164.312(e)(1) | Gap | Transmission security not enforced at L2 |
| NIST 800-171 | 3.13.1 | Gap | Communications not monitored at internal boundaries |
| SOC 2 | CC6.1, CC6.6 | Gap | Logical access controls and network boundary deficiency |
| ISO 27001 | A.13.1.1, A.13.1.3 | Gap | Network controls and segregation missing |

### 5. Recommendation Summary

| Finding | Decision | Priority | Timeline | Cost |
|---------|----------|----------|----------|------|
| SC-7 ARP Spoofing | Mitigate | Immediate | 7 days | $1,200 |
| AC-3 VLAN Hopping | Mitigate | Immediate | 14 days | $2,500 |

Both findings should be remediated in the same maintenance window since they involve the same switches and the same network engineering team.

## How to Present

**Do:** Lead with the combined number. "$2 million in annual exposure, fixed for $3,700 in staff time" is a sentence that gets budget approved instantly.

**Do:** Emphasize that these are configuration changes, not purchases. "We already own everything we need. This is a switch configuration project, not a procurement project."

**Do:** Connect to network segmentation. "Our firewall rules, our ACLs, our security zones — all of them assume VLANs provide isolation. If someone can hop VLANs, every control above Layer 2 is bypassed."

**Do:** Show the ROSI. "527x return. For every dollar we spend, we eliminate $527 in risk."

**Do:** Reference the PCI-DSS segmentation impact. "If our VLAN segmentation fails a pen test, the entire network goes into PCI scope. That is a $50K-$200K/year increase in assessment costs alone."

**Don't:** Explain how ARP spoofing or VLAN hopping works at a technical level. The CISO cares that traffic can be intercepted and segmentation can be bypassed — not the mechanics.

**Don't:** Present without dollar figures. Every finding needs ALE, fix cost, and ROSI.

**Don't:** Combine Layer 2 findings with other layers in the same presentation. Each layer gets its own brief — this prevents scope creep and keeps the ask focused.

**Don't:** Make it optional. "We recommend" is weak. "This must be implemented within 14 days to maintain compliance" is what moves the organization.

## Source Citations

All dollar figures in this report are sourced from:
- **IBM Cost of a Data Breach Report 2024** — $164/record global average, $4.88M average total breach cost, credential theft vector premium
- **Ponemon Institute 2024** — man-in-the-middle attack cost data, unauthorized access incident costs
- **PCI Security Standards Council** — fine ranges for non-compliance ($5,000-$100,000/month)
- **HHS Office for Civil Rights** — HIPAA penalty tiers (up to $2.13M/violation category/year)
- **Gordon-Loeb Model** — "The Economics of Information Security Investment" (2002), optimal security investment ceiling of 37% of expected loss
