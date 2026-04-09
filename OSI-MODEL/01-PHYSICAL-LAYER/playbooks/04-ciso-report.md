# Layer 1 Physical — CISO Report

## Purpose

Compile scenario results into a governance report suitable for CISO or board presentation. This playbook teaches you how to translate physical security findings into business language.

## Report Structure

### 1. Executive Summary (1 paragraph)

Template: "Physical security assessment of [facility name] identified [N] findings across [N] PE controls. The highest-risk finding is [description] with an estimated annual loss exposure of $[X]. Total remediation cost: $[X]. Overall ROSI: [X]x. [N] findings require immediate action to maintain [compliance framework] compliance."

### 2. Risk Heatmap

Plot each finding on the 5x5 matrix:

```
        Impact →
        1    2    3    4    5
  5   |    |    |    | !! | !! |
L 4   |    |    | !  | !! | !! |
i 3   |    |    | !  | !  | !! |
k 2   |    |    |    | !  |  ! |
e 1   |    |    |    |    |    |
```

Legend: blank = Low, ! = Medium, !! = High/Very High

### 3. Financial Summary

| Finding | ALE | Fix Cost | ROSI | Gordon-Loeb Check |
|---------|-----|----------|------|-------------------|
| PE-3 Tailgating | $480,000 | $21,700 | 13.4x | Under ceiling |
| PE-14 HVAC | $54,000-$432,000 | $23,200-$54,200 | 1.1x-6.2x | Under ceiling |

### 4. Compliance Impact

| Framework | Control | Status | Impact if Not Remediated |
|-----------|---------|--------|------------------------|
| FedRAMP | PE-3 | Other Than Satisfied | ATO blocked |
| FedRAMP | PE-14 | Other Than Satisfied | ATO blocked |
| HIPAA | §164.310 | Gap | OCR investigation risk |
| PCI-DSS | Req 9 | Gap | Qualified assessment |
| SOC 2 | CC6.4, A1.2 | Gap | Qualified opinion |

### 5. Recommendation Summary

| Finding | Decision | Priority | Timeline |
|---------|----------|----------|----------|
| PE-3 Tailgating | Mitigate | High | 90 days |
| PE-14 HVAC | Mitigate | Medium-High | 90 days |

## How to Present

**Do:** Lead with dollars, not technical details. "We have a $480K annual exposure from physical access gaps" not "We found a tailgating vulnerability."

**Do:** Show the ROSI. "$21K investment returns 13x" is a language every executive understands.

**Do:** Connect to compliance. "This blocks our FedRAMP authorization" creates urgency.

**Don't:** List CVEs or technical jargon. The CISO cares about risk, cost, and compliance — not the specifics of how ARP spoofing works.

**Don't:** Present more than 5-8 findings. Prioritize by risk score. Detail the top 3, summarize the rest.

**Don't:** Make recommendations without cost and ROI. Every "we should do X" needs "it costs $Y and saves $Z."
