# Layer 6 Presentation — CISO Report

## Purpose

Compile scenario results into a governance report suitable for CISO or board presentation. This playbook teaches you how to translate data encryption and cryptographic findings into business language.

## Report Structure

### 1. Executive Summary (1 paragraph)

Template: "Data-at-rest and cryptographic algorithm assessment of [system name] identified [N] findings across [N] controls (SC-28, SC-13). The highest-risk finding is [description] with an estimated annual loss exposure of $[X]. Total remediation cost: $[X]. Overall ROSI: [X]x. [N] findings require immediate action to maintain [compliance framework] compliance. IBM reports the average cost per breached record at $164 globally and $185 for healthcare. MD5 password hashes are cracked in seconds on commodity hardware."

### 2. Risk Heatmap

Plot each finding on the 5x5 matrix:

```
        Impact ->
        1    2    3    4    5
  5   |    |    |    |[C] |[U] |
L 4   |    |    |    |    |    |
i 3   |    |    |    |    |    |
k 2   |    |    |    |    |    |
e 1   |    |    |    |    |    |
```

Legend: [U] = SC-28 Unencrypted Data (L:5, I:5 = 25 Critical), [C] = SC-13 Weak Crypto (L:5, I:4 = 20 Critical)

### 3. Financial Summary

| Finding | ALE | Fix Cost | ROSI | Gordon-Loeb Check |
|---------|-----|----------|------|-------------------|
| SC-28 Unencrypted Data at Rest | $820,000 | $21,800 | 32.8x | Under ceiling |
| SC-13 Weak Cryptography | $732,000 | $15,000 | 38.4x | Under ceiling |

### 4. Compliance Impact

| Framework | Control | Status | Impact if Not Remediated |
|-----------|---------|--------|------------------------|
| FedRAMP | SC-28 | Other Than Satisfied | ATO blocked |
| FedRAMP | SC-13 | Other Than Satisfied | ATO blocked |
| HIPAA | 164.312(a)(2)(iv) | Gap | PHI encryption required — OCR investigation risk |
| PCI-DSS | 3.4 | Gap | PAN must be unreadable — non-compliant |
| PCI-DSS | 3.5 | Gap | Stored account data protection — non-compliant |
| FIPS 140-2 | SC-13 | Gap | MD5/SHA-1 prohibited — federal systems non-compliant |
| SOC 2 | CC6.1 | Gap | Encryption controls deficient |
| NIST 800-171 | 3.13.16 | Gap | CUI at rest not protected |

### 5. Attack Landscape Context

| Statistic | Source | Relevance |
|-----------|--------|-----------|
| $164 average cost per breached record (global) | IBM Cost of a Data Breach 2024 | Direct financial exposure per record |
| $185 average cost per breached record (healthcare) | IBM Cost of a Data Breach 2024 | Healthcare premium due to PHI |
| $4.81M average breach cost (stolen credentials) | IBM Cost of a Data Breach 2024 | Most expensive initial attack vector |
| 150 billion MD5 hashes/sec on RTX 4090 | hashcat benchmarks 2024 | MD5 is functionally plaintext |
| 6.5M SHA-1 hashes cracked in days | LinkedIn breach 2012 | SHA-1 provides no protection |
| $700M settlement | Equifax 2017 (unencrypted SSNs) | Regulatory cost of unencrypted PII |
| $131M settlement | Anthem 2015 (unencrypted PHI) | Regulatory cost of unencrypted PHI |
| 292 days average breach lifecycle (credential theft) | IBM Cost of a Data Breach 2024 | Attackers have ~10 months of access |

### 6. Recommendation Summary

| Finding | Decision | Priority | Timeline |
|---------|----------|----------|----------|
| SC-28 Unencrypted Data at Rest | Mitigate | Critical | 14 days |
| SC-13 Weak Cryptography | Mitigate | Critical | 14 days |

### 7. Remediation Roadmap

| Week | Action | Cost | Risk Reduction |
|------|--------|------|----------------|
| 1 | Password hashing migration + secrets to vault | $6,000 | 50% of exposure eliminated |
| 2 | Column-level PII/PHI encryption + disk encryption | $8,400 | 80% of exposure eliminated |
| 3 | SHA-256 integrity migration + crypto config | $2,400 | 90% of exposure eliminated |
| 4 | CI enforcement + standards doc + quarterly audit | $1,800 | 95% of exposure eliminated |

## How to Present

**Do:** Lead with dollar figures. "We have $1.5M in combined annual exposure from unencrypted data and weak cryptography" gets attention. Follow with: "Equifax paid $700 million for unencrypted SSNs. Our SSNs are also unencrypted."

**Do:** Show the hash cracking demo. Nothing demonstrates MD5 weakness better than cracking all passwords in the room in 30 seconds. Run detect.sh live if the audience is technical.

**Do:** Show the ROSI. "$21,800 investment returns 32x on SC-28. $15,000 returns 38x on SC-13." Every executive understands ROI.

**Do:** Connect to compliance. "HIPAA requires encryption of PHI at rest. Our patient records are in plaintext. This is a breach notification trigger." Creates immediate urgency.

**Do:** Reference the breach precedents. "Equifax: $700M for unencrypted SSNs. Anthem: $131M for unencrypted PHI. Adobe: $1.1M for DES-ECB encryption. These are our exact findings."

**Don't:** Explain how MD5 collisions work mathematically. The CISO cares that passwords are crackable in seconds, not that Xiaoyun Wang used differential cryptanalysis.

**Don't:** Present more than 5-8 findings. Prioritize by risk score. Detail the top 3, summarize the rest.

**Don't:** Make recommendations without cost and ROI. Every "we should do X" needs "it costs $Y and saves $Z."

**Don't:** Forget the timeline. "Implement within 14 days, starting with password hashing on day 1" gives the CISO a plan to act on, not just a problem to worry about.
