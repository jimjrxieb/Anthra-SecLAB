# Layer 4 Transport — CISO Report

## Purpose

Compile scenario results into a governance report suitable for CISO or board presentation. This playbook teaches you how to translate transport-layer security findings into business language.

## Report Structure

### 1. Executive Summary (1 paragraph)

Template: "Transport-layer security assessment of [environment name] identified [N] findings across [N] controls (SC-8, IA-5). The highest-risk finding is [description] with an estimated annual loss exposure of $[X]. Total remediation cost: $[X]. Overall ROSI: [X]x. [N] findings require immediate action to maintain [compliance framework] compliance. PCI-DSS explicitly bans TLS 1.0 — any affected payment system is non-compliant until remediated."

### 2. Risk Heatmap

Plot each finding on the 5x5 matrix:

```
        Impact ->
        1    2    3    4    5
  5   |    |    |    |    |    |
L 4   |    |    |    |!!  |    |   SC-8 Weak TLS, IA-5 Expired Cert
i 3   |    |    |    |    |    |
k 2   |    |    |    |    |    |
e 1   |    |    |    |    |    |
```

Legend: blank = Low, ! = Medium, !! = High/Very High

### 3. Financial Summary

| Finding | ALE | Fix Cost | ROSI | Gordon-Loeb Check |
|---------|-----|----------|------|-------------------|
| SC-8 Weak TLS | $976,000 | $3,000 | 292x | Under ceiling (0.31%) |
| IA-5 Expired Certificate | $312,000 | $4,400 | 66x | Under ceiling (1.4%) |
| **Combined** | **$1,288,000** | **$7,400** | **165x** | **Under ceiling** |

### 4. Compliance Impact

| Framework | Control | Status | Impact if Not Remediated |
|-----------|---------|--------|------------------------|
| FedRAMP | SC-8 | Other Than Satisfied | ATO blocked |
| FedRAMP | IA-5 | Other Than Satisfied | ATO blocked |
| PCI-DSS | Req 4.1 | Non-Compliant | TLS 1.0 ban since June 2018 — fines $5K-$100K/month |
| HIPAA | §164.312(e)(1) | Gap | Transmission security requirement — OCR investigation risk |
| SOC 2 | CC6.1, CC6.7 | Gap | Qualified opinion on encryption controls |
| ISO 27001 | A.10.1.1 | Gap | Cryptographic controls non-conformity |
| NIST 800-171 | 3.13.8 | Gap | CUI transmission protection — DFARS non-compliance |

### 5. Precedent Cases

| Incident | Root Cause | Cost | Relevance |
|----------|-----------|------|-----------|
| Equifax 2017 | Expired certificate on SSL inspection device (19 months) | $1.4 billion | IA-5: No cert inventory, no monitoring, no renewal |
| Microsoft Teams 2020 | Expired authentication certificate | $50M+ estimated | IA-5: No automated renewal for critical cert |
| Let's Encrypt Root 2021 | Root CA expiry broke legacy devices | $100M+ aggregate | IA-5: Chain management, not just leaf certs |
| BEAST/POODLE 2011-2014 | TLS 1.0 protocol weaknesses exploited | Industry-wide | SC-8: TLS 1.0 is a broken protocol |

### 6. Recommendation Summary

| Finding | Decision | Priority | Timeline | Cost | Return |
|---------|----------|----------|----------|------|--------|
| SC-8 Weak TLS | Mitigate | High | 30 days | $3,000 | 292x ROSI |
| IA-5 Expired Cert | Mitigate | High | 30 days | $4,400 | 66x ROSI |

## How to Present

**Do:** Lead with the Equifax story. "$1.4 billion because nobody checked whether a certificate was expired." Every executive knows Equifax. Every executive fears being the next one.

**Do:** Show the PCI-DSS deadline. "TLS 1.0 was banned six years ago. Every day we accept TLS 1.0 connections on payment systems, we are non-compliant." Binary. No gray area.

**Do:** Show the ROSI. "Combined $7,400 investment eliminates $1.3M annual exposure with a 165x return." That is the language of capital allocation.

**Do:** Emphasize automation. "Certificate expiry is not a technology problem — it is a process problem. certbot renews automatically. The monitoring script alerts 30 days before expiry. The Equifax failure mode is eliminated."

**Don't:** Get into cipher suite specifics. The CISO does not need to know the difference between AES-128-GCM and AES-256-GCM. They need to know "we removed all the broken ones and kept only the ones that NIST approves."

**Don't:** Downplay expired certificates as "just an outage risk." The Equifax case proves that expired certificates have security implications — they blind monitoring tools.

**Don't:** Present without a timeline. "We will fix this" is not actionable. "TLS hardening completes in Week 1, certificate lifecycle automation completes in Week 2, validation in Week 3" is actionable.

**Don't:** Forget the ongoing operations cost. The one-time fix is cheap, but monitoring and maintenance require budget allocation. Present it: "$7,000/year ongoing to maintain transport-layer security across the environment."
