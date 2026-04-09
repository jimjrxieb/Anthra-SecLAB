# SC-13 Weak Cryptography — CISO Governance Brief

## Executive Summary

Cryptographic algorithm audit identified critical weaknesses: application passwords are hashed with MD5 (collision-broken since 2004, crackable at 150 billion hashes/second on a single GPU), file integrity checks use SHA-1 (collision-demonstrated 2017 by Google/CWI for ~$110,000), and the application configuration specifies DES encryption (56-bit key, brute-forced in hours) with ECB mode (leaks plaintext patterns). A database dump would expose all user credentials within seconds. LinkedIn's 2012 breach demonstrated this exact scenario — 6.5 million SHA-1 password hashes cracked by researchers within days, with the true scope later revealed as 117 million accounts. Estimated annual loss exposure: $732,000. Recommended remediation (bcrypt migration, SHA-256 integrity, FIPS 140-2 config, code remediation) costs $12,600 one-time + $2,400/year. ROSI: 39x in year one.

## NIST 800-53 Control Requirement

**SC-13 Cryptographic Protection:** "The information system implements FIPS-validated or NSA-approved cryptography in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards."

**SC-13(1) FIPS-Validated Cryptography:** "The information system implements FIPS-validated cryptography for all cryptographic functions."

**Required by:** FedRAMP (all baselines — SC-13 is required at Low, Moderate, and High), NIST 800-171 (3.13.11 — Employ FIPS-validated cryptography), HIPAA (Section 164.312(a)(2)(iv) — Encryption implementation specification), PCI-DSS (Requirement 3.4 — Render PAN unreadable using strong cryptography, Requirement 4.1 — Protect cardholder data with strong cryptography during transmission), CMMC Level 2 (SC.L2-3.13.11 — CUI Encryption), SOC 2 (CC6.1 — Encryption of data), ISO 27001 (A.10.1.1 — Policy on use of cryptographic controls), FIPS 140-2 (all federal systems processing sensitive data).

## Attack History

### Wang et al MD5 Collision — 2004
Xiaoyun Wang and colleagues demonstrated the first practical collision attack against MD5 at CRYPTO 2004. They showed that two different inputs could produce identical MD5 hashes, fundamentally breaking the algorithm's security properties. This was not theoretical — the attack was practical and reproducible. Despite this, MD5 continued to be used for password hashing in production systems for over a decade, directly leading to breaches at LinkedIn, Adobe, and others.

### LinkedIn Breach — June 2012
Attackers exfiltrated 6.5 million password hashes from LinkedIn's user database. The passwords were hashed with unsalted SHA-1. Security researcher Jeremi Gosney cracked 90% of the hashes within days using GPU-accelerated hashcat. In 2016, it emerged that the actual breach scope was 117 million accounts. The cracked passwords were sold on dark web markets and used in credential stuffing attacks across thousands of other services. LinkedIn was acquired by Microsoft for $26.2 billion — the breach contributed to valuation pressure.

### Adobe Breach — October 2013
Attackers stole 153 million user records from Adobe. Passwords were encrypted with 3DES-ECB (not hashed — encrypted, and with the worst possible mode). Because ECB mode preserves patterns, identical passwords produced identical ciphertext. The most common password — "123456" — was immediately identifiable across 1.9 million accounts because they all had the same encrypted value. Adobe settled for $1.1 million and faced years of regulatory scrutiny.

### SHAttered: SHA-1 Collision — February 2017
Google and CWI Amsterdam demonstrated the first practical SHA-1 collision, producing two different PDF documents with identical SHA-1 hashes. The computation cost approximately $110,000 in cloud GPU time. By 2020, Stevens et al demonstrated a chosen-prefix collision attack for approximately $45,000 — bringing SHA-1 collision attacks within reach of well-funded attackers. Git, SVN, and many integrity verification systems relied on SHA-1 and required migration.

### Hashcat Performance Benchmarks — 2024
A single NVIDIA RTX 4090 GPU achieves approximately 150 billion MD5 hashes per second and 50 billion SHA-1 hashes per second. This means an 8-character password using all printable ASCII characters (95^8 = 6.6 quadrillion combinations) falls to MD5 brute force in approximately 12 hours. For context: the average employee password has fewer than 10 characters and uses a subset of the character space. Dictionary attacks with rules crack 80%+ of real-world MD5 password hashes in under 60 seconds.

## Risk Assessment

- **Likelihood: 5 (Almost Certain)** — MD5 password cracking is automated and instant. Hashcat cracks dictionary passwords hashed with MD5 in seconds. Every database breach in the last decade that exposed MD5 hashes resulted in mass credential recovery. It is not a question of whether the passwords can be cracked — it is a certainty.
- **Impact: 4 (Major)** — Cracked passwords enable credential stuffing (65% of users reuse passwords per Google research), account takeover across all services, and lateral movement within the organization. SHA-1 integrity bypass enables file tampering without detection. Weak encryption (DES/ECB) renders data protection meaningless.
- **Inherent Risk Score: 20** (5 x 4)
- **Risk Level: Critical**

## 5x5 Risk Matrix

```
        Impact ->
        1    2    3    4    5
  5   |    |    |    |[X] |    |   <- SC-13 Weak Crypto (L:5, I:4 = 20 CRITICAL)
L 4   |    |    |    |    |    |
i 3   |    |    |    |    |    |
k 2   |    |    |    |    |    |
e 1   |    |    |    |    |    |
```

Risk Score 20 = Critical. Remediation required within 14 days per most vulnerability management SLAs.

## Business Impact

- **Attack path:** Database dump (SQL injection, backup exposure, insider threat) → MD5 hashes extracted → hashcat cracks 80%+ in under 60 seconds → credential stuffing across all services → account takeover, data exfiltration, lateral movement
- **Data exposure:** All user credentials. With cracked passwords: access to every system where the user reuses that password (email, VPN, cloud console, financial systems). With SHA-1 bypass: ability to tamper with files whose integrity is verified by SHA-1 without detection.
- **Estimated breach cost:** IBM Cost of a Data Breach 2024: stolen credentials cost **$4.81M** per breach (most expensive initial attack vector). Average lifecycle of credential-based breach: **292 days** (longest of any vector). For Anthra-SecLAB with 10 compromised accounts at estimated $73,200/account (productivity loss, incident response, regulatory): **$732,000**
- **Regulatory exposure:** FIPS 140-2 explicitly prohibits MD5 and SHA-1 for cryptographic purposes in federal systems. PCI-DSS Requirement 3.4 specifies "strong cryptography" — MD5 does not qualify. HIPAA encryption guidance references NIST standards that exclude MD5/SHA-1. Non-compliance triggers: PCI $5,000-$100,000/month, HIPAA up to $2.13M/year per violation category, FedRAMP ATO revocation.
- **Compliance gap:** SC-13 requires FIPS-validated cryptography. MD5 and SHA-1 are explicitly not approved for cryptographic use in any current federal standard. An auditor running hashcat against the password database is a routine pen test activity — cracking the passwords in seconds produces an undeniable Critical finding.

## Proportionality Analysis (Gordon-Loeb)

- **Asset value protected:** All user credentials and their downstream access. Estimated value: user account access ($3M based on 10 accounts with system access), downstream systems ($5M based on credential reuse attack surface), regulatory standing ($4M based on compliance revenue at risk) = **$12M**
- **Annualized Loss Expectancy (ALE):** Likelihood 15% (database breach resulting in hash exposure — common vector) x $4.88M (IBM average for credential-based breach) = **$732,000/year**
- **Control implementation cost:** $12,600 one-time (bcrypt password migration: 16 hours at $150/hr = $2,400; SHA-256 integrity migration: 4 hours at $150/hr = $600; crypto config update: 8 hours at $150/hr = $1,200; auth handler rewrite: 16 hours at $150/hr = $2,400; semgrep rule creation for CI: 8 hours at $150/hr = $1,200; testing and validation: 16 hours at $150/hr = $2,400; standards documentation: 4 hours at $150/hr = $600; code review: $1,800) + $2,400/year (quarterly crypto audit, algorithm deprecation monitoring) = **$15,000 first year**
- **ROSI:** ($732,000 x 0.85 risk_reduction - $15,000) / $15,000 = **38.4x return**
- **Gordon-Loeb ceiling:** 37% of $732,000 = **$270,840** — our $15,000 cost is 5.5% of the ceiling
- **Verdict: Highly Proportional** — Cryptographic algorithm migration is primarily an engineering effort with no licensing cost. Open source tools (bcrypt, hashlib) provide FIPS-grade algorithms at zero license cost. The investment returns 38x in year one.

## Remediation Summary

- **What was fixed:** Migrated all MD5 and SHA-1 password hashes to PBKDF2-SHA256 with 600,000 iterations (bcrypt with work factor 12 in production). Replaced all SHA-1 file integrity checksums with SHA-256. Updated cryptographic configuration to specify FIPS 140-2 approved algorithms only (AES-256-GCM, TLS 1.2+ minimum, CSPRNG). Rewrote authentication handler to use secrets module for token generation and hmac.compare_digest for constant-time password verification. Created organizational cryptographic standards document.
- **Time to remediate:** Password migration: 4 hours. Integrity migration: 1 hour. Config update: 2 hours. Auth handler rewrite: 4 hours. Standards document: 2 hours. Testing: 4 hours. Total: **17 hours across 4 business days**
- **Residual risk score:** Likelihood drops from 5 to 1 (Rare — bcrypt work factor 12 requires ~12 years per password on GPU, AES-256 has no practical attack), Impact drops from 4 to 2 (Minor — even if hashes stolen, cracking is computationally infeasible) = **2 (Low)**

## Metrics Impact

- **MTTD for this finding:** Database algorithm query identifies MD5 hashes in **30 seconds**. Code grep identifies weak patterns in **60 seconds**. Automated detection via detect.sh with hash cracking: **5 minutes total**.
- **MTTR:** Password migration: 4 hours. Full algorithm remediation: **4 business days**
- **Control coverage change:** SC-13 cryptographic protection: 0% (MD5/SHA-1/DES) → 100% (bcrypt/SHA-256/AES-256-GCM)
- **Vulnerability SLA status:** Within 14-day SLA for Critical findings

## Recommendation to Leadership

**Decision: Mitigate — Critical Priority**
Justification: MD5 password hashes are the cryptographic equivalent of storing passwords in plaintext — a single GPU cracks them in seconds. LinkedIn paid with 117 million exposed accounts. Adobe paid $1.1 million for using 3DES-ECB. The $15,000 investment in algorithm migration against $732,000 annual exposure delivers a 38x return. FIPS 140-2 explicitly prohibits MD5 and SHA-1 — this is not a recommendation, it is a federal requirement for any system processing sensitive data. PCI-DSS and HIPAA both require "strong cryptography" — MD5 has not qualified since 2004. The highest-impact action is the password hash migration — it takes 4 hours and immediately protects all user credentials. Follow with SHA-256 integrity migration, then crypto config standardization. Add semgrep rules to CI/CD to prevent future introduction of weak algorithms. Implement within 14 days. Start with password migration (day 1), then integrity checksums (day 2), then config and code (week 2).
