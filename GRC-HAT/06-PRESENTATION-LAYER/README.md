# Layer 6 — Presentation

## What This Layer Covers

Data encoding, encryption at rest, input/output sanitization, cryptographic protection. This is the layer between the application logic and the raw data — how data is formatted, encrypted, and validated.

## Why It Matters

Passwords stored in MD5 get cracked in seconds. Unencrypted databases get dumped in breaches and every record becomes a liability. Weak cryptography is a compliance failure under every major framework — HIPAA, PCI-DSS, FedRAMP all require approved algorithms.

## NIST 800-53 Controls

| Control ID | Control Name | What It Requires |
|-----------|-------------|-----------------|
| SC-28 | Protection of Information at Rest | Encrypt stored data |
| SI-10 | Information Input Validation | Validate and sanitize all input |
| SC-13 | Cryptographic Protection | Use FIPS-approved algorithms |
| SI-15 | Information Output Filtering | Sanitize output to prevent data leakage |

## Tools

| Tool | Type | Cost | Purpose |
|------|------|------|---------|
| Microsoft BitLocker | Microsoft | Free with Windows Pro | Disk encryption |
| Azure Key Vault | Microsoft | Free tier | Secret and key management |
| OpenSSL | Open source | Free | Encryption verification |
| CyberChef | Open source | Free | Encoding/decoding analysis |
| hashcat | Open source | Free | Weak hash cracking demonstration |

## Scenarios

| Scenario | Control | Format |
|----------|---------|--------|
| [SC-28 Unencrypted Data](scenarios/SC-28-unencrypted-data/) | SC-28 | Scripts (.sh) |
| [SC-13 Weak Cryptography](scenarios/SC-13-weak-crypto/) | SC-13 | Scripts (.sh) |
