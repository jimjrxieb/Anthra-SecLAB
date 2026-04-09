# Layer 6 Presentation — Control Map

| NIST Control | Control Name | Tool | Enterprise Equivalent | What Misconfiguration Looks Like |
|-------------|-------------|------|----------------------|--------------------------------|
| SC-28 | Protection of Information at Rest | BitLocker, Azure Key Vault | Thales CipherTrust, Vormetric | Unencrypted database, plaintext passwords, secrets in config files |
| SI-10 | Information Input Validation | CyberChef, manual review | Imperva WAF, F5 ASM | No input sanitization, injection vectors in forms/APIs |
| SC-13 | Cryptographic Protection | OpenSSL, hashcat | Thales HSM, AWS KMS | MD5/SHA1 for passwords, weak PRNG, homebrew crypto |
| SI-15 | Information Output Filtering | Manual review, CyberChef | DLP (Symantec, Forcepoint) | PII in logs, stack traces in error responses, verbose debug output |
