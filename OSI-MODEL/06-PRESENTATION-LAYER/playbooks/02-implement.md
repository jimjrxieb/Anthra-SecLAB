# Layer 6 Presentation — Implement Controls

## Purpose

Implement data-at-rest encryption and cryptographic protections based on assessment findings. Start with highest-risk gaps from the 01-assess output.

## Implementation Order

Priority by risk and cost-efficiency:

### Priority 1: Password Hashing Migration (Week 1, ~$2,400)
1. Identify all user tables with MD5 or SHA-1 password hashes
2. Implement bcrypt (work factor 12) or PBKDF2-SHA256 (600,000 iterations) as the target algorithm
3. Strategy A (recommended): Re-hash on next login — verify old hash, replace with bcrypt
4. Strategy B (lab only): Batch migration using known passwords from break scenario
5. Force password reset for any accounts that cannot be migrated
6. Update authentication code to use constant-time comparison (hmac.compare_digest)
7. Add automated test: verify new user registration stores bcrypt, not MD5

### Priority 2: Secrets Migration to Vault (Week 1-2, ~$3,600)
1. Deploy secrets vault (HashiCorp Vault, Azure Key Vault, or AWS Secrets Manager)
2. Inventory all hardcoded secrets in config files and .env files
3. Migrate each secret to vault with documented path (e.g., `vault:secret/data/db/production#password`)
4. Update application config to reference vault paths or environment variables
5. Remove plaintext secrets from all config files
6. Add .gitignore entries for .env, *.key, *.pem, *.db
7. Install git pre-commit hook (detect-secrets or trufflehog) to prevent future secret commits
8. Scan git history for previously committed secrets: `trufflehog git file://./repo`

### Priority 3: Column-Level Encryption for PII/PHI (Week 2, ~$6,000)
1. Identify all database columns containing PII (SSN, DOB, address) and PHI (diagnosis, medication)
2. Generate AES-256 encryption key and store in vault
3. Implement application-level encryption: encrypt before INSERT, decrypt after SELECT
4. Use AES-256-GCM for authenticated encryption (integrity + confidentiality)
5. Migrate existing plaintext PII/PHI to encrypted format
6. Verify decryption works correctly for all application read paths
7. Update database indexes (encrypted columns cannot use standard B-tree indexes)
8. Document key rotation procedure

### Priority 4: Disk Encryption (Week 2-3, ~$2,400)
1. Linux: Enable LUKS2 on all data volumes (`cryptsetup luksFormat --type luks2 --cipher aes-xts-plain64 --key-size 512`)
2. Windows: Enable BitLocker with AES-256-XTS (`manage-bde -on C: -EncryptionMethod XtsAes256`)
3. Cloud: Enable encrypted EBS volumes with customer-managed KMS key
4. Verify TPM is used for key storage where available
5. Document recovery key storage procedure (escrow to vault, not shared drive)
6. Encrypt database backup volumes and verify backup/restore with encryption

### Priority 5: File Integrity Migration (Week 3, ~$600)
1. Replace all SHA-1 checksums with SHA-256
2. Update integrity verification scripts to use sha256sum
3. Add SHA-256 checksum generation to build/release pipeline
4. Remove SHA-1 checksum files

### Priority 6: Cryptographic Standards and CI Enforcement (Week 3-4, ~$1,800)
1. Create organizational CRYPTO-STANDARDS.md document listing approved/prohibited algorithms
2. Create semgrep rules to block MD5, SHA-1, DES, RC4, ECB, random.seed in CI
3. Add TLS cipher suite audit to deployment pipeline (testssl.sh or similar)
4. Configure SAST tool to flag weak crypto patterns
5. Update code review checklist to include cryptographic algorithm verification
6. Schedule quarterly cryptographic algorithm audit

## Verification After Each Implementation

After each control is implemented, run the corresponding scenario's `validate.sh` to confirm it works. Do not proceed to the next priority without validation.

## Cost Summary

| Priority | Scope | Estimated Cost | Timeline |
|----------|-------|---------------|----------|
| 1 | Password hashing migration | $2,400 | Week 1 |
| 2 | Secrets migration to vault | $3,600 | Week 1-2 |
| 3 | Column-level PII/PHI encryption | $6,000 | Week 2 |
| 4 | Disk encryption | $2,400 | Week 2-3 |
| 5 | File integrity migration | $600 | Week 3 |
| 6 | Crypto standards and CI enforcement | $1,800 | Week 3-4 |
| **Total** | | **$16,800** | **4 weeks** |
