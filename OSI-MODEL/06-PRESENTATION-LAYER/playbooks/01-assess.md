# Layer 6 Presentation — Assess Current State

## Purpose

Document the current data encoding, encryption at rest, and cryptographic algorithm posture before implementing any controls. This assessment establishes the baseline for measuring improvement.

## Assessment Checklist

### SC-28 Protection of Information at Rest

- [ ] Identify all databases in the environment. What DBMS? Where hosted?
- [ ] For each database: are passwords stored as plaintext, MD5, SHA-1, or bcrypt/Argon2?
- [ ] For each database: is PII (SSN, DOB, address) encrypted at the column level?
- [ ] For each database: is PHI (diagnoses, medications, insurance IDs) encrypted at the column level?
- [ ] Are API keys, tokens, and service credentials stored in the database? If so, encrypted?
- [ ] Check all configuration files (.yaml, .json, .xml, .properties) for hardcoded secrets
- [ ] Check all .env files for plaintext passwords, API keys, and tokens
- [ ] Is .env in .gitignore? Has it ever been committed? (`git log --all --follow -p -- .env`)
- [ ] Where are secrets stored? (Hardcoded, env vars, vault, cloud KMS?)
- [ ] Is disk encryption enabled on all volumes? (Linux: `lsblk` for LUKS; Windows: `manage-bde -status`)
- [ ] Are database backups encrypted at rest?
- [ ] Are cloud storage volumes (EBS, Azure Disk, GCS) encrypted with customer-managed keys?

### SC-13 Cryptographic Protection

- [ ] Inventory all password hashing algorithms in use (query each user table)
- [ ] For MD5/SHA-1 hashes: how many accounts are affected?
- [ ] What hash work factor is used for bcrypt? (Target: 12+)
- [ ] What iteration count for PBKDF2? (Target: 600,000+ per OWASP 2024)
- [ ] What algorithm is used for file integrity checks? (SHA-1 vs SHA-256+)
- [ ] What encryption algorithm is used for data at rest? (DES, 3DES, AES-128, AES-256?)
- [ ] What encryption mode is used? (ECB leaks patterns — must use GCM or CBC+HMAC)
- [ ] What TLS version is configured as minimum? (Target: 1.2, prefer 1.3)
- [ ] What cipher suites are enabled? Any RC4, DES, 3DES, or NULL ciphers?
- [ ] How are security tokens generated? (`random` module or `secrets`/CSPRNG?)
- [ ] Is there a static seed for any random number generator?
- [ ] Is there an organizational cryptographic standards document?
- [ ] When was the last cryptographic algorithm audit?

### Secrets Management Review

- [ ] Is a secrets vault deployed? (HashiCorp Vault, Azure Key Vault, AWS Secrets Manager)
- [ ] Do applications retrieve secrets from vault at runtime or are secrets baked into images?
- [ ] Is secret rotation automated? What is the rotation schedule?
- [ ] Are Kubernetes Secrets encrypted at rest with KMS? (`kubectl get secret -o yaml` — base64 is NOT encryption)
- [ ] Is there a process for emergency secret rotation (breach response)?
- [ ] Are secrets logged anywhere? (Check application logs, debug output, error messages)
- [ ] Is there a git pre-commit hook to detect secrets? (git-secrets, detect-secrets, trufflehog)

### Key Management

- [ ] Where are encryption keys stored? (Same server as data = no protection)
- [ ] Are encryption keys rotated? On what schedule?
- [ ] Is there key separation between environments (dev/staging/prod)?
- [ ] Who has access to encryption keys? Is access logged?
- [ ] Is there a key recovery procedure documented?
- [ ] Are HSMs or cloud KMS used for key storage?

## Tools for Assessment

| Tool | Command | Purpose |
|------|---------|---------|
| sqlite3 | `sqlite3 app.db "SELECT password FROM users LIMIT 5;"` | Check password storage format |
| grep | `grep -rn 'password\|secret\|api_key' /path/to/config/` | Find hardcoded secrets |
| trufflehog | `trufflehog git file://./repo` | Scan git history for secrets |
| detect-secrets | `detect-secrets scan --all-files` | Scan codebase for secrets |
| lsblk | `lsblk -o NAME,FSTYPE,TYPE,SIZE` | Check disk encryption (LUKS) |
| manage-bde | `manage-bde -status C:` | Check BitLocker (Windows) |
| openssl | `openssl s_client -connect host:443` | Check TLS version and ciphers |
| hashcat | `hashcat --identify hash.txt` | Identify hash algorithm |
| CyberChef | Web tool | Decode and analyze encoding |

## Output

Complete the checklist above and produce:
1. Data-at-rest encryption inventory (databases, volumes, backups, config files)
2. Cryptographic algorithm inventory (password hashing, integrity, encryption, TLS, PRNG)
3. Secrets management inventory (where secrets live, rotation status, vault usage)
4. Gap analysis: which SC-28 and SC-13 controls have findings?
5. Risk ranking of findings using 5x5 matrix
