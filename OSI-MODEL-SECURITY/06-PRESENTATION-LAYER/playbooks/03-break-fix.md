# Layer 6 Presentation — Break/Fix Scenarios

## Purpose

Run each scenario's break, detect, fix, validate cycle to demonstrate the control's value and produce evidence for governance reporting.

## How to Run a Scenario

Each scenario is in `scenarios/{CONTROL-ID}-{name}/` and contains .sh scripts and governance documentation:

### SC-28 Unencrypted Data at Rest

| File | Purpose | Format |
|------|---------|--------|
| `break.sh` | Creates SQLite database with plaintext passwords, PII, PHI; writes secrets to config files; disables disk encryption | Script |
| `detect.sh` | Queries database for plaintext fields, scans configs for hardcoded secrets, checks disk encryption | Script |
| `fix.sh` | Hashes passwords with bcrypt/PBKDF2, encrypts PII with AES-256, migrates secrets to vault references | Script |
| `validate.sh` | Verifies no plaintext passwords, PII encrypted, no hardcoded secrets, disk encryption status | Script |
| `governance.md` | CISO brief with SC-28 risk, Equifax/Anthem breach data, HIPAA requirements, Gordon-Loeb, ROSI | Documentation |

### SC-13 Weak Cryptography

| File | Purpose | Format |
|------|---------|--------|
| `break.sh` | Creates database with MD5-hashed passwords, SHA-1 file integrity, weak crypto config, vulnerable auth code | Script |
| `detect.sh` | Cracks MD5 hashes with dictionary attack, audits code/config for weak algorithms | Script |
| `fix.sh` | Migrates passwords to bcrypt/PBKDF2, replaces SHA-1 with SHA-256, updates config to FIPS 140-2 standards | Script |
| `validate.sh` | Verifies all passwords use approved hashing, SHA-256 checksums, FIPS config, no weak patterns in code | Script |
| `governance.md` | CISO brief with SC-13 risk, LinkedIn breach, Wang et al MD5 collision, FIPS 140-2 requirements, Gordon-Loeb, ROSI | Documentation |

## Scenario Execution Order

### Scenario 1: SC-28 Unencrypted Data at Rest

1. Read the scenario overview in `scenarios/SC-28-unencrypted-data/governance.md` — understand the business risk
2. Run `scenarios/SC-28-unencrypted-data/break.sh` — create vulnerable data environment
   ```bash
   ./scenarios/SC-28-unencrypted-data/break.sh /tmp/sc28-data-lab
   ```
3. Run `scenarios/SC-28-unencrypted-data/detect.sh` — confirm plaintext data and missing encryption
   ```bash
   ./scenarios/SC-28-unencrypted-data/detect.sh /tmp/sc28-data-lab
   ```
4. Run `scenarios/SC-28-unencrypted-data/fix.sh` — hash passwords, encrypt PII, migrate secrets
   ```bash
   ./scenarios/SC-28-unencrypted-data/fix.sh /tmp/sc28-data-lab
   ```
5. Run `scenarios/SC-28-unencrypted-data/validate.sh` — confirm the fix
   ```bash
   ./scenarios/SC-28-unencrypted-data/validate.sh /tmp/sc28-data-lab
   ```
6. Review `scenarios/SC-28-unencrypted-data/governance.md` — understand the CISO narrative

### Scenario 2: SC-13 Weak Cryptography

1. Read the scenario overview in `scenarios/SC-13-weak-crypto/governance.md` — understand the business risk
2. Run `scenarios/SC-13-weak-crypto/break.sh` — create weak crypto environment
   ```bash
   ./scenarios/SC-13-weak-crypto/break.sh /tmp/sc13-crypto-lab
   ```
3. Run `scenarios/SC-13-weak-crypto/detect.sh` — crack MD5 hashes, audit algorithms
   ```bash
   ./scenarios/SC-13-weak-crypto/detect.sh /tmp/sc13-crypto-lab
   ```
4. Run `scenarios/SC-13-weak-crypto/fix.sh` — migrate to FIPS 140-2 approved algorithms
   ```bash
   ./scenarios/SC-13-weak-crypto/fix.sh /tmp/sc13-crypto-lab
   ```
5. Run `scenarios/SC-13-weak-crypto/validate.sh` — confirm approved algorithms in use
   ```bash
   ./scenarios/SC-13-weak-crypto/validate.sh /tmp/sc13-crypto-lab
   ```
6. Review `scenarios/SC-13-weak-crypto/governance.md` — understand the CISO narrative

## Tools Required

| Tool | Install | Purpose |
|------|---------|---------|
| sqlite3 | `apt install sqlite3` or pre-installed | Database creation and querying |
| python3 | Pre-installed on most systems | Hash generation, cracking, encryption |
| hashcat | `apt install hashcat` | GPU-accelerated hash cracking (optional) |
| openssl | Pre-installed on most systems | Key generation, encryption verification |
| sha256sum | Pre-installed on Linux | SHA-256 checksum generation |
| trufflehog | `pip install trufflehog` | Git history secrets scanning |
| detect-secrets | `pip install detect-secrets` | Codebase secrets scanning |
| CyberChef | https://gchq.github.io/CyberChef/ | Encoding/decoding analysis (web tool) |
| manage-bde | Windows built-in | BitLocker management |
| lsblk | Linux built-in | Disk layout and encryption check |

## Evidence Collection

After each scenario, save evidence to `evidence/YYYY-MM-DD/`:
- Database snapshots (before and after — showing plaintext vs encrypted)
- Hash cracking output (time to crack, passwords recovered)
- Configuration files (before and after — showing hardcoded secrets vs vault references)
- Disk encryption status output
- Validation test results
- Governance brief (completed with real data from the environment)
