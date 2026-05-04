# 01-assess.md — L6 Presentation Layer Assessment

| Field | Value |
|---|---|
| **NIST Controls** | SC-28, SC-13, SC-12, SI-10, SI-15 |
| **Objective** | Establish encryption baseline — etcd, disk, database, keys, secrets, algorithms |
| **Output** | Gap analysis, prioritized findings, evidence archive |
| **Time** | 1–2 hours |
| **Rank** | D (run auditors, no decisions required at this stage) |

---

## Quick Start

```bash
# Run all 4 auditors at once
./tools/run-all-audits.sh --dir $(pwd)

# Or run individually with scan dir specified:
./01-auditors/audit-encryption-at-rest.sh
./01-auditors/audit-key-rotation.sh
./01-auditors/audit-crypto-standards.sh --dir /path/to/source-code
./01-auditors/audit-secrets-exposure.sh --dir /path/to/repo
```

---

## Checklist 1: Encryption at Rest (SC-28)

| # | Check | Command/Verification | Pass Condition |
|---|---|---|---|
| 1 | K8s etcd encryption enabled | `kubectl get pod kube-apiserver-* -n kube-system -o yaml \| grep encryption-provider` | `--encryption-provider-config` flag present |
| 2 | K8s Secrets encrypted in etcd | `etcdctl get /registry/secrets/default/<name>` | Output begins with `k8s:enc:aescbc:v1` |
| 3 | EncryptionConfiguration provider | Read the YAML at encryption-provider-config path | Provider is `aescbc` or `kms`, NOT just `identity` |
| 4 | PostgreSQL SSL enabled | `psql -c "SHOW ssl;"` | Returns `on` |
| 5 | PostgreSQL data directory encrypted | Verify OS-level LUKS/BitLocker covers data_directory | LUKS or BitLocker active on that path |
| 6 | Linux disk encryption | `dmsetup ls --target crypt` + `cryptsetup status` | Active LUKS mappings for OS/data volumes |
| 7 | Windows disk encryption | `manage-bde -status C:` or `Get-BitLockerVolume` | `ProtectionStatus: On` |
| 8 | Azure storage encryption | `az storage account show --query encryption` | `blob.enabled: true`, `keySource: Microsoft.Keyvault` (BYOK) |

**Priority:** #1, #2, #3 are critical. etcd stores ALL cluster secrets.

---

## Checklist 2: Key Rotation (SC-12)

| # | Check | Command/Verification | Pass Condition |
|---|---|---|---|
| 1 | Azure Key Vault key age | `az keyvault key list` → check `attributes.created` | All keys < 90 days old |
| 2 | Azure Key Vault rotation policy | `az keyvault key rotation-policy show` | Auto-rotation enabled, expiryTime set |
| 3 | HashiCorp Vault transit key age | `vault read transit/keys/<name>` → check version creation | Latest version < 90 days old |
| 4 | HashiCorp Vault min decryption version | `vault read transit/keys/<name>` → `min_decryption_version` | Old versions retired after migration |
| 5 | cert-manager certificate expiry | `kubectl get certificates -A` → check `notAfter` | All certs expire > 30 days from now |
| 6 | TLS certificate age | `openssl s_client -connect host:443` → `NotAfter` | Not expired, not within 30 days of expiry |

**Priority:** #5, #6 first — expired certs cause outages. Then #1, #2 for compliance.

---

## Checklist 3: Cryptographic Standards (SC-13)

| # | Check | Command/Verification | Pass Condition |
|---|---|---|---|
| 1 | No MD5 in source code | `grep -rn "hashlib.md5\|createHash.*md5" --include="*.{py,js,ts}"` | No matches |
| 2 | No SHA-1 in source code | `grep -rn "hashlib.sha1\|createHash.*sha1"` | No matches in auth/crypto code |
| 3 | No DES/3DES in configs | `grep -rn "\bDES\b\|3DES\|TripleDES" --include="*.{conf,yaml,yml}"` | No matches |
| 4 | No RC4 in configs | `grep -rn "\bRC4\b" --include="*.{conf,yaml,yml,cnf}"` | No matches |
| 5 | TLS 1.2+ on all endpoints | `openssl s_client -connect <host>:443` → Protocol line | `TLSv1.2` or `TLSv1.3` only |
| 6 | No weak TLS ciphers accepted | `openssl s_client -cipher RC4-SHA -connect <host>:443` | Connection rejected |
| 7 | Password hashing uses bcrypt/argon2 | `grep -rn "bcrypt\|argon2\|scrypt" --include="*.py"` | Found in auth code |
| 8 | No MD5 for password storage | `grep -rn "password.*md5\|md5.*password"` | No matches |

**Priority:** #1, #8 — MD5 passwords crack in seconds. Then #5, #6 for TLS hardening.

---

## Checklist 4: Secrets Exposure (SC-28 / SI-10)

| # | Check | Command/Verification | Pass Condition |
|---|---|---|---|
| 1 | gitleaks clean | `gitleaks detect --source . --verbose` | Exit code 0, no leaks |
| 2 | No .env files in git | `git ls-files \| grep "\.env$"` | No matches |
| 3 | No .env files in git history | `git log --all --name-only --pretty=format: \| grep "\.env$" \| sort -u` | No matches |
| 4 | K8s ConfigMaps: no passwords | Check ConfigMap data for password/token/secret keys | No secret-like values in ConfigMaps |
| 5 | K8s Secrets used (not ConfigMaps) | `kubectl get deployments -A -o yaml \| grep -A5 envFrom` | `secretRef`, not `configMapRef` for credentials |
| 6 | Pre-commit hook installed | `ls .git/hooks/pre-commit` | Exists and is executable |
| 7 | Secret detection in pre-commit | `cat .pre-commit-config.yaml \| grep gitleaks` | gitleaks or detect-secrets configured |
| 8 | No hardcoded credentials in Dockerfiles | `grep -rn "ENV.*PASSWORD\|ENV.*SECRET\|ENV.*TOKEN" --include="Dockerfile"` | No matches with real values |

**Priority:** #1 first — rotate immediately if found. Then #2, #3 — history exposure is hard to undo.

---

## Priority Ranking

Based on NIST risk and remediation difficulty:

| Priority | Finding | NIST | Effort | Blast Radius |
|---|---|---|---|---|
| **P1** | Secrets in git history | SC-28 | High | Permanent — secrets must be rotated |
| **P1** | MD5/SHA-1 passwords | SC-13, IA-5 | Medium | All user accounts |
| **P2** | etcd not encrypted | SC-28 | Medium | All cluster secrets |
| **P2** | Weak TLS (1.0/1.1) | SC-13 | Low | All encrypted traffic |
| **P3** | Keys older than 365 days | SC-12 | Low | Encrypted data at risk |
| **P3** | No disk encryption | SC-28 | High | Physical access = full compromise |
| **P4** | ConfigMap secrets | SC-28 | Medium | Depends on what is stored |
| **P4** | No pre-commit hooks | SI-10 | Low | Future secrets may leak |

---

## What to Do With Findings

| Finding type | Next playbook |
|---|---|
| etcd not encrypted | `02-fix-SC28-encryption.md` |
| No disk encryption | `02-fix-SC28-encryption.md` |
| Weak hashing (MD5/SHA-1) | `02a-fix-SC13-crypto.md` |
| Weak TLS | `02a-fix-SC13-crypto.md` |
| Key rotation needed | `02-fixers/fix-key-rotation.sh` |
| Secrets in git | Rotate immediately + `02-fixers/fix-plaintext-secrets.sh` |
| Deep encryption audit needed | `01a-encryption-audit.md` |
| Deep crypto audit needed | `01b-crypto-standards-audit.md` |
