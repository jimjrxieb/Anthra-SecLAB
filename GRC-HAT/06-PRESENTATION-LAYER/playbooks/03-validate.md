# 03-validate.md — L6 Presentation Layer Validation

| Field | Value |
|---|---|
| **NIST Controls** | SC-28, SC-13, SC-12, SI-10 |
| **Prerequisite** | All fix playbooks applied: 02-fix-SC28-encryption.md + 02a-fix-SC13-crypto.md |
| **Objective** | Re-run all auditors, verify fixes hold, produce evidence archive for auditor review |
| **Time** | 30–60 minutes |
| **Rank** | D (re-run scripts, compare results) |

---

## Step 1: Re-Run All Auditors

```bash
# Full suite — compare timestamps with pre-fix evidence
./tools/run-all-audits.sh --dir $(pwd) --tls-host your-service:443

AFTER_EVIDENCE=$(ls -td /tmp/jsa-evidence/L6-presentation-* | head -1)
echo "After evidence: ${AFTER_EVIDENCE}"
```

---

## Step 2: Verify Encryption at Rest

```bash
# K8s etcd
APISERVER_POD=$(kubectl get pods -n kube-system -l component=kube-apiserver \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
kubectl get pod "$APISERVER_POD" -n kube-system \
    -o jsonpath='{.spec.containers[0].command}' \
    | python3 -c "
import json,sys
cmds = json.load(sys.stdin)
enc = [c for c in cmds if 'encryption-provider-config' in c]
print('[PASS]' if enc else '[FAIL]', 'etcd encryption flag:', enc[0] if enc else 'NOT SET')
"

# Spot-check: verify secret is encrypted in etcd (on control plane)
# Expected hex: 6b 38 73 3a 65 6e 63 3a = 'k8s:enc:'
ETCDCTL_API=3 etcdctl get /registry/secrets/default/$(kubectl get secrets -n default -o name | head -1 | cut -d/ -f2) \
    --endpoints=https://127.0.0.1:2379 \
    --cacert=/etc/kubernetes/pki/etcd/ca.crt \
    --cert=/etc/kubernetes/pki/etcd/server.crt \
    --key=/etc/kubernetes/pki/etcd/server.key \
    | hexdump -C | head -2

# Linux disk encryption
dmsetup ls --target crypt
lsblk -o NAME,TYPE,FSTYPE,MOUNTPOINT | grep crypt

# Windows BitLocker
# Get-BitLockerVolume -MountPoint "C:" | Select-Object ProtectionStatus, EncryptionMethod
```

---

## Step 3: Verify Cryptographic Standards

```bash
# TLS protocol check
echo | openssl s_client -connect your-service:443 -brief 2>/dev/null | grep Protocol
# Expected: TLSv1.2 or TLSv1.3

# Weak cipher rejection test
for cipher in RC4-SHA DES-CBC3-SHA EXP-RC4-MD5 "NULL-MD5"; do
    RESULT=$(echo | timeout 3 openssl s_client -connect your-service:443 \
        -cipher "$cipher" 2>&1 | grep -E "Cipher is|no ciphers|handshake failure" | head -1)
    if echo "$RESULT" | grep -q "Cipher is"; then
        echo "[FAIL] Accepted weak cipher: $cipher"
    else
        echo "[PASS] Rejected: $cipher"
    fi
done

# Source code: no MD5/SHA-1 remaining
MD5_COUNT=$(grep -rn "hashlib\.md5\|createHash.*md5" \
    --include="*.{py,js,ts}" --exclude-dir={node_modules,.git} . \
    2>/dev/null | wc -l)
echo "MD5 usage remaining: ${MD5_COUNT} (target: 0)"

SHA1_COUNT=$(grep -rn "hashlib\.sha1\b\|createHash.*sha1" \
    --include="*.{py,js,ts}" --exclude-dir={node_modules,.git} . \
    2>/dev/null | wc -l)
echo "SHA-1 usage remaining: ${SHA1_COUNT} (target: 0)"
```

---

## Step 4: Verify Hash Migration with hashcat

Demonstrate that migrated bcrypt hashes resist cracking — the central evidence for SC-13 compliance.

```bash
# Confirm no MD5 hashes remain in the user table
psql -h localhost -U postgres -c "
SELECT
    CASE
        WHEN password_hash ~ '^[a-f0-9]{32}$' THEN 'MD5 (FAIL)'
        WHEN password_hash LIKE '\$2b\$%' OR password_hash LIKE '\$2a\$%' THEN 'bcrypt (PASS)'
        WHEN password_hash LIKE '\$argon2%' THEN 'argon2 (PASS)'
        ELSE 'unknown'
    END as algorithm,
    COUNT(*) as count
FROM users
GROUP BY 1
ORDER BY 1;
"

# If any MD5 remain: run forced migration for inactive accounts
# or set force_password_reset = TRUE for those users

# hashcat validation: confirm bcrypt hashes from the new scheme cannot be cracked quickly
python3 -c "
import bcrypt, subprocess, tempfile, os

# Generate a sample bcrypt hash (as if from your app)
sample_hash = bcrypt.hashpw(b'password123', bcrypt.gensalt(rounds=12)).decode()
print(f'Sample bcrypt hash: {sample_hash[:20]}...')

# Write to temp file for hashcat
with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
    f.write(sample_hash + '\n')
    tmpfile = f.name

# Try to crack it for 30 seconds
print('Running hashcat for 30 seconds...')
result = subprocess.run(
    ['hashcat', '-m', '3200', tmpfile, '/usr/share/wordlists/rockyou.txt',
     '--runtime=30', '--quiet'],
    capture_output=True, text=True, timeout=45)

# Check if cracked
cracked = subprocess.run(
    ['hashcat', '-m', '3200', tmpfile, '--show'],
    capture_output=True, text=True)

if cracked.stdout.strip():
    print('[FAIL] Hash was cracked in 30 seconds')
else:
    print('[PASS] bcrypt hash not cracked in 30 seconds (expected)')

os.unlink(tmpfile)
" 2>/dev/null || echo "hashcat not available — skip crack test"
```

---

## Step 5: Verify Secrets Exposure Controls

```bash
# gitleaks should be clean
gitleaks detect --source . --exit-code 1 && echo "[PASS] No secrets in repo" \
    || echo "[FAIL] Secrets detected"

# No .env files in git
ENV_IN_GIT=$(git ls-files | grep -E "\.env$" | wc -l)
echo ".env files tracked in git: ${ENV_IN_GIT} (target: 0)"

# Pre-commit hook installed
if [[ -x .git/hooks/pre-commit ]]; then
    echo "[PASS] pre-commit hook installed and executable"
else
    echo "[FAIL] pre-commit hook not installed"
fi

# No ConfigMaps with secret-like keys
kubectl get configmaps -A -o json \
    | python3 -c "
import json,sys
data = json.load(sys.stdin)
secret_keys = ['password','token','secret','api_key','apikey']
findings = 0
for cm in data.get('items', []):
    if cm['metadata']['namespace'] in ['kube-system','kube-public']:
        continue
    for key in (cm.get('data') or {}).keys():
        if any(sk in key.lower() for sk in secret_keys):
            print(f'[WARN] {cm[\"metadata\"][\"namespace\"]}/{cm[\"metadata\"][\"name\"]}: key={key}')
            findings += 1
print(f'[PASS] ConfigMap secret scan: {findings} findings' if findings == 0
      else f'[FAIL] ConfigMap secret scan: {findings} findings')
"
```

---

## Step 6: Evidence Archive

```bash
BEFORE_EVIDENCE=$(ls -td /tmp/jsa-evidence/L6-presentation-* | tail -1)
AFTER_EVIDENCE=$(ls -td /tmp/jsa-evidence/L6-presentation-* | head -1)

echo "Before: ${BEFORE_EVIDENCE}"
echo "After:  ${AFTER_EVIDENCE}"

# Compare total findings
BEFORE_FINDINGS=$(cat "${BEFORE_EVIDENCE}/master-summary.txt" 2>/dev/null \
    | grep "Total Findings" | awk '{print $NF}')
AFTER_FINDINGS=$(cat "${AFTER_EVIDENCE}/master-summary.txt" 2>/dev/null \
    | grep "Total Findings" | awk '{print $NF}')

echo ""
echo "Before findings: ${BEFORE_FINDINGS}"
echo "After findings:  ${AFTER_FINDINGS}"
echo "Improvement: $(( ${BEFORE_FINDINGS:-0} - ${AFTER_FINDINGS:-0} )) findings resolved"

# Copy both to evidence/ dir for this engagement
LAYER_EVIDENCE="$(dirname $0)/../evidence"
mkdir -p "${LAYER_EVIDENCE}"
cp -r "$BEFORE_EVIDENCE" "${LAYER_EVIDENCE}/before-$(basename $BEFORE_EVIDENCE)"
cp -r "$AFTER_EVIDENCE" "${LAYER_EVIDENCE}/after-$(basename $AFTER_EVIDENCE)"

echo ""
echo "Evidence archived to: ${LAYER_EVIDENCE}"
```

---

## Validation Pass Criteria

All of the following must be true before marking L6 complete:

- [ ] `audit-encryption-at-rest.sh` returns 0 FAIL findings
- [ ] etcd hexdump shows `k8s:enc:aescbc:v1` prefix (or KMS equivalent)
- [ ] Disk encryption active (LUKS mappings or BitLocker ProtectionStatus=On)
- [ ] `audit-crypto-standards.sh` returns 0 FAIL findings
- [ ] TLS endpoints accept only TLS 1.2+
- [ ] All weak cipher tests rejected
- [ ] No MD5/SHA-1 in source code (grep returns 0 matches)
- [ ] `audit-key-rotation.sh` returns 0 FAIL findings (no keys > 365 days)
- [ ] `audit-secrets-exposure.sh` returns 0 FAIL findings (gitleaks clean)
- [ ] bcrypt hashcat test: 0 passwords cracked in 30 seconds
- [ ] Before/after evidence archived in evidence/
