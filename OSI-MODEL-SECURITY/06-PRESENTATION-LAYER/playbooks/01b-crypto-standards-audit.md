# 01b-crypto-standards-audit.md — L6 Deep-Dive: Cryptographic Standards

| Field | Value |
|---|---|
| **NIST Controls** | SC-13 (cryptographic protection), IA-5(1) (authenticator management — passwords) |
| **Prerequisite** | `01-assess.md` checklist complete — at least one SC-13 finding identified |
| **Objective** | Full codebase scan for weak algorithms, TLS audit, password hash demonstration with hashcat |
| **Time** | 2–4 hours |
| **Rank** | D (scanning and evidence) / C (deciding migration order) |

---

## Part 1: Codebase Scan for Weak Algorithms

### Run the automated auditor

```bash
# Scan current repo
./01-auditors/audit-crypto-standards.sh --dir $(pwd) --tls-host localhost:443

# Evidence will be at: /tmp/jsa-evidence/crypto-standards-<timestamp>/
```

### Manual deep-dive by language

**Python:**

```bash
# Find all crypto usage in Python files
grep -rn -E "hashlib\.|hmac\.|cryptography\.|bcrypt\.|argon2\." \
    --include="*.py" . \
    | grep -v "__pycache__" \
    | grep -v ".pyc"

# Focus: authentication code
grep -rn -E "password|hash|digest|encrypt|decrypt|sign" \
    --include="*.py" \
    --include="*.pyc" \
    -l . \
    | grep -v "__pycache__"
# Then inspect each file manually

# Specific bad patterns
echo "=== MD5 usage ==="
grep -rn "hashlib\.md5" --include="*.py" .

echo "=== SHA-1 usage ==="
grep -rn "hashlib\.sha1\b" --include="*.py" .

echo "=== Good: bcrypt usage ==="
grep -rn "bcrypt\|argon2\|scrypt" --include="*.py" .
```

**JavaScript / TypeScript:**

```bash
echo "=== Bad: MD5 ==="
grep -rn "createHash.*['\"]md5['\"]" --include="*.{js,ts}" --exclude-dir=node_modules .

echo "=== Bad: SHA-1 ==="
grep -rn "createHash.*['\"]sha1['\"]" --include="*.{js,ts}" --exclude-dir=node_modules .

echo "=== Good: argon2/bcrypt ==="
grep -rn "require.*argon2\|require.*bcrypt\|from.*argon2\|from.*bcrypt" \
    --include="*.{js,ts}" --exclude-dir=node_modules .

# Check package.json for crypto dependencies
cat package.json 2>/dev/null | python3 -c "
import json,sys
pkg = json.load(sys.stdin)
deps = {**pkg.get('dependencies', {}), **pkg.get('devDependencies', {})}
crypto_pkgs = {k:v for k,v in deps.items() if any(w in k.lower() for w in
    ['crypto','bcrypt','argon','hash','encrypt','jwt','auth','password'])}
for k,v in crypto_pkgs.items():
    print(f'  {k}: {v}')
" 2>/dev/null || echo "no package.json"
```

**Go:**

```bash
echo "=== Bad: crypto/md5 ==="
grep -rn '"crypto/md5"' --include="*.go" .

echo "=== Bad: crypto/sha1 ==="
grep -rn '"crypto/sha1"' --include="*.go" .

echo "=== Good: bcrypt ==="
grep -rn "golang.org/x/crypto/bcrypt" --include="*.go" .

echo "=== Good: sha256 ==="
grep -rn '"crypto/sha256"' --include="*.go" .
```

**Configuration files:**

```bash
# OpenSSL / TLS configs
echo "=== TLS config weak protocols ==="
grep -rn -E "SSLv3|TLSv1\b|TLSv1\.0|TLSv1\.1" \
    --include="*.{conf,cfg,cnf,ini,yaml,yml}" .

echo "=== Weak cipher strings ==="
grep -rn -E "RC4|DES|3DES|NULL|EXPORT|aNULL|eNULL|MD5" \
    --include="*.{conf,cfg,cnf}" .

echo "=== Password hashing configs ==="
grep -rn -E "password_hash|PASSWORD_HASHER|HASH_ALGORITHM" \
    --include="*.{conf,cfg,yaml,yml,env,properties}" .
```

---

## Part 2: TLS Endpoint Audit

### Single endpoint check

```bash
HOST="example.internal"
PORT=443

# Basic: protocol and cipher
echo | openssl s_client -connect "${HOST}:${PORT}" -brief 2>/dev/null
# Look for: Protocol: TLSv1.2 or TLSv1.3

# Full certificate chain and cipher details
echo | openssl s_client -connect "${HOST}:${PORT}" 2>/dev/null \
    | grep -E "Protocol|Cipher|subject|issuer|Verify|notAfter|notBefore"

# Test for weak protocol acceptance
for proto in "-ssl3" "-tls1" "-tls1_1"; do
    echo -n "Testing $proto: "
    echo | timeout 3 openssl s_client $proto -connect "${HOST}:${PORT}" 2>&1 \
        | grep -E "Cipher is|no peer certificate|handshake failure|alert" \
        | head -1 || echo "rejected"
done

# Test weak cipher suites
echo "=== Weak cipher tests ==="
for cipher in RC4-SHA DES-CBC3-SHA EXP-RC4-MD5 "NULL-MD5" ADH-AES256-SHA; do
    echo -n "  Testing ${cipher}: "
    RESULT=$(echo | timeout 3 openssl s_client \
        -connect "${HOST}:${PORT}" \
        -cipher "$cipher" 2>&1 \
        | grep -E "Cipher is|no ciphers|handshake failure" | head -1)
    if echo "$RESULT" | grep -q "Cipher is"; then
        echo "FAIL — server accepted weak cipher"
    else
        echo "PASS — rejected"
    fi
done
```

### Cluster-wide TLS check

```bash
# Check all HTTPS services in K8s cluster
kubectl get services -A \
    -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.spec.clusterIP}{"\t"}{range .spec.ports[*]}{.port}{","}{end}{"\n"}{end}' \
    2>/dev/null \
    | while IFS=$'\t' read -r ns name ip ports; do
        if echo "$ports" | grep -qE "(443|8443),"; then
            echo "Checking: ${ns}/${name} (${ip}:443)"
            PROTO=$(echo | timeout 3 openssl s_client -connect "${ip}:443" -brief 2>/dev/null \
                | grep "Protocol" | awk '{print $NF}' || echo "unreachable")
            echo "  Protocol: ${PROTO}"
        fi
    done
```

---

## Part 3: Password Hash Demonstration (hashcat)

### Why MD5 is broken — live demo

This section demonstrates WHY MD5 is a SC-13 violation. Not just "it's deprecated" — it is actively crackable in seconds.

```bash
# Step 1: Create test MD5 hashes (simulating stolen database)
echo -n "password123" | md5sum | cut -d' ' -f1  # 482c811da5d5b4bc6d497ffa98491e38
echo -n "admin" | md5sum | cut -d' ' -f1          # 21232f297a57a5a743894a0e4a801fc3
echo -n "letmein" | md5sum | cut -d' ' -f1         # 0d107d09f5bbe40cade3de5c71e9e9b7

# Save to file
python3 -c "
import hashlib
passwords = ['password123', 'admin', 'letmein', 'welcome1', 'qwerty']
for p in passwords:
    h = hashlib.md5(p.encode()).hexdigest()
    print(h)
" > /tmp/test-md5-hashes.txt

cat /tmp/test-md5-hashes.txt
```

```bash
# Step 2: Benchmark MD5 crack speed (no wordlist needed — just speed test)
hashcat -b -m 0 --quiet
# Note the speed: typically 500M-160,000M H/s depending on hardware

# Step 3: Crack with rockyou wordlist
# rockyou.txt is the de facto standard breach wordlist (14 million passwords)
# Usually at: /usr/share/wordlists/rockyou.txt (Kali) or download from github

# Download if needed:
# wget -q https://github.com/praetorian-inc/Hob0Rules/raw/master/wordlists/rockyou.txt.gz
# gunzip rockyou.txt.gz

hashcat -m 0 /tmp/test-md5-hashes.txt /usr/share/wordlists/rockyou.txt --quiet
# Expected result: ALL 5 common passwords cracked in under 10 seconds
# This is what an attacker does immediately after stealing your database
```

```bash
# Step 4: Compare bcrypt speed
# First, create bcrypt hashes
python3 -c "
import bcrypt
passwords = ['password123', 'admin', 'letmein']
for p in passwords:
    h = bcrypt.hashpw(p.encode(), bcrypt.gensalt(rounds=12))
    print(h.decode())
" > /tmp/test-bcrypt-hashes.txt

# Benchmark bcrypt crack speed
hashcat -b -m 3200 --quiet
# Expected: ~30,000-100,000 H/s — 1 MILLION times slower than MD5

# Attempt crack (will take hours/days for same passwords)
hashcat -m 3200 /tmp/test-bcrypt-hashes.txt /usr/share/wordlists/rockyou.txt --quiet &
# Let it run for 30 seconds, then kill it
sleep 30; kill %1

hashcat -m 3200 /tmp/test-bcrypt-hashes.txt --show 2>/dev/null || echo "No passwords cracked yet"
# Expected: 0 passwords cracked in 30 seconds (vs all 5 MD5 in <10 seconds)
```

**Evidence to capture:**

```bash
EVIDENCE_DIR="/tmp/jsa-evidence/crypto-audit-$(date +%Y%m%d)"
mkdir -p "$EVIDENCE_DIR"

# Save MD5 crack results
hashcat -m 0 /tmp/test-md5-hashes.txt /usr/share/wordlists/rockyou.txt --quiet \
    --outfile "${EVIDENCE_DIR}/md5-cracked.txt" 2>/dev/null || true
cat "${EVIDENCE_DIR}/md5-cracked.txt"

# Save speed comparison
(hashcat -b -m 0 --quiet 2>&1 | grep "Speed\|Type") > "${EVIDENCE_DIR}/hashcat-speed-md5.txt"
(hashcat -b -m 3200 --quiet 2>&1 | grep "Speed\|Type") > "${EVIDENCE_DIR}/hashcat-speed-bcrypt.txt"

echo "MD5 speed:    $(cat "${EVIDENCE_DIR}/hashcat-speed-md5.txt" | grep Speed)"
echo "bcrypt speed: $(cat "${EVIDENCE_DIR}/hashcat-speed-bcrypt.txt" | grep Speed)"
echo ""
echo "CISO message: MD5 cracks at ~100 billion/second. bcrypt at ~60,000/second."
echo "That is a 1.6 million x speed difference. SC-13 violation = crackable in seconds."
```

---

## Part 4: Algorithm Classification

Use this reference when reviewing code findings:

| Algorithm | Type | Status | Use Case |
|---|---|---|---|
| MD5 | Hash | BROKEN | No new use. Replace: SHA-256+ or bcrypt for passwords |
| SHA-1 | Hash | DEPRECATED | No new use. Replace: SHA-256+ |
| SHA-256 | Hash | CURRENT | Data integrity, checksums, HMAC |
| SHA-3-256 | Hash | CURRENT | Preferred for high-security new designs |
| DES | Cipher | BROKEN | Replace: AES-256-GCM |
| 3DES | Cipher | DEPRECATED | Replace: AES-256-GCM (Sweet32 birthday attack) |
| AES-128-ECB | Cipher | WEAK | ECB mode leaks patterns. Replace: AES-256-GCM |
| AES-256-GCM | Cipher | CURRENT | Authenticated encryption — required for new designs |
| RC4 | Cipher | BROKEN | Replace: ChaCha20-Poly1305 or AES-256-GCM |
| RSA-1024 | Asymmetric | BROKEN | Replace: RSA-2048+ or ECDSA P-256+ |
| RSA-2048 | Asymmetric | CURRENT (until 2030) | Use for TLS, signing |
| ECDSA P-256 | Asymmetric | CURRENT | Preferred for TLS and signing |
| MD5crypt | Password | BROKEN | Replace: bcrypt or argon2id |
| SHA-1 (password) | Password | BROKEN | Replace: bcrypt or argon2id |
| bcrypt (rounds=10+) | Password | CURRENT | Password hashing |
| argon2id | Password | CURRENT/PREFERRED | Password hashing (OWASP #1) |
| PBKDF2-SHA256 (600k+) | Password | CURRENT | Password hashing (FIPS-approved) |

---

## Evidence Summary

After completing this playbook, document findings as:

```
SC-13 Finding Summary
Date: <date>
Assessor: <name>

Weak algorithm findings:
  Files with MD5: <count> (<list>)
  Files with SHA-1: <count>
  Configs with DES/3DES: <count>
  Configs with RC4: <count>

TLS findings:
  Services accepting TLS < 1.2: <count>
  Services accepting weak ciphers: <count>

Password hashing:
  MD5 passwords in DB: <count accounts>
  Bcrypt/argon2 passwords: <count accounts>

hashcat evidence:
  MD5 crack speed: <H/s>
  bcrypt crack speed: <H/s>
  Time to crack 'password123' (MD5): <time>
  Time to crack 'password123' (bcrypt rounds=12): <estimated>

Remediation: see 02a-fix-SC13-crypto.md
```
