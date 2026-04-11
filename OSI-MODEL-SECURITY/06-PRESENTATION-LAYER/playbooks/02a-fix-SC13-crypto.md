# 02a-fix-SC13-crypto.md — Replace Weak Algorithms (SC-13)

| Field | Value |
|---|---|
| **NIST Controls** | SC-13 (cryptographic protection), IA-5(1) (authenticator management) |
| **Prerequisite** | `01b-crypto-standards-audit.md` completed — specific findings with file/line locations |
| **Scripts** | `02-fixers/fix-weak-hashing.md` (migration guide) |
| **Time** | 2–4 hours per service + migration window (phased rollout) |
| **Rank** | C (migration strategy needs human decision on rollout order and user impact) |

---

## Decision Required (C-Rank)

Before migrating, answer:
1. How many user accounts have MD5/SHA-1 hashes?
2. Can we use dual-hash migration (SC-13 compliant, zero downtime)?
3. What is the blast radius if the migration breaks auth?
4. Do any upstream systems (SSO, LDAP) depend on the hash format?

If answers are yes/low/acceptable/no: proceed. If uncertain: escalate to B-rank (architecture review).

---

## Fix 1: Migrate Password Hashing (Python)

**Full guide:** `02-fixers/fix-weak-hashing.md`

```python
# Quick reference — Python migration

# BEFORE (FAIL):
import hashlib
hashed = hashlib.md5(password.encode()).hexdigest()

# AFTER (PASS):
import bcrypt
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
```

**Migration strategy (zero-downtime):**

```python
# Phase 1: Dual-hash detection on login
# When a user with an MD5 hash logs in:
# 1. Verify MD5 (old)
# 2. Re-hash with bcrypt (new)
# 3. Update database
# 4. User is transparently migrated

def authenticate(username: str, password: str) -> bool:
    user = db.get_user(username)
    if not user:
        return False

    # Detect hash type by format
    if len(user.password_hash) == 32 and all(c in '0123456789abcdef' for c in user.password_hash):
        # Looks like MD5 (32 hex chars)
        if user.password_hash == hashlib.md5(password.encode()).hexdigest():
            # Valid — upgrade hash
            new_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
            db.update_password_hash(username, new_hash.decode())
            return True
        return False
    else:
        # Assume bcrypt
        return bcrypt.checkpw(password.encode(), user.password_hash.encode())
```

**Track migration progress:**

```sql
-- Add column to track
ALTER TABLE users ADD COLUMN hash_algorithm VARCHAR(20) DEFAULT 'unknown';

-- Identify MD5 hashes (32 hex chars)
UPDATE users
SET hash_algorithm = 'md5'
WHERE LENGTH(password_hash) = 32
AND password_hash REGEXP '^[a-f0-9]+$';

-- Identify bcrypt hashes (start with $2b$ or $2a$)
UPDATE users
SET hash_algorithm = 'bcrypt'
WHERE password_hash LIKE '$2b$%' OR password_hash LIKE '$2a$%';

-- Monitor progress
SELECT hash_algorithm, COUNT(*) as count,
       ROUND(COUNT(*) * 100.0 / SUM(COUNT(*)) OVER (), 1) as pct
FROM users
GROUP BY hash_algorithm;
```

---

## Fix 2: Harden TLS Configuration

### Nginx

```nginx
# /etc/nginx/ssl.conf (include in server blocks)
# WHY: SC-13 requires only NIST-approved algorithms in TLS.

ssl_protocols TLSv1.2 TLSv1.3;
# Remove: SSLv3, TLSv1, TLSv1.1 (all broken)

ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
# All ECDHE (forward secrecy), all GCM or ChaCha20 (AEAD)
# No: RC4, DES, 3DES, NULL, EXPORT, MD5, CAMELLIA, SEED

ssl_prefer_server_ciphers on;
# WHY: Server selects cipher — prevents client downgrade attack

ssl_session_cache shared:SSL:10m;
ssl_session_timeout 10m;
ssl_session_tickets off;
# WHY: Session ticket keys are vulnerable if not rotated. Off = each connection uses fresh keys.

ssl_stapling on;
ssl_stapling_verify on;
# WHY: OCSP stapling reduces latency and prevents certificate revocation bypass

add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;
# WHY: HSTS prevents downgrade to HTTP. 2-year max-age.

# Apply OpenSSL defaults
ssl_conf_command Options PrioritizeChaCha;
```

### Apache

```apache
# /etc/apache2/conf-available/ssl-hardening.conf
SSLProtocol -all +TLSv1.2 +TLSv1.3
SSLCipherSuite ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305
SSLHonorCipherOrder on
SSLSessionTickets off
SSLUseStapling on
SSLStaplingCache "shmcb:logs/ssl_stapling(32768)"
Header always set Strict-Transport-Security "max-age=63072000"
```

### K8s Ingress (nginx ingress controller)

```yaml
# Add to nginx-ingress ConfigMap (kube-system)
apiVersion: v1
kind: ConfigMap
metadata:
  name: nginx-configuration
  namespace: ingress-nginx
data:
  # WHY: SC-13 — remove broken protocols and ciphers from all ingress TLS
  ssl-protocols: "TLSv1.2 TLSv1.3"
  ssl-ciphers: "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305"
  ssl-prefer-server-ciphers: "true"
  ssl-session-tickets: "false"
  hsts: "true"
  hsts-max-age: "63072000"
  hsts-include-subdomains: "true"
```

---

## Fix 3: Remove MD5/SHA-1 from Non-Password Code

### Data integrity (file checksums)

```python
# BEFORE (FAIL — SC-13):
import hashlib
checksum = hashlib.md5(file_content).hexdigest()

# AFTER (PASS):
import hashlib
checksum = hashlib.sha256(file_content).hexdigest()
# Or for large files:
h = hashlib.sha256()
with open(filepath, 'rb') as f:
    for chunk in iter(lambda: f.read(65536), b''):
        h.update(chunk)
checksum = h.hexdigest()
```

### HMAC (message authentication)

```python
# BEFORE (FAIL):
import hmac, hashlib
mac = hmac.new(key, message, hashlib.md5).hexdigest()

# AFTER (PASS):
import hmac, hashlib
mac = hmac.new(key, message, hashlib.sha256).hexdigest()
```

### JWT signing (if using HS256 with HMAC)

```python
# HS256 uses HMAC-SHA256 — this is acceptable
# HS1 (HMAC-SHA1) is NOT acceptable — check jwt library config

# python-jose example:
from jose import jwt
# PASS: algorithm="HS256" or "RS256" or "ES256"
# FAIL: algorithm="HS1" or "RS1"
token = jwt.encode(payload, key, algorithm="HS256")
```

---

## Fix 4: OpenSSL System Configuration

Deploy the hardened OpenSSL config to enforce strong defaults system-wide:

```bash
# Test it first
OPENSSL_CONF=./03-templates/openssl/strong-defaults.cnf \
    openssl s_client -connect your-service:443 -brief
# Verify TLSv1.2 or TLSv1.3

# Deploy system-wide (Linux)
sudo cp ./03-templates/openssl/strong-defaults.cnf /etc/ssl/openssl.cnf
# NOTE: Test all services after this change — it may break legacy clients

# Or apply per-service (safer):
# In service startup: export OPENSSL_CONF=/etc/ssl/openssl-hardened.cnf
```

---

## Verification

```bash
# Re-run crypto standards auditor
./01-auditors/audit-crypto-standards.sh --dir $(pwd) --tls-host your-service:443

# Evidence comparison:
# Before: /tmp/jsa-evidence/crypto-standards-<before-timestamp>/
# After:  /tmp/jsa-evidence/crypto-standards-<after-timestamp>/
# diff the summary.txt files

# Confirm password hash migration progress
psql -h localhost -U postgres -c "
SELECT hash_algorithm, COUNT(*) as count
FROM users
GROUP BY hash_algorithm;
"
# Target: 0 rows with hash_algorithm = 'md5'
```

Move to `03-validate.md` when all auditors pass.
