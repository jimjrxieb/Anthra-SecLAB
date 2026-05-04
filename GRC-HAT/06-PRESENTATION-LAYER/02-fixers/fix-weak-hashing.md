# fix-weak-hashing.md — Migrate from MD5/SHA-1 to Modern Algorithms

| Field | Value |
|---|---|
| **NIST Controls** | SC-13 (cryptographic protection), IA-5 (authenticator management) |
| **Severity** | FAIL — MD5/SHA-1 are cryptographically broken |
| **Risk** | Password cracking, data integrity bypass, collision attacks |
| **Fix Time** | 2–4 hours per service (+ migration window) |

---

## Why This Matters

MD5 and SHA-1 are **cryptographically broken**. They are not slow (bad for passwords) and they have known collision attacks (bad for data integrity).

**MD5 crack speed on a consumer GPU (RTX 4090):** ~164 billion hashes/second.
A 6-character lowercase password is cracked in under 1 second. An 8-character password in under 3 minutes.

**NIST position:** MD5 and SHA-1 are disallowed for all new applications under NIST SP 800-131A. Federal systems cannot use them at all.

---

## Detection: Find MD5/SHA-1 Usage

```bash
# Python
grep -rn "hashlib\.md5\|hashlib\.sha1\|hashlib\.sha" --include="*.py" .

# JavaScript/TypeScript
grep -rn "createHash.*['\"]md5\|createHash.*['\"]sha1" --include="*.{js,ts}" .

# Go
grep -rn "crypto/md5\|crypto/sha1" --include="*.go" .

# Java
grep -rn "MessageDigest\.getInstance.*['\"]MD5\|MessageDigest\.getInstance.*['\"]SHA-1" --include="*.java" .

# Config files
grep -rn "MD5\|SHA-1\|sha1\|md5" --include="*.{conf,cfg,yaml,yml,ini,properties}" .

# All at once (output: file:line:match)
grep -rn -E "md5|sha[-_]?1\b" \
  --include="*.{py,js,ts,go,java,rb,php,conf,cfg,yaml,yml}" \
  --exclude-dir={.git,node_modules,__pycache__,vendor} \
  . 2>/dev/null
```

---

## Python: Migrate from MD5 to bcrypt

**Use case:** Password hashing only. Use bcrypt/argon2 — never SHA-256 for passwords.

```python
# BEFORE (FAIL — SC-13 violation):
import hashlib
hashed = hashlib.md5(password.encode()).hexdigest()
# 164 billion attempts/second on a GPU. This is not a hash, it's a lookup.

# AFTER (PASS — bcrypt with salt):
import bcrypt
# Hash a new password
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
# rounds=12 means 2^12 = 4096 iterations. ~100ms per hash on modern hardware.

# Verify
is_valid = bcrypt.checkpw(password.encode(), hashed)

# Install: pip install bcrypt==4.2.0
```

**Use case:** Data integrity (not passwords). Use SHA-256 or SHA-3.

```python
# BEFORE (FAIL):
import hashlib
checksum = hashlib.md5(data).hexdigest()

# AFTER (PASS — SHA-256 for data integrity):
import hashlib
checksum = hashlib.sha256(data).hexdigest()

# Or SHA-3 for highest security:
checksum = hashlib.sha3_256(data).hexdigest()
```

**Use case:** HMAC (message authentication). Use SHA-256.

```python
# BEFORE (FAIL):
import hmac, hashlib
mac = hmac.new(key, message, hashlib.md5).hexdigest()

# AFTER (PASS):
import hmac, hashlib
mac = hmac.new(key, message, hashlib.sha256).hexdigest()
```

---

## Go: Migrate from crypto/md5 to bcrypt

```go
// BEFORE (FAIL — SC-13 violation):
import "crypto/md5"
hash := md5.Sum([]byte(password))
hashedStr := fmt.Sprintf("%x", hash)

// AFTER (PASS — bcrypt):
import "golang.org/x/crypto/bcrypt"

// Hash
cost := 12 // 2^12 iterations
hash, err := bcrypt.GenerateFromPassword([]byte(password), cost)
if err != nil {
    return err
}

// Verify
err = bcrypt.CompareHashAndPassword(hash, []byte(password))
isValid := (err == nil)

// go get golang.org/x/crypto@v0.21.0
```

**For data integrity in Go (not passwords):**

```go
// BEFORE (FAIL):
import "crypto/md5"
sum := md5.Sum(data)

// AFTER (PASS):
import "crypto/sha256"
sum := sha256.Sum256(data)
// Or sha512: sha512.Sum512(data)
```

---

## Node.js: Migrate from MD5 to argon2

```javascript
// BEFORE (FAIL — SC-13 violation):
const crypto = require('crypto');
const hashed = crypto.createHash('md5').update(password).digest('hex');

// AFTER (PASS — argon2id for passwords):
const argon2 = require('argon2');

// Hash (async)
const hash = await argon2.hash(password, {
    type: argon2.argon2id,  // WHY: argon2id resists both GPU and side-channel attacks
    memoryCost: 65536,       // 64MB memory (makes GPU attacks expensive)
    timeCost: 3,             // 3 iterations
    parallelism: 4,
});

// Verify
const isValid = await argon2.verify(hash, password);

// npm install argon2@0.31.2
```

**For data integrity in Node.js (not passwords):**

```javascript
// BEFORE (FAIL):
crypto.createHash('md5').update(data).digest('hex')

// AFTER (PASS):
crypto.createHash('sha256').update(data).digest('hex')
// Or: crypto.createHash('sha512').update(data).digest('hex')
```

---

## Database Migration Strategy

Never do a hard cutover. Users with old hashes get locked out. Use dual-hash migration.

### Phase 1: Detect old hash format on login

```python
def login(username: str, password: str) -> bool:
    user = get_user(username)
    if not user:
        return False

    # Detect old MD5 hash (32 hex chars)
    if is_md5_hash(user.password_hash):
        # Verify against old MD5
        old_hash = hashlib.md5(password.encode()).hexdigest()
        if old_hash == user.password_hash:
            # Re-hash with bcrypt and update record
            new_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
            update_user_hash(username, new_hash)
            return True
        return False
    else:
        # Verify against bcrypt
        return bcrypt.checkpw(password.encode(), user.password_hash)

def is_md5_hash(h: str) -> bool:
    """MD5 hashes are exactly 32 hex characters."""
    import re
    return bool(re.match(r'^[a-f0-9]{32}$', h))
```

### Phase 2: Track migration progress

```sql
-- Add migration column
ALTER TABLE users ADD COLUMN hash_algorithm VARCHAR(20) DEFAULT 'md5';

-- After re-hashing on login
UPDATE users SET hash_algorithm = 'bcrypt' WHERE password_hash LIKE '$2b$%';

-- Monitor progress
SELECT hash_algorithm, COUNT(*) FROM users GROUP BY hash_algorithm;
-- Target: 0 rows with hash_algorithm = 'md5'
```

### Phase 3: Force migration for inactive accounts

```python
# For users who haven't logged in during migration window
# Option 1: Invalidate MD5 hashes (force password reset)
def invalidate_old_hashes():
    old_users = db.query("SELECT id FROM users WHERE hash_algorithm = 'md5'")
    for user in old_users:
        db.update("UPDATE users SET force_password_reset = TRUE WHERE id = ?", user.id)
        send_password_reset_email(user)

# Option 2: Set a deadline and delete unrotated hashes after N days
```

### Phase 4: Enforce new algorithm (remove MD5 code path)

Once migration is complete:
1. Remove the `is_md5_hash` detection branch
2. Remove `hashlib.md5` import entirely
3. Add a linter rule or Semgrep policy to prevent re-introduction

---

## Algorithm Selection Guide

| Use Case | Recommended | Avoid |
|---|---|---|
| Password storage | bcrypt (rounds=12+), argon2id, scrypt | MD5, SHA-1, SHA-256 (too fast) |
| Data integrity / checksums | SHA-256, SHA-3-256 | MD5, SHA-1 |
| HMAC (message auth) | HMAC-SHA-256, HMAC-SHA-512 | HMAC-MD5, HMAC-SHA1 |
| Digital signatures | RSA-2048+/SHA-256, ECDSA/P-256 | RSA-1024, MD5withRSA |
| Key derivation | PBKDF2-SHA256 (600k iter), scrypt, argon2 | MD5, SHA-1 |
| TLS cipher | AES-128-GCM, AES-256-GCM, ChaCha20 | RC4, DES, 3DES |

---

## Semgrep Rule: Prevent MD5 Re-introduction

```yaml
# .semgrep/no-weak-crypto.yaml
rules:
  - id: python-no-md5
    pattern: hashlib.md5(...)
    message: "SC-13 violation: hashlib.md5 is cryptographically broken. Use hashlib.sha256 for data integrity or bcrypt for passwords."
    severity: ERROR
    languages: [python]

  - id: python-no-sha1
    pattern: hashlib.sha1(...)
    message: "SC-13 violation: hashlib.sha1 is broken. Use hashlib.sha256."
    severity: ERROR
    languages: [python]
```

Run: `semgrep --config .semgrep/no-weak-crypto.yaml .`
