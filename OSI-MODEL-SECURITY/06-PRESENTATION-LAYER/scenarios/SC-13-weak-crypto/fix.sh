#!/usr/bin/env bash
set -euo pipefail

# SC-13 Weak Cryptography — Fix
#
# Remediates weak cryptographic algorithms:
#   1. Migrates MD5 passwords to bcrypt (work factor 12)
#   2. Replaces SHA-1 integrity checks with SHA-256
#   3. Updates crypto config to FIPS 140-2 approved algorithms
#   4. Generates secure auth handler with secrets module
#   5. Documents cryptographic standards
#
# REQUIREMENTS:
#   - sqlite3
#   - python3
#   - sha256sum / shasum
#   - openssl (for verification)
#
# USAGE:
#   ./fix.sh [data_dir]
#
# EXAMPLE:
#   ./fix.sh /tmp/sc13-crypto-lab
#
# REFERENCES:
#   - NIST SP 800-53 SC-13: Cryptographic Protection
#   - NIST SP 800-131A Rev 2: Transitioning to Approved Algorithms
#   - FIPS 140-2: Security Requirements for Cryptographic Modules
#   - PCI-DSS Requirement 3.4: Render PAN unreadable

# --- Argument Validation ---

DATA_DIR="${1:-/tmp/sc13-crypto-lab}"

EVIDENCE_DIR="/tmp/sc13-weak-crypto-fix-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$EVIDENCE_DIR"
mkdir -p "$DATA_DIR"

echo "============================================"
echo "SC-13 Weak Cryptography — Fix"
echo "============================================"
echo ""
echo "[*] Data dir:     $DATA_DIR"
echo "[*] Evidence dir: $EVIDENCE_DIR"
echo ""

# --- Record Pre-Fix State ---

echo "[*] Recording pre-fix state..."
if [[ -f "$DATA_DIR/crypto.db" ]]; then
    cp "$DATA_DIR/crypto.db" "$EVIDENCE_DIR/crypto-db-before-fix.db"
    echo "[+] Saved database snapshot"
fi
if [[ -f "$DATA_DIR/crypto-config.yaml" ]]; then
    cp "$DATA_DIR/crypto-config.yaml" "$EVIDENCE_DIR/crypto-config-before-fix.yaml"
    echo "[+] Saved crypto config snapshot"
fi
if [[ -f "$DATA_DIR/auth_handler.py" ]]; then
    cp "$DATA_DIR/auth_handler.py" "$EVIDENCE_DIR/auth_handler-before-fix.py"
    echo "[+] Saved auth handler snapshot"
fi
echo ""

# --- Fix 1: Migrate MD5/SHA-1 Passwords to bcrypt ---

echo "[*] Fix 1: Migrating passwords from MD5/SHA-1 to bcrypt..."
echo "----------------------------------------------"

DB_PATH="$DATA_DIR/crypto.db"
export DB_PATH

if [[ -f "$DB_PATH" ]] && command -v python3 &>/dev/null; then
    python3 << 'PYEOF'
import sqlite3
import hashlib
import os
import base64

DB_PATH = os.environ.get("DB_PATH", "/tmp/sc13-crypto-lab/crypto.db")

# Known password list from break.sh (in real life, you'd force a password reset)
# This demonstrates the migration path — in production, you hash on next login
KNOWN_PASSWORDS = {
    "jsmith": "Welcome2024!", "mjones": "Password123", "admin": "admin",
    "bwilson": "Qwerty!2024", "alee": "Summer2024#", "dpark": "Letmein2024",
    "ctaylor": "Dragon2024!", "fgarcia": "Baseball24",
    "legacy_svc": "ServiceP@ss1", "batch_job": "Batch2024!Run",
}

try:
    import bcrypt
    USE_BCRYPT = True
    print("[+] Using bcrypt for password migration")
except ImportError:
    USE_BCRYPT = False
    print("[INFO] bcrypt not installed — using PBKDF2-SHA256 (stdlib)")
    print("[INFO] For production: pip install bcrypt==4.2.1")

conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

cursor.execute("SELECT id, username, password_hash, hash_algorithm FROM users")
rows = cursor.fetchall()

migrated = 0
for row_id, username, current_hash, algorithm in rows:
    # Skip already-migrated passwords
    if algorithm in ("bcrypt", "PBKDF2-SHA256"):
        print(f"  [SKIP] {username}: already using {algorithm}")
        continue

    # In production: re-hash on next login. For lab: use known passwords.
    password = KNOWN_PASSWORDS.get(username)
    if not password:
        print(f"  [WARN] {username}: no known password — mark for reset")
        continue

    # Verify current hash matches before migrating
    if algorithm == "MD5":
        verify = hashlib.md5(password.encode()).hexdigest() == current_hash
    elif algorithm == "SHA-1":
        verify = hashlib.sha1(password.encode()).hexdigest() == current_hash
    else:
        verify = False

    if not verify:
        print(f"  [WARN] {username}: hash verification failed — skip")
        continue

    # Hash with bcrypt or PBKDF2
    if USE_BCRYPT:
        new_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()
        new_algo = "bcrypt"
    else:
        salt = os.urandom(16)
        dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 600000)
        salt_b64 = base64.b64encode(salt).decode()
        dk_b64 = base64.b64encode(dk).decode()
        new_hash = f"pbkdf2:sha256:600000${salt_b64}${dk_b64}"
        new_algo = "PBKDF2-SHA256"

    cursor.execute(
        "UPDATE users SET password_hash = ?, hash_algorithm = ?, salt = 'embedded' WHERE id = ?",
        (new_hash, new_algo, row_id)
    )
    print(f"  [+] {username}: {algorithm} -> {new_algo}")
    migrated += 1

conn.commit()
conn.close()
print(f"\n[+] Migrated {migrated} passwords to strong hashing")
PYEOF

    echo "[+] Password migration complete"
    cp "$DB_PATH" "$EVIDENCE_DIR/crypto-db-fixed.db"
else
    echo "[INFO] Database or python3 not available — generating migration script"

    cat > "$EVIDENCE_DIR/password-migration.py" << 'MIGEOF'
#!/usr/bin/env python3
"""Migrate MD5/SHA-1 passwords to bcrypt on next login."""
import hashlib
try:
    import bcrypt
except ImportError:
    print("Install: pip install bcrypt==4.2.1")
    exit(1)

def migrate_on_login(username, plaintext_password, stored_hash, algorithm):
    """Call this during login — verify old hash, replace with bcrypt."""
    if algorithm == "MD5":
        valid = hashlib.md5(plaintext_password.encode()).hexdigest() == stored_hash
    elif algorithm == "SHA-1":
        valid = hashlib.sha1(plaintext_password.encode()).hexdigest() == stored_hash
    else:
        return None

    if valid:
        new_hash = bcrypt.hashpw(plaintext_password.encode(), bcrypt.gensalt(rounds=12))
        return new_hash.decode()
    return None
MIGEOF

    echo "[+] Migration script saved to $EVIDENCE_DIR/password-migration.py"
fi
echo ""

# --- Fix 2: Replace SHA-1 Integrity Checks with SHA-256 ---

echo "[*] Fix 2: Replacing SHA-1 integrity checksums with SHA-256..."
echo "----------------------------------------------"

if [[ -d "$DATA_DIR/protected-files" ]]; then
    CHECKSUM_FILE="$DATA_DIR/protected-files/checksums-sha256.txt"
    > "$CHECKSUM_FILE"

    for f in "$DATA_DIR/protected-files"/*.txt; do
        BASENAME=$(basename "$f")
        [[ "$BASENAME" == "checksums-sha1.txt" ]] && continue
        [[ "$BASENAME" == "checksums-sha256.txt" ]] && continue

        HASH=$(sha256sum "$f" 2>/dev/null | cut -d' ' -f1 || shasum -a 256 "$f" 2>/dev/null | cut -d' ' -f1)
        echo "$HASH  $BASENAME" >> "$CHECKSUM_FILE"
        echo "  [+] $BASENAME: SHA-256 = ${HASH:0:32}..."
    done

    # Remove old SHA-1 checksum file
    if [[ -f "$DATA_DIR/protected-files/checksums-sha1.txt" ]]; then
        mv "$DATA_DIR/protected-files/checksums-sha1.txt" \
           "$EVIDENCE_DIR/checksums-sha1-removed.txt"
        echo ""
        echo "[+] Removed SHA-1 checksum file"
    fi

    echo "[+] SHA-256 checksums written to $CHECKSUM_FILE"
    cp "$CHECKSUM_FILE" "$EVIDENCE_DIR/checksums-sha256-fixed.txt"
else
    echo "[INFO] No protected-files directory found"
fi
echo ""

# --- Fix 3: Update Crypto Configuration ---

echo "[*] Fix 3: Updating cryptographic configuration to FIPS 140-2 standards..."
echo "----------------------------------------------"

cat > "$DATA_DIR/crypto-config.yaml" << 'YAMLEOF'
# SC13-FIX: Application cryptographic configuration — FIPS 140-2 approved
# Applied by Anthra-SecLAB fix.sh
#
# References:
#   - NIST SP 800-53 SC-13: Cryptographic Protection
#   - NIST SP 800-131A Rev 2: Transitioning to Approved Algorithms
#   - FIPS 140-2: Security Requirements for Cryptographic Modules

cryptography:
  password_hashing:
    # FIX: bcrypt with work factor 12 (OWASP recommendation)
    # Alternative: Argon2id (m=65536, t=3, p=4) per OWASP 2024
    algorithm: "bcrypt"
    work_factor: 12
    # PBKDF2-SHA256 with 600,000 iterations as fallback (OWASP 2024)
    fallback_algorithm: "PBKDF2-SHA256"
    fallback_iterations: 600000

  file_integrity:
    # FIX: SHA-256 minimum for integrity verification
    algorithm: "SHA-256"
    verify_on_access: true
    alternatives:
      - "SHA-384"
      - "SHA-512"
      - "SHA3-256"

  data_encryption:
    # FIX: AES-256-GCM (authenticated encryption)
    algorithm: "AES-256"
    mode: "GCM"
    key_size: 256
    # GCM provides both confidentiality and integrity (AEAD)
    # Never use ECB mode — it leaks plaintext patterns

  tls:
    # FIX: TLS 1.2 minimum, prefer TLS 1.3
    min_version: "1.2"
    preferred_version: "1.3"
    cipher_suites:
      # TLS 1.3 cipher suites (no configuration needed — all are strong)
      - "TLS_AES_256_GCM_SHA384"
      - "TLS_AES_128_GCM_SHA256"
      - "TLS_CHACHA20_POLY1305_SHA256"
      # TLS 1.2 cipher suites (ECDHE only — forward secrecy required)
      - "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
      - "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
    # Explicitly disabled:
    disabled_ciphers:
      - "RC4"
      - "DES"
      - "3DES"
      - "MD5"
      - "SHA1 (for HMAC in cipher suites)"

  random:
    # FIX: Cryptographically secure PRNG
    source: "CSPRNG"
    implementation: "os.urandom / secrets module"
    # Python: import secrets; secrets.token_hex(32)
    # Linux: /dev/urandom
    # Windows: CryptGenRandom

  key_management:
    # Key rotation schedule
    symmetric_key_rotation: "90 days"
    asymmetric_key_rotation: "1 year"
    password_hash_upgrade: "on next login"
    # Key storage: never in code, config, or environment variables
    storage: "vault"
    vault_reference: "vault:secret/data/crypto/production"
YAMLEOF

echo "[+] Wrote FIPS 140-2 compliant crypto config"
cp "$DATA_DIR/crypto-config.yaml" "$EVIDENCE_DIR/crypto-config-fixed.yaml"
echo ""

# --- Fix 4: Generate Secure Auth Handler ---

echo "[*] Fix 4: Generating secure auth handler with proper cryptography..."
echo "----------------------------------------------"

cat > "$DATA_DIR/auth_handler.py" << 'PYEOF'
#!/usr/bin/env python3
"""SC13-FIX: Authentication handler with FIPS 140-2 approved cryptography.

Applied by Anthra-SecLAB fix.sh

References:
    - NIST SP 800-53 SC-13: Cryptographic Protection
    - OWASP Password Storage Cheat Sheet (2024)
    - Python secrets module (PEP 506)
"""

import hashlib
import hmac
import os
import secrets
import base64


def hash_password(password: str) -> str:
    """Hash password with PBKDF2-SHA256 (600,000 iterations).

    FIX: Replaces MD5 with OWASP-recommended PBKDF2-SHA256.
    In production, prefer bcrypt (work factor 12) or Argon2id.

    Args:
        password: The plaintext password to hash.

    Returns:
        Formatted hash string with embedded salt and iteration count.
    """
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 600000)
    salt_b64 = base64.b64encode(salt).decode('ascii')
    dk_b64 = base64.b64encode(dk).decode('ascii')
    return f"pbkdf2:sha256:600000${salt_b64}${dk_b64}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify password against stored hash using constant-time comparison.

    FIX: Uses hmac.compare_digest to prevent timing attacks.

    Args:
        password: The plaintext password to verify.
        stored_hash: The stored hash string from hash_password().

    Returns:
        True if password matches, False otherwise.
    """
    parts = stored_hash.split('$')
    if len(parts) != 3 or not parts[0].startswith('pbkdf2:'):
        return False

    header = parts[0]  # pbkdf2:sha256:600000
    salt_b64 = parts[1]
    stored_dk_b64 = parts[2]

    iterations = int(header.split(':')[2])
    salt = base64.b64decode(salt_b64)
    stored_dk = base64.b64decode(stored_dk_b64)

    computed_dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations)

    # FIX: Constant-time comparison prevents timing attacks
    return hmac.compare_digest(computed_dk, stored_dk)


def generate_reset_token() -> str:
    """Generate cryptographically secure password reset token.

    FIX: Uses secrets module (CSPRNG) instead of random module.
    secrets.token_urlsafe uses os.urandom internally.

    Returns:
        URL-safe base64-encoded 32-byte token (256 bits of entropy).
    """
    return secrets.token_urlsafe(32)


def generate_session_id() -> str:
    """Generate cryptographically secure session identifier.

    FIX: Uses secrets.token_hex (CSPRNG) instead of random with static seed.

    Returns:
        64-character hex string (256 bits of entropy).
    """
    return secrets.token_hex(32)


def check_file_integrity(filepath: str) -> str:
    """Compute SHA-256 hash for file integrity verification.

    FIX: Replaces SHA-1 with SHA-256 (FIPS 140-2 approved).

    Args:
        filepath: Path to the file to hash.

    Returns:
        Hex-encoded SHA-256 digest.
    """
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            sha256.update(chunk)
    return sha256.hexdigest()
PYEOF

echo "[+] Wrote secure auth_handler.py with FIPS 140-2 approved algorithms"
cp "$DATA_DIR/auth_handler.py" "$EVIDENCE_DIR/auth_handler-fixed.py"
echo ""

# --- Fix 5: Generate Crypto Standards Document ---

echo "[*] Fix 5: Generating cryptographic standards document..."
echo "----------------------------------------------"

cat > "$DATA_DIR/CRYPTO-STANDARDS.md" << 'MDEOF'
# Cryptographic Standards — Anthra-SecLAB

## Approved Algorithms (FIPS 140-2 / NIST SP 800-131A Rev 2)

| Purpose | Approved | Prohibited |
|---------|----------|------------|
| Password hashing | bcrypt (wf 12+), Argon2id, PBKDF2-SHA256 (600K iter) | MD5, SHA-1, SHA-256 (unsalted), plaintext |
| File integrity | SHA-256, SHA-384, SHA-512, SHA3-256 | MD5, SHA-1 |
| Symmetric encryption | AES-128/192/256 (GCM or CBC+HMAC) | DES, 3DES, RC4, Blowfish |
| Asymmetric encryption | RSA-2048+, ECDSA P-256+ | RSA-1024, DSA-1024 |
| Key exchange | ECDHE (P-256+), DH-2048+ | Static RSA, DH-1024 |
| TLS | TLS 1.2+ (prefer 1.3) | TLS 1.0, TLS 1.1, SSL |
| Random numbers | os.urandom, secrets module, /dev/urandom | math.random, srand, static seeds |

## Migration Priority

1. **Immediate:** Replace all MD5/SHA-1 password hashes with bcrypt
2. **Week 1:** Replace SHA-1 integrity checks with SHA-256
3. **Week 2:** Upgrade TLS to 1.2 minimum, remove weak cipher suites
4. **Month 1:** Implement key rotation schedule (90 days symmetric, 1 year asymmetric)

## Code Review Checklist

- [ ] No imports of `hashlib.md5` or `hashlib.sha1` for security purposes
- [ ] No `import random` for security tokens (use `import secrets`)
- [ ] No `random.seed()` with static values
- [ ] No DES, 3DES, RC4, or Blowfish usage
- [ ] No ECB mode encryption
- [ ] All password storage uses bcrypt, Argon2id, or PBKDF2-SHA256
- [ ] All TLS connections use TLS 1.2+
- [ ] All integrity checks use SHA-256+
MDEOF

echo "[+] Wrote CRYPTO-STANDARDS.md"
cp "$DATA_DIR/CRYPTO-STANDARDS.md" "$EVIDENCE_DIR/crypto-standards.md"
echo ""

echo "============================================"
echo "Fix Summary"
echo "============================================"
echo ""
echo "[+] Passwords:       MD5/SHA-1 -> PBKDF2-SHA256 (600K iterations)"
echo "[+] Integrity:       SHA-1 -> SHA-256 checksums"
echo "[+] Config:          Updated to FIPS 140-2 approved algorithms"
echo "[+] Auth handler:    Rewritten with secrets module, constant-time comparison"
echo "[+] TLS:             Minimum TLS 1.2, prefer TLS 1.3"
echo "[+] PRNG:            Static seed -> os.urandom / secrets module"
echo "[+] Standards doc:   Approved/prohibited algorithm reference created"
echo ""
echo "[*] Production notes:"
echo "    - Install bcrypt: pip install bcrypt==4.2.1"
echo "    - For Argon2id: pip install argon2-cffi==23.1.0"
echo "    - Key rotation: implement 90-day schedule for symmetric keys"
echo "    - Code review: add semgrep rules to block MD5/SHA-1 in CI"
echo ""
echo "[*] Run validate.sh to confirm the fix is effective."
echo "[*] Evidence saved to: $EVIDENCE_DIR"
