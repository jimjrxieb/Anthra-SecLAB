#!/usr/bin/env bash
set -euo pipefail

# SC-13 Weak Cryptography — Break
#
# Creates a SQLite database with MD5-hashed passwords, uses SHA-1 for file
# integrity checks, and configures weak cryptographic defaults. This simulates
# production systems using deprecated algorithms that can be cracked in seconds
# with commodity hardware.
#
# REQUIREMENTS:
#   - sqlite3
#   - md5sum / sha1sum
#   - python3 (for hash generation)
#
# USAGE:
#   ./break.sh [data_dir]
#
# EXAMPLE:
#   ./break.sh /tmp/sc13-crypto-lab
#   ./break.sh ./test-data
#
# WARNING: This script is for authorized security testing only.
#          Unauthorized use is illegal under the CFAA and equivalent laws.

# --- Argument Validation ---

DATA_DIR="${1:-/tmp/sc13-crypto-lab}"

EVIDENCE_DIR="/tmp/sc13-weak-crypto-evidence-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$EVIDENCE_DIR"
mkdir -p "$DATA_DIR"

echo "============================================"
echo "SC-13 Weak Cryptography — Break"
echo "============================================"
echo ""
echo "[*] Data dir:     $DATA_DIR"
echo "[*] Evidence dir: $EVIDENCE_DIR"
echo ""

# --- Record Pre-Break State ---

echo "[*] Recording pre-break state..."
if [[ -f "$DATA_DIR/crypto.db" ]]; then
    cp "$DATA_DIR/crypto.db" "$EVIDENCE_DIR/crypto-db-before.db"
    echo "[+] Backed up existing database"
fi
echo ""

# --- Create Database with MD5-Hashed Passwords ---

echo "[*] Creating database with MD5-hashed passwords..."

if command -v sqlite3 &>/dev/null && command -v python3 &>/dev/null; then
    DB_PATH="$DATA_DIR/crypto.db"
    export DB_PATH

    # Generate MD5 hashes using python3 (md5sum syntax varies by platform)
    python3 << 'PYEOF'
import hashlib
import sqlite3
import os

DB_PATH = os.environ.get("DB_PATH", "/tmp/sc13-crypto-lab/crypto.db")

conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

cursor.execute("DROP TABLE IF EXISTS users")
cursor.execute("""
    CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        hash_algorithm TEXT NOT NULL,
        salt TEXT,
        created_at TEXT DEFAULT (datetime('now'))
    )
""")

# VULNERABILITY: Passwords hashed with MD5 — no salt
# MD5 produces 128-bit hashes, is collision-broken since 2004 (Wang et al),
# and can be brute-forced at 150 billion hashes/sec on modern GPUs
users = [
    ("jsmith", "Welcome2024!"),
    ("mjones", "Password123"),
    ("admin", "admin"),
    ("bwilson", "Qwerty!2024"),
    ("alee", "Summer2024#"),
    ("dpark", "Letmein2024"),
    ("ctaylor", "Dragon2024!"),
    ("fgarcia", "Baseball24"),
]

for username, password in users:
    md5_hash = hashlib.md5(password.encode()).hexdigest()
    cursor.execute(
        "INSERT INTO users (username, password_hash, hash_algorithm, salt) VALUES (?, ?, ?, ?)",
        (username, md5_hash, "MD5", None)
    )
    print(f"  [+] {username}: MD5({password}) = {md5_hash}")

# Also create some SHA-1 hashed passwords (deprecated but common)
sha1_users = [
    ("legacy_svc", "ServiceP@ss1"),
    ("batch_job", "Batch2024!Run"),
]

for username, password in sha1_users:
    sha1_hash = hashlib.sha1(password.encode()).hexdigest()
    cursor.execute(
        "INSERT INTO users (username, password_hash, hash_algorithm, salt) VALUES (?, ?, ?, ?)",
        (username, sha1_hash, "SHA-1", None)
    )
    print(f"  [+] {username}: SHA1({password}) = {sha1_hash}")

conn.commit()
conn.close()
print(f"\n[+] Created {len(users) + len(sha1_users)} users with weak hashes")
PYEOF

    echo "[+] Created database at $DB_PATH"
    cp "$DB_PATH" "$EVIDENCE_DIR/crypto-db-weak.db"
else
    echo "[WARN] sqlite3 or python3 not available"
    echo "[INFO] Creating hash file for manual demonstration"

    python3 -c "
import hashlib
passwords = {'jsmith':'Welcome2024!','mjones':'Password123','admin':'admin','bwilson':'Qwerty!2024','alee':'Summer2024#'}
for user, pw in passwords.items():
    md5 = hashlib.md5(pw.encode()).hexdigest()
    print(f'{user}:{md5}')
" > "$DATA_DIR/md5-hashes.txt" 2>/dev/null || echo "[WARN] Cannot generate hashes"
fi
echo ""

# --- Create SHA-1 File Integrity Checks ---

echo "[*] Creating SHA-1 file integrity checks (deprecated algorithm)..."

# Create sample files to protect
mkdir -p "$DATA_DIR/protected-files"

echo "Confidential financial report Q4 2025" > "$DATA_DIR/protected-files/financial-report.txt"
echo "Employee salary data — restricted access" > "$DATA_DIR/protected-files/salary-data.txt"
echo "Customer PII export — do not distribute" > "$DATA_DIR/protected-files/customer-export.txt"

# VULNERABILITY: Using SHA-1 for integrity verification
# SHA-1 has been collision-broken since 2017 (SHAttered attack by Google/CWI)
# Cost to generate a SHA-1 collision: ~$45,000 (down from theoretical in 2005)
echo "[*] Generating SHA-1 integrity checksums (VULNERABLE)..."

CHECKSUM_FILE="$DATA_DIR/protected-files/checksums-sha1.txt"
> "$CHECKSUM_FILE"

for f in "$DATA_DIR/protected-files"/*.txt; do
    [[ "$(basename "$f")" == "checksums-sha1.txt" ]] && continue
    HASH=$(sha1sum "$f" 2>/dev/null | cut -d' ' -f1 || shasum "$f" 2>/dev/null | cut -d' ' -f1)
    echo "$HASH  $(basename "$f")" >> "$CHECKSUM_FILE"
    echo "  [+] $(basename "$f"): SHA-1 = $HASH"
done

echo "[+] SHA-1 checksums written to $CHECKSUM_FILE"
cp "$CHECKSUM_FILE" "$EVIDENCE_DIR/checksums-sha1.txt"
echo ""

# --- Create Weak Crypto Configuration ---

echo "[*] Creating application config with weak cryptographic settings..."

cat > "$DATA_DIR/crypto-config.yaml" << 'YAMLEOF'
# SC13-BREAK: Application cryptographic configuration — INSECURE
# DO NOT use in production — for security testing only

cryptography:
  password_hashing:
    # VULNERABILITY: MD5 is collision-broken (Wang et al, 2004)
    # MD5 cracking speed: 150 billion hashes/sec on RTX 4090
    algorithm: "MD5"
    salt: false
    iterations: 1

  file_integrity:
    # VULNERABILITY: SHA-1 is collision-broken (SHAttered, 2017)
    # SHA-1 collision cost: ~$45,000 (Stevens et al, 2020)
    algorithm: "SHA-1"
    verify_on_access: false

  data_encryption:
    # VULNERABILITY: DES is 56-bit — crackable in hours
    algorithm: "DES"
    mode: "ECB"
    key_size: 56
    # VULNERABILITY: ECB mode leaks patterns in ciphertext

  tls:
    # VULNERABILITY: TLS 1.0 and weak cipher suites
    min_version: "1.0"
    cipher_suites:
      - "TLS_RSA_WITH_RC4_128_SHA"
      - "TLS_RSA_WITH_DES_CBC_SHA"
      - "TLS_RSA_WITH_3DES_EDE_CBC_SHA"

  random:
    # VULNERABILITY: Using math.random/srand for security tokens
    source: "pseudo-random"
    seed: "static-seed-2024"
YAMLEOF

echo "[+] Wrote weak crypto config to $DATA_DIR/crypto-config.yaml"
cp "$DATA_DIR/crypto-config.yaml" "$EVIDENCE_DIR/crypto-config-weak.yaml"
echo ""

# --- Create Sample Code with Weak Crypto ---

echo "[*] Creating sample code with weak cryptographic patterns..."

cat > "$DATA_DIR/auth_handler.py" << 'PYEOF'
#!/usr/bin/env python3
"""SC13-BREAK: Authentication handler with weak cryptography."""
# DO NOT use in production — for security testing only

import hashlib
import random
import string

def hash_password(password):
    """VULNERABILITY: MD5 with no salt."""
    return hashlib.md5(password.encode()).hexdigest()

def verify_password(password, stored_hash):
    """VULNERABILITY: MD5 comparison — timing attack vulnerable."""
    return hashlib.md5(password.encode()).hexdigest() == stored_hash

def generate_reset_token():
    """VULNERABILITY: Using random (not secrets) for security token."""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=32))

def generate_session_id():
    """VULNERABILITY: Predictable PRNG seeded with static value."""
    random.seed(42)
    return ''.join(random.choices(string.hexdigits, k=32))

def check_file_integrity(filepath):
    """VULNERABILITY: SHA-1 for integrity verification."""
    with open(filepath, 'rb') as f:
        return hashlib.sha1(f.read()).hexdigest()
PYEOF

echo "[+] Wrote vulnerable auth_handler.py to $DATA_DIR/"
cp "$DATA_DIR/auth_handler.py" "$EVIDENCE_DIR/auth_handler-weak.py"
echo ""

echo "============================================"
echo "Break Summary"
echo "============================================"
echo ""
echo "[!] Cryptographic protections are now WEAK:"
echo "[!]   - Password hashing: MD5 (crackable at 150B hashes/sec)"
echo "[!]   - Password salting: DISABLED"
echo "[!]   - File integrity: SHA-1 (collision-broken since 2017)"
echo "[!]   - Data encryption: DES/ECB (56-bit, pattern-leaking)"
echo "[!]   - TLS minimum: 1.0 (deprecated, POODLE/BEAST vulnerable)"
echo "[!]   - Random source: PRNG with static seed (predictable)"
echo ""
echo "[*] This configuration is vulnerable to:"
echo "    - Password cracking: MD5 hashes cracked in seconds (hashcat)"
echo "    - Collision attacks: SHA-1 collisions for \$45K (integrity bypass)"
echo "    - Brute force: DES 56-bit key space exhausted in hours"
echo "    - Pattern analysis: ECB mode reveals plaintext patterns"
echo "    - Downgrade attacks: TLS 1.0 enables POODLE/BEAST/CRIME"
echo "    - Token prediction: Static PRNG seed enables session forgery"
echo ""
echo "[*] Wang et al (2004): First MD5 collision — broke the algorithm"
echo "[*] LinkedIn (2012): 6.5M SHA-1 passwords cracked within days"
echo "[*] SHAttered (2017): First SHA-1 collision — \$110K computation"
echo ""
echo "[*] Run detect.sh to crack the hashes, then fix.sh to remediate."
echo "[*] Evidence saved to: $EVIDENCE_DIR"
