#!/usr/bin/env bash
set -euo pipefail

# SC-13 Weak Cryptography — Detect
#
# Detects weak cryptographic algorithms using:
#   1. Hash cracking — demonstrates MD5 weakness with hashcat or python
#   2. Algorithm audit — scans code/config for MD5, SHA-1, DES, RC4
#   3. Integrity check audit — verifies checksum algorithms
#   4. PRNG audit — checks for insecure random sources
#
# REQUIREMENTS:
#   - python3 (for hash cracking demonstration)
#   - hashcat (optional — for GPU-accelerated cracking)
#   - grep (for code scanning)
#
# USAGE:
#   ./detect.sh [data_dir]
#
# EXAMPLE:
#   ./detect.sh /tmp/sc13-crypto-lab
#   ./detect.sh ./test-data

# --- Argument Validation ---

DATA_DIR="${1:-/tmp/sc13-crypto-lab}"

EVIDENCE_DIR="/tmp/sc13-weak-crypto-detect-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$EVIDENCE_DIR"

echo "============================================"
echo "SC-13 Weak Cryptography — Detection"
echo "============================================"
echo ""
echo "[*] Data dir:     $DATA_DIR"
echo "[*] Evidence dir: $EVIDENCE_DIR"
echo ""

FINDINGS=0

# --- Method 1: MD5 Hash Cracking Demonstration ---

echo "[*] Method 1: MD5 hash cracking (demonstrates weakness)"
echo "----------------------------------------------"

DB_PATH="$DATA_DIR/crypto.db"

if [[ -f "$DB_PATH" ]] && command -v python3 &>/dev/null; then
    export DB_PATH
    echo "[*] Extracting MD5 hashes from database..."

    # Extract hashes
    sqlite3 "$DB_PATH" "SELECT username, password_hash FROM users WHERE hash_algorithm='MD5';" \
        > "$EVIDENCE_DIR/md5-hashes-extracted.txt" 2>/dev/null || true

    # Attempt cracking with hashcat if available
    if command -v hashcat &>/dev/null; then
        echo "[*] hashcat detected — attempting GPU-accelerated crack..."

        # Prepare hashcat format (hash:username)
        sqlite3 "$DB_PATH" "SELECT password_hash FROM users WHERE hash_algorithm='MD5';" 2>/dev/null \
            > "$EVIDENCE_DIR/hashes-for-hashcat.txt"

        # Common password wordlist check
        if [[ -f /usr/share/wordlists/rockyou.txt ]]; then
            WORDLIST="/usr/share/wordlists/rockyou.txt"
        elif [[ -f /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt ]]; then
            WORDLIST="/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt"
        else
            WORDLIST=""
        fi

        if [[ -n "$WORDLIST" ]]; then
            echo "[*] Using wordlist: $WORDLIST"
            # hashcat mode 0 = MD5
            timeout 30 hashcat -m 0 -a 0 "$EVIDENCE_DIR/hashes-for-hashcat.txt" "$WORDLIST" \
                --force --quiet -o "$EVIDENCE_DIR/cracked-hashcat.txt" 2>/dev/null || true

            if [[ -f "$EVIDENCE_DIR/cracked-hashcat.txt" ]]; then
                CRACKED=$(wc -l < "$EVIDENCE_DIR/cracked-hashcat.txt")
                echo "[ALERT] hashcat cracked $CRACKED password(s)"
                cat "$EVIDENCE_DIR/cracked-hashcat.txt"
            fi
        else
            echo "[INFO] No wordlist found — using dictionary attack with common passwords"
        fi
    else
        echo "[INFO] hashcat not installed — using Python dictionary attack"
    fi

    # Python-based cracking (always runs — demonstrates the point without hashcat)
    echo ""
    echo "[*] Running Python dictionary attack against MD5 hashes..."

    python3 << 'PYEOF'
import hashlib
import sqlite3
import time
import os

DB_PATH = os.environ.get("DB_PATH", "/tmp/sc13-crypto-lab/crypto.db")

# Common passwords — not a full wordlist, just enough to demonstrate the risk
COMMON_PASSWORDS = [
    "admin", "password", "Password123", "Welcome2024!", "Qwerty!2024",
    "Summer2024#", "Letmein2024", "Dragon2024!", "Baseball24",
    "123456", "letmein", "welcome", "monkey", "dragon",
    "master", "qwerty", "login", "abc123", "football",
    "shadow", "michael", "password1", "iloveyou", "trustno1",
    "ServiceP@ss1", "Batch2024!Run",
]

conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

# Crack MD5 hashes
cursor.execute("SELECT username, password_hash FROM users WHERE hash_algorithm='MD5'")
md5_users = cursor.fetchall()

print(f"[*] Attempting to crack {len(md5_users)} MD5 hashes...")
print(f"[*] Dictionary size: {len(COMMON_PASSWORDS)} common passwords")
print()

start = time.time()
cracked = 0

for username, stored_hash in md5_users:
    for candidate in COMMON_PASSWORDS:
        if hashlib.md5(candidate.encode()).hexdigest() == stored_hash:
            elapsed = time.time() - start
            print(f"  [CRACKED] {username}: {stored_hash} -> '{candidate}' ({elapsed:.3f}s)")
            cracked += 1
            break
    else:
        print(f"  [INTACT]  {username}: {stored_hash} (not in dictionary)")

elapsed = time.time() - start
print(f"\n[*] Cracked {cracked}/{len(md5_users)} MD5 hashes in {elapsed:.3f} seconds")
print(f"[*] Speed: {len(md5_users) * len(COMMON_PASSWORDS) / elapsed:.0f} hash comparisons/sec (Python)")
print(f"[*] hashcat on RTX 4090: ~150,000,000,000 MD5 hashes/sec")
print(f"[*] At GPU speed, the entire 10-char keyspace falls in hours")

# Also crack SHA-1 hashes
cursor.execute("SELECT username, password_hash FROM users WHERE hash_algorithm='SHA-1'")
sha1_users = cursor.fetchall()

if sha1_users:
    print(f"\n[*] Attempting to crack {len(sha1_users)} SHA-1 hashes...")
    for username, stored_hash in sha1_users:
        for candidate in COMMON_PASSWORDS:
            if hashlib.sha1(candidate.encode()).hexdigest() == stored_hash:
                print(f"  [CRACKED] {username}: {stored_hash[:20]}... -> '{candidate}'")
                cracked += 1
                break
        else:
            print(f"  [INTACT]  {username}: {stored_hash[:20]}... (not in dictionary)")

conn.close()
print(f"\n[ALERT] Total cracked: {cracked} passwords")
PYEOF

    CRACK_COUNT=$(python3 -c "
import hashlib, sqlite3, os
DB = os.environ.get('DB_PATH','/tmp/sc13-crypto-lab/crypto.db')
DICT = ['admin','password','Password123','Welcome2024!','Qwerty!2024','Summer2024#','Letmein2024','Dragon2024!','Baseball24','ServiceP@ss1','Batch2024!Run','123456','letmein']
conn = sqlite3.connect(DB)
c = conn.cursor()
c.execute('SELECT username, password_hash, hash_algorithm FROM users')
cracked = 0
for u, h, alg in c.fetchall():
    for pw in DICT:
        if alg == 'MD5' and hashlib.md5(pw.encode()).hexdigest() == h:
            cracked += 1; break
        elif alg == 'SHA-1' and hashlib.sha1(pw.encode()).hexdigest() == h:
            cracked += 1; break
conn.close()
print(cracked)
" 2>/dev/null || echo "0")

    echo ""
    echo "[ALERT] $CRACK_COUNT password(s) cracked with a small dictionary"
    FINDINGS=$((FINDINGS + CRACK_COUNT))
else
    echo "[INFO] Database not found or required tools missing"
fi
echo ""

# --- Method 2: Algorithm Audit (Code and Config) ---

echo "[*] Method 2: Weak algorithm audit (code and config files)"
echo "----------------------------------------------"

ALGO_FINDINGS=0

# Patterns indicating weak cryptography
declare -A WEAK_PATTERNS
WEAK_PATTERNS=(
    ["hashlib.md5"]="MD5 hash function (collision-broken 2004)"
    ["hashlib.sha1"]="SHA-1 hash function (collision-broken 2017)"
    ["MD5("]="MD5 function call"
    ["SHA1("]="SHA-1 function call"
    ["random.seed"]="Predictable PRNG seeding"
    ["random.choices"]="Non-cryptographic PRNG for tokens"
    ["random.randint"]="Non-cryptographic PRNG"
    ["DES"]="DES encryption (56-bit — crackable)"
    ["ECB"]="ECB mode (leaks patterns)"
    ["RC4"]="RC4 stream cipher (broken)"
    ["TLS.*1\\.0"]="TLS 1.0 (deprecated)"
)

# Scan Python files
for f in "$DATA_DIR"/*.py "$DATA_DIR"/*.yaml "$DATA_DIR"/*.yml "$DATA_DIR"/*.json 2>/dev/null; do
    [[ -f "$f" ]] || continue
    FILENAME=$(basename "$f")

    for pattern in "${!WEAK_PATTERNS[@]}"; do
        MATCHES=$(grep -n "$pattern" "$f" 2>/dev/null || true)
        if [[ -n "$MATCHES" ]]; then
            DESCRIPTION="${WEAK_PATTERNS[$pattern]}"
            echo "  [ALERT] $FILENAME: $DESCRIPTION"
            echo "    $MATCHES" | head -3
            ALGO_FINDINGS=$((ALGO_FINDINGS + 1))
        fi
    done
done

if [[ "$ALGO_FINDINGS" -gt 0 ]]; then
    echo ""
    echo "[ALERT] Found $ALGO_FINDINGS weak cryptographic patterns in code/config"
    FINDINGS=$((FINDINGS + ALGO_FINDINGS))
else
    echo "  [OK] No weak cryptographic patterns detected"
fi
echo ""

# --- Method 3: Integrity Checksum Audit ---

echo "[*] Method 3: File integrity checksum algorithm audit"
echo "----------------------------------------------"

CHECKSUM_FILE="$DATA_DIR/protected-files/checksums-sha1.txt"

if [[ -f "$CHECKSUM_FILE" ]]; then
    # Check the hash length to determine algorithm
    FIRST_HASH=$(head -1 "$CHECKSUM_FILE" | cut -d' ' -f1)
    HASH_LEN=${#FIRST_HASH}

    if [[ "$HASH_LEN" -eq 40 ]]; then
        echo "  [ALERT] Integrity checksums use SHA-1 (40-character hash)"
        echo "  [ALERT] SHA-1 collisions demonstrated by Google/CWI in 2017 (SHAttered)"
        echo "  [ALERT] Collision cost: ~\$45,000 (Stevens et al, 2020)"
        echo "  [*] Current checksums:"
        cat "$CHECKSUM_FILE" | while IFS= read -r line; do
            echo "    $line"
        done
        FINDINGS=$((FINDINGS + 1))
    elif [[ "$HASH_LEN" -eq 32 ]]; then
        echo "  [ALERT] Integrity checksums use MD5 (32-character hash)"
        FINDINGS=$((FINDINGS + 1))
    elif [[ "$HASH_LEN" -eq 64 ]]; then
        echo "  [OK] Integrity checksums use SHA-256 (64-character hash)"
    else
        echo "  [INFO] Unknown hash format (length: $HASH_LEN)"
    fi
else
    echo "  [INFO] No checksum file found at $CHECKSUM_FILE"
fi
echo ""

# --- Method 4: PRNG Audit ---

echo "[*] Method 4: Random number generator audit"
echo "----------------------------------------------"

if [[ -f "$DATA_DIR/auth_handler.py" ]]; then
    echo "[*] Checking $DATA_DIR/auth_handler.py for PRNG issues..."

    # Check for import random (non-cryptographic)
    if grep -q "^import random" "$DATA_DIR/auth_handler.py" 2>/dev/null; then
        echo "  [ALERT] Uses 'import random' — non-cryptographic PRNG"
        echo "  [*] Python 'random' module uses Mersenne Twister (MT19937)"
        echo "  [*] MT19937 state is recoverable from 624 outputs"
        FINDINGS=$((FINDINGS + 1))
    fi

    # Check for import secrets (cryptographic)
    if ! grep -q "^import secrets" "$DATA_DIR/auth_handler.py" 2>/dev/null; then
        echo "  [ALERT] Does NOT use 'import secrets' — no CSPRNG"
        echo "  [*] Fix: replace random.choices() with secrets.token_hex()"
        FINDINGS=$((FINDINGS + 1))
    fi

    # Check for static seed
    if grep -q "random.seed" "$DATA_DIR/auth_handler.py" 2>/dev/null; then
        echo "  [ALERT] Uses random.seed() with static value — fully predictable"
        echo "  [*] All tokens generated with this seed are deterministic"
        FINDINGS=$((FINDINGS + 1))
    fi
else
    echo "  [INFO] No auth_handler.py found"
fi
echo ""

# --- Method 5: Crypto Config Audit ---

echo "[*] Method 5: Cryptographic configuration audit"
echo "----------------------------------------------"

if [[ -f "$DATA_DIR/crypto-config.yaml" ]] && command -v python3 &>/dev/null; then
    python3 << 'PYEOF'
import sys

# Simple YAML-like parsing (no PyYAML dependency)
config_findings = 0

with open(sys.argv[1] if len(sys.argv) > 1 else "/tmp/sc13-crypto-lab/crypto-config.yaml") as f:
    content = f.read()

checks = [
    ("MD5", "Password hashing uses MD5 — broken since 2004"),
    ("SHA-1", "File integrity uses SHA-1 — collision-broken since 2017"),
    ("DES", "Data encryption uses DES — 56-bit key, crackable in hours"),
    ("ECB", "Encryption uses ECB mode — leaks plaintext patterns"),
    ('"1.0"', "TLS minimum version is 1.0 — POODLE/BEAST vulnerable"),
    ("RC4", "Cipher suite includes RC4 — broken stream cipher"),
    ("pseudo-random", "Random source is non-cryptographic PRNG"),
    ("static-seed", "PRNG uses static seed — fully predictable"),
]

for pattern, description in checks:
    if pattern in content:
        print(f"  [ALERT] {description}")
        config_findings += 1

print(f"\n[*] Configuration findings: {config_findings}")
PYEOF

    python3 -c "
content = open('$DATA_DIR/crypto-config.yaml').read()
checks = [('MD5','MD5'),('SHA-1','SHA-1'),('DES','DES'),('ECB','ECB'),('\"1.0\"','TLS 1.0'),('RC4','RC4'),('pseudo-random','weak PRNG'),('static-seed','static seed')]
hits = sum(1 for p,_ in checks if p in content)
print(hits)
" 2>/dev/null | while read -r count; do
        FINDINGS=$((FINDINGS + count))
    done
else
    echo "  [INFO] crypto-config.yaml not found"
fi
echo ""

# --- Evidence Summary ---

echo "============================================"
echo "Detection Summary"
echo "============================================"
echo ""
echo "[*] Total findings: $FINDINGS"
echo ""

if [[ "$FINDINGS" -gt 0 ]]; then
    echo "[ALERT] Weak cryptographic algorithms in use!"
    echo ""
    echo "[*] Weak algorithms found:"
    echo "    - MD5 for password hashing (crackable at 150B hashes/sec on GPU)"
    echo "    - SHA-1 for file integrity (collision cost: ~\$45K)"
    echo "    - DES for encryption (56-bit key — brute-forced in hours)"
    echo "    - ECB mode (leaks patterns in ciphertext)"
    echo "    - Non-cryptographic PRNG for security tokens"
    echo ""
    echo "[*] FIPS 140-2 approved algorithms:"
    echo "    - Password hashing: bcrypt (work factor 12+), Argon2id, PBKDF2-SHA256"
    echo "    - Integrity: SHA-256, SHA-384, SHA-512"
    echo "    - Encryption: AES-128/192/256 in GCM or CBC mode"
    echo "    - Key exchange: ECDHE with P-256 or P-384"
    echo "    - Random: /dev/urandom, secrets module, CSPRNG"
    echo ""
    echo "[*] Run fix.sh to migrate to approved algorithms."
else
    echo "[OK] No weak cryptographic algorithms detected."
fi

echo ""
echo "[*] Evidence saved to: $EVIDENCE_DIR"
echo "[*] Files:"
ls -la "$EVIDENCE_DIR/"
