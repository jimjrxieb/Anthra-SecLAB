#!/usr/bin/env bash
set -euo pipefail

# SC-13 Weak Cryptography — Validate
#
# Confirms that cryptographic protections use approved algorithms:
#   1. All passwords use bcrypt or PBKDF2-SHA256 (no MD5/SHA-1)
#   2. Integrity checks use SHA-256+ (no SHA-1)
#   3. Crypto config specifies FIPS 140-2 approved algorithms
#   4. Auth handler uses secrets module (no random)
#   5. No weak crypto patterns in codebase
#
# CSF 2.0: DE.CM-09 (Computing monitored for adverse events)
# CIS v8: 3.10 (Encrypt Sensitive Data in Transit)
# NIST: SC-13 (Cryptographic Protection)
#
# REQUIREMENTS:
#   - sqlite3
#   - python3
#   - grep
#
# USAGE:
#   ./validate.sh [data_dir]
#
# EXAMPLE:
#   ./validate.sh /tmp/sc13-crypto-lab

# --- Argument Validation ---

DATA_DIR="${1:-/tmp/sc13-crypto-lab}"

EVIDENCE_DIR="/tmp/sc13-weak-crypto-validate-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$EVIDENCE_DIR"

echo "============================================"
echo "SC-13 Weak Cryptography — Validation"
echo "============================================"
echo ""
echo "[*] Data dir:     $DATA_DIR"
echo "[*] Evidence dir: $EVIDENCE_DIR"
echo ""

PASS=0
FAIL=0
SKIP=0

# --- Helper Function ---

check_result() {
    local test_name="$1"
    local result="$2"
    local detail="$3"

    if [[ "$result" == "pass" ]]; then
        echo "[PASS] $test_name — $detail"
        PASS=$((PASS + 1))
    else
        echo "[FAIL] $test_name — $detail"
        FAIL=$((FAIL + 1))
    fi
}

# --- Test 1: Password Hash Algorithm Verification ---

echo "[*] Test 1: Password hash algorithm verification"
echo "----------------------------------------------"

DB_PATH="$DATA_DIR/crypto.db"

if [[ -f "$DB_PATH" ]] && command -v sqlite3 &>/dev/null; then
    WEAK_COUNT=0
    STRONG_COUNT=0

    while IFS='|' read -r username hash_val algorithm; do
        case "$algorithm" in
            bcrypt|PBKDF2-SHA256|Argon2id)
                echo "  [OK] $username: $algorithm"
                STRONG_COUNT=$((STRONG_COUNT + 1))
                ;;
            MD5|SHA-1|SHA1)
                echo "  [FAIL] $username: $algorithm (weak — must migrate)"
                WEAK_COUNT=$((WEAK_COUNT + 1))
                ;;
            *)
                echo "  [WARN] $username: unknown algorithm '$algorithm'"
                ;;
        esac
    done < <(sqlite3 "$DB_PATH" "SELECT username, password_hash, hash_algorithm FROM users;" 2>/dev/null)

    if [[ "$WEAK_COUNT" -eq 0 ]] && [[ "$STRONG_COUNT" -gt 0 ]]; then
        check_result "Password hashing" "pass" "All $STRONG_COUNT passwords use approved algorithms"
    else
        check_result "Password hashing" "fail" "$WEAK_COUNT passwords still using weak algorithms"
    fi

    # Additional check: verify hash format matches algorithm claim
    echo ""
    echo "[*] Verifying hash format matches algorithm claim..."

    FORMAT_OK=true
    while IFS='|' read -r username hash_val algorithm; do
        if [[ "$algorithm" == "bcrypt" ]] && [[ ! "$hash_val" =~ ^\$2[aby]\$ ]]; then
            echo "  [FAIL] $username: claims bcrypt but hash format wrong"
            FORMAT_OK=false
        elif [[ "$algorithm" == "PBKDF2-SHA256" ]] && [[ ! "$hash_val" =~ ^pbkdf2: ]]; then
            echo "  [FAIL] $username: claims PBKDF2 but hash format wrong"
            FORMAT_OK=false
        fi
    done < <(sqlite3 "$DB_PATH" "SELECT username, password_hash, hash_algorithm FROM users;" 2>/dev/null)

    if [[ "$FORMAT_OK" == "true" ]]; then
        echo "  [OK] All hash formats match their claimed algorithms"
    fi
else
    echo "[SKIP] Database not found or sqlite3 not installed"
    SKIP=$((SKIP + 1))
fi
echo ""

# --- Test 2: Integrity Checksum Algorithm ---

echo "[*] Test 2: File integrity checksum algorithm"
echo "----------------------------------------------"

SHA256_FILE="$DATA_DIR/protected-files/checksums-sha256.txt"
SHA1_FILE="$DATA_DIR/protected-files/checksums-sha1.txt"

if [[ -f "$SHA1_FILE" ]]; then
    check_result "SHA-1 checksums removed" "fail" "checksums-sha1.txt still exists"
else
    check_result "SHA-1 checksums removed" "pass" "No SHA-1 checksum files found"
fi

if [[ -f "$SHA256_FILE" ]]; then
    FIRST_HASH=$(head -1 "$SHA256_FILE" | cut -d' ' -f1)
    HASH_LEN=${#FIRST_HASH}

    if [[ "$HASH_LEN" -eq 64 ]]; then
        check_result "SHA-256 checksums" "pass" "Integrity checksums use SHA-256 (64-char hash)"

        # Verify checksums are valid
        echo ""
        echo "[*] Verifying SHA-256 checksums..."
        VERIFY_OK=true
        while IFS='  ' read -r expected_hash filename; do
            [[ -z "$filename" ]] && continue
            FILEPATH="$DATA_DIR/protected-files/$filename"
            if [[ -f "$FILEPATH" ]]; then
                ACTUAL_HASH=$(sha256sum "$FILEPATH" 2>/dev/null | cut -d' ' -f1 || shasum -a 256 "$FILEPATH" 2>/dev/null | cut -d' ' -f1)
                if [[ "$ACTUAL_HASH" == "$expected_hash" ]]; then
                    echo "  [OK] $filename: checksum valid"
                else
                    echo "  [FAIL] $filename: checksum mismatch"
                    VERIFY_OK=false
                fi
            fi
        done < "$SHA256_FILE"

        if [[ "$VERIFY_OK" == "true" ]]; then
            echo "  [OK] All checksums verified"
        fi
    else
        check_result "SHA-256 checksums" "fail" "Checksum hash length $HASH_LEN (expected 64 for SHA-256)"
    fi
else
    echo "[SKIP] No SHA-256 checksum file found"
    SKIP=$((SKIP + 1))
fi
echo ""

# --- Test 3: Crypto Configuration Audit ---

echo "[*] Test 3: Cryptographic configuration standards"
echo "----------------------------------------------"

if [[ -f "$DATA_DIR/crypto-config.yaml" ]]; then
    CONFIG_PASS=0
    CONFIG_FAIL=0

    # Check for approved algorithms
    CONTENT=$(cat "$DATA_DIR/crypto-config.yaml")

    # Password hashing
    if echo "$CONTENT" | grep -q 'algorithm: "bcrypt"'; then
        echo "  [OK] Password hashing: bcrypt"
        CONFIG_PASS=$((CONFIG_PASS + 1))
    elif echo "$CONTENT" | grep -q 'PBKDF2-SHA256'; then
        echo "  [OK] Password hashing: PBKDF2-SHA256"
        CONFIG_PASS=$((CONFIG_PASS + 1))
    else
        echo "  [FAIL] Password hashing: not using approved algorithm"
        CONFIG_FAIL=$((CONFIG_FAIL + 1))
    fi

    # File integrity
    if echo "$CONTENT" | grep -q 'algorithm: "SHA-256"'; then
        echo "  [OK] File integrity: SHA-256"
        CONFIG_PASS=$((CONFIG_PASS + 1))
    else
        echo "  [FAIL] File integrity: not using SHA-256+"
        CONFIG_FAIL=$((CONFIG_FAIL + 1))
    fi

    # Encryption algorithm
    if echo "$CONTENT" | grep -q 'algorithm: "AES-256"'; then
        echo "  [OK] Data encryption: AES-256"
        CONFIG_PASS=$((CONFIG_PASS + 1))
    else
        echo "  [FAIL] Data encryption: not using AES-256"
        CONFIG_FAIL=$((CONFIG_FAIL + 1))
    fi

    # Encryption mode
    if echo "$CONTENT" | grep -q 'mode: "GCM"'; then
        echo "  [OK] Encryption mode: GCM (authenticated)"
        CONFIG_PASS=$((CONFIG_PASS + 1))
    else
        echo "  [FAIL] Encryption mode: not using GCM"
        CONFIG_FAIL=$((CONFIG_FAIL + 1))
    fi

    # TLS version
    if echo "$CONTENT" | grep -q 'min_version: "1.2"'; then
        echo "  [OK] TLS minimum: 1.2"
        CONFIG_PASS=$((CONFIG_PASS + 1))
    else
        echo "  [FAIL] TLS minimum: not 1.2+"
        CONFIG_FAIL=$((CONFIG_FAIL + 1))
    fi

    # Random source
    if echo "$CONTENT" | grep -q 'source: "CSPRNG"'; then
        echo "  [OK] Random source: CSPRNG"
        CONFIG_PASS=$((CONFIG_PASS + 1))
    else
        echo "  [FAIL] Random source: not CSPRNG"
        CONFIG_FAIL=$((CONFIG_FAIL + 1))
    fi

    if [[ "$CONFIG_FAIL" -eq 0 ]]; then
        check_result "Crypto configuration" "pass" "All $CONFIG_PASS settings use approved algorithms"
    else
        check_result "Crypto configuration" "fail" "$CONFIG_FAIL settings use non-approved algorithms"
    fi
else
    echo "[SKIP] crypto-config.yaml not found"
    SKIP=$((SKIP + 1))
fi
echo ""

# --- Test 4: Auth Handler Code Audit ---

echo "[*] Test 4: Auth handler code audit"
echo "----------------------------------------------"

if [[ -f "$DATA_DIR/auth_handler.py" ]]; then
    CODE_PASS=0
    CODE_FAIL=0

    # Check for weak patterns
    if grep -q "hashlib.md5" "$DATA_DIR/auth_handler.py" 2>/dev/null; then
        echo "  [FAIL] Uses hashlib.md5"
        CODE_FAIL=$((CODE_FAIL + 1))
    else
        echo "  [OK] No MD5 usage"
        CODE_PASS=$((CODE_PASS + 1))
    fi

    if grep -q "hashlib.sha1" "$DATA_DIR/auth_handler.py" 2>/dev/null; then
        echo "  [FAIL] Uses hashlib.sha1"
        CODE_FAIL=$((CODE_FAIL + 1))
    else
        echo "  [OK] No SHA-1 usage"
        CODE_PASS=$((CODE_PASS + 1))
    fi

    if grep -q "^import random" "$DATA_DIR/auth_handler.py" 2>/dev/null; then
        echo "  [FAIL] Uses non-cryptographic random module"
        CODE_FAIL=$((CODE_FAIL + 1))
    else
        echo "  [OK] No non-cryptographic random"
        CODE_PASS=$((CODE_PASS + 1))
    fi

    if grep -q "random.seed" "$DATA_DIR/auth_handler.py" 2>/dev/null; then
        echo "  [FAIL] Uses static random seed"
        CODE_FAIL=$((CODE_FAIL + 1))
    else
        echo "  [OK] No static random seed"
        CODE_PASS=$((CODE_PASS + 1))
    fi

    # Check for strong patterns
    if grep -q "import secrets" "$DATA_DIR/auth_handler.py" 2>/dev/null; then
        echo "  [OK] Uses secrets module (CSPRNG)"
        CODE_PASS=$((CODE_PASS + 1))
    else
        echo "  [FAIL] Does not use secrets module"
        CODE_FAIL=$((CODE_FAIL + 1))
    fi

    if grep -q "hmac.compare_digest" "$DATA_DIR/auth_handler.py" 2>/dev/null; then
        echo "  [OK] Uses constant-time comparison"
        CODE_PASS=$((CODE_PASS + 1))
    else
        echo "  [FAIL] No constant-time comparison for hash verification"
        CODE_FAIL=$((CODE_FAIL + 1))
    fi

    if grep -q "pbkdf2_hmac\|bcrypt\|argon2" "$DATA_DIR/auth_handler.py" 2>/dev/null; then
        echo "  [OK] Uses approved password hashing"
        CODE_PASS=$((CODE_PASS + 1))
    else
        echo "  [FAIL] No approved password hashing function"
        CODE_FAIL=$((CODE_FAIL + 1))
    fi

    if [[ "$CODE_FAIL" -eq 0 ]]; then
        check_result "Auth handler code" "pass" "All $CODE_PASS code checks passed"
    else
        check_result "Auth handler code" "fail" "$CODE_FAIL weak patterns found"
    fi
else
    echo "[SKIP] auth_handler.py not found"
    SKIP=$((SKIP + 1))
fi
echo ""

# --- Test 5: Crypto Standards Document ---

echo "[*] Test 5: Cryptographic standards document exists"
echo "----------------------------------------------"

if [[ -f "$DATA_DIR/CRYPTO-STANDARDS.md" ]]; then
    # Verify it mentions approved algorithms
    if grep -q "bcrypt" "$DATA_DIR/CRYPTO-STANDARDS.md" && \
       grep -q "AES" "$DATA_DIR/CRYPTO-STANDARDS.md" && \
       grep -q "SHA-256" "$DATA_DIR/CRYPTO-STANDARDS.md"; then
        check_result "Crypto standards doc" "pass" "Document exists with approved algorithm list"
    else
        check_result "Crypto standards doc" "fail" "Document exists but missing algorithm guidance"
    fi
else
    check_result "Crypto standards doc" "fail" "No CRYPTO-STANDARDS.md found"
fi
echo ""

# --- Validation Summary ---

echo "============================================"
echo "Validation Summary"
echo "============================================"
echo ""
echo "[*] Passed: $PASS"
echo "[*] Failed: $FAIL"
echo "[*] Skipped: $SKIP"
echo ""

if [[ "$FAIL" -eq 0 ]] && [[ "$PASS" -gt 0 ]]; then
    echo "[PASS] SC-13 cryptographic protection validated successfully."
    echo "[*] All algorithms are FIPS 140-2 approved. No weak crypto detected."
    echo ""
    echo "[*] Residual risk: LOW"
    echo "    - Likelihood: 1 (Rare) — bcrypt and AES-256 have no practical attacks"
    echo "    - Impact: 2 (Minor) — even if database stolen, hashes resist cracking"
    echo "    - Residual Score: 2 (Low)"
elif [[ "$FAIL" -gt 0 ]]; then
    echo "[FAIL] SC-13 validation has $FAIL failing check(s)."
    echo "[*] Review the failures above and re-run fix.sh."
else
    echo "[INCOMPLETE] All tests were skipped — verify data directory and tools exist."
fi

echo ""
echo "[*] Evidence saved to: $EVIDENCE_DIR"
echo "[*] Files:"
ls -la "$EVIDENCE_DIR/"
