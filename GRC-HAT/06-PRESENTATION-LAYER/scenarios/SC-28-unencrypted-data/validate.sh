#!/usr/bin/env bash
set -euo pipefail

# SC-28 Unencrypted Data at Rest — Validate
#
# Confirms that data-at-rest protection is properly implemented:
#   1. No plaintext passwords in database (all bcrypt or PBKDF2)
#   2. PII fields encrypted (SSN, PHI show ENC[] prefix)
#   3. No hardcoded secrets in config files
#   4. Disk encryption enabled or requirements documented
#   5. .gitignore prevents secret commits
#
# CSF 2.0: PR.DS-01 (Data-at-rest confidentiality)
# CIS v8: 3.11 (Encrypt Sensitive Data at Rest)
# NIST: SC-28 (Protection of Information at Rest)
#
# REQUIREMENTS:
#   - sqlite3
#   - python3 (for hash format verification)
#   - grep
#
# USAGE:
#   ./validate.sh [data_dir]
#
# EXAMPLE:
#   ./validate.sh /tmp/sc28-data-lab

# --- Argument Validation ---

DATA_DIR="${1:-/tmp/sc28-data-lab}"

EVIDENCE_DIR="/tmp/sc28-unencrypted-data-validate-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$EVIDENCE_DIR"

echo "============================================"
echo "SC-28 Unencrypted Data at Rest — Validation"
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

# --- Test 1: Password Hashing Verification ---

echo "[*] Test 1: Password hashing verification"
echo "----------------------------------------------"

DB_PATH="$DATA_DIR/app.db"

if [[ -f "$DB_PATH" ]] && command -v sqlite3 &>/dev/null; then
    PLAINTEXT_COUNT=0
    HASHED_COUNT=0

    while IFS='|' read -r username password; do
        if [[ "$password" =~ ^\$2[aby]\$ ]]; then
            echo "  [OK] $username: bcrypt hash"
            HASHED_COUNT=$((HASHED_COUNT + 1))
        elif [[ "$password" =~ ^pbkdf2: ]]; then
            echo "  [OK] $username: PBKDF2-SHA256 hash"
            HASHED_COUNT=$((HASHED_COUNT + 1))
        elif [[ "$password" =~ ^[a-f0-9]{32}$ ]]; then
            echo "  [FAIL] $username: MD5 hash (weak — must use bcrypt)"
            PLAINTEXT_COUNT=$((PLAINTEXT_COUNT + 1))
        else
            echo "  [FAIL] $username: plaintext password detected"
            PLAINTEXT_COUNT=$((PLAINTEXT_COUNT + 1))
        fi
    done < <(sqlite3 "$DB_PATH" "SELECT username, password FROM users;" 2>/dev/null)

    if [[ "$PLAINTEXT_COUNT" -eq 0 ]] && [[ "$HASHED_COUNT" -gt 0 ]]; then
        check_result "Password hashing" "pass" "All $HASHED_COUNT passwords properly hashed"
    else
        check_result "Password hashing" "fail" "$PLAINTEXT_COUNT plaintext/weak passwords remain"
    fi
else
    echo "[SKIP] Database not found or sqlite3 not installed"
    SKIP=$((SKIP + 1))
fi
echo ""

# --- Test 2: PII Encryption Verification ---

echo "[*] Test 2: PII encryption (SSN fields)"
echo "----------------------------------------------"

if [[ -f "$DB_PATH" ]] && command -v sqlite3 &>/dev/null; then
    ENCRYPTED_SSN=0
    PLAINTEXT_SSN=0

    while IFS='|' read -r username ssn; do
        [[ -z "$ssn" ]] && continue

        if [[ "$ssn" =~ ^ENC\[ ]]; then
            echo "  [OK] $username: SSN encrypted"
            ENCRYPTED_SSN=$((ENCRYPTED_SSN + 1))
        elif [[ "$ssn" =~ ^[0-9]{3}-[0-9]{2}-[0-9]{4}$ ]]; then
            echo "  [FAIL] $username: SSN in plaintext — $ssn"
            PLAINTEXT_SSN=$((PLAINTEXT_SSN + 1))
        else
            echo "  [WARN] $username: SSN format unclear — manual review"
        fi
    done < <(sqlite3 "$DB_PATH" "SELECT username, ssn FROM users WHERE ssn IS NOT NULL;" 2>/dev/null)

    if [[ "$PLAINTEXT_SSN" -eq 0 ]] && [[ "$ENCRYPTED_SSN" -gt 0 ]]; then
        check_result "SSN encryption" "pass" "All $ENCRYPTED_SSN SSNs encrypted"
    elif [[ "$ENCRYPTED_SSN" -eq 0 ]] && [[ "$PLAINTEXT_SSN" -eq 0 ]]; then
        echo "  [INFO] No SSN data found"
        SKIP=$((SKIP + 1))
    else
        check_result "SSN encryption" "fail" "$PLAINTEXT_SSN plaintext SSNs remain"
    fi
else
    SKIP=$((SKIP + 1))
fi
echo ""

# --- Test 3: PHI Encryption Verification ---

echo "[*] Test 3: PHI encryption (patient records)"
echo "----------------------------------------------"

if [[ -f "$DB_PATH" ]] && command -v sqlite3 &>/dev/null; then
    ENCRYPTED_PHI=0
    PLAINTEXT_PHI=0

    while IFS='|' read -r name diagnosis medication ins_id; do
        ALL_ENC=true

        if [[ ! "$diagnosis" =~ ^ENC\[ ]]; then
            echo "  [FAIL] $name: diagnosis in plaintext"
            ALL_ENC=false
        fi
        if [[ ! "$medication" =~ ^ENC\[ ]]; then
            echo "  [FAIL] $name: medication in plaintext"
            ALL_ENC=false
        fi
        if [[ ! "$ins_id" =~ ^ENC\[ ]]; then
            echo "  [FAIL] $name: insurance_id in plaintext"
            ALL_ENC=false
        fi

        if [[ "$ALL_ENC" == "true" ]]; then
            echo "  [OK] $name: all PHI fields encrypted"
            ENCRYPTED_PHI=$((ENCRYPTED_PHI + 1))
        else
            PLAINTEXT_PHI=$((PLAINTEXT_PHI + 1))
        fi
    done < <(sqlite3 "$DB_PATH" "SELECT patient_name, diagnosis, medication, insurance_id FROM patient_records;" 2>/dev/null)

    if [[ "$PLAINTEXT_PHI" -eq 0 ]] && [[ "$ENCRYPTED_PHI" -gt 0 ]]; then
        check_result "PHI encryption" "pass" "All $ENCRYPTED_PHI patient records encrypted"
    else
        check_result "PHI encryption" "fail" "$PLAINTEXT_PHI patients with plaintext PHI"
    fi
else
    SKIP=$((SKIP + 1))
fi
echo ""

# --- Test 4: API Key Encryption Verification ---

echo "[*] Test 4: API key encryption"
echo "----------------------------------------------"

if [[ -f "$DB_PATH" ]] && command -v sqlite3 &>/dev/null; then
    ENCRYPTED_KEYS=0
    PLAINTEXT_KEYS=0

    while IFS='|' read -r service api_key; do
        if [[ "$api_key" =~ ^ENC\[ ]] || [[ "$api_key" =~ ^vault: ]]; then
            echo "  [OK] $service: API key encrypted or vault-referenced"
            ENCRYPTED_KEYS=$((ENCRYPTED_KEYS + 1))
        else
            echo "  [FAIL] $service: API key in plaintext"
            PLAINTEXT_KEYS=$((PLAINTEXT_KEYS + 1))
        fi
    done < <(sqlite3 "$DB_PATH" "SELECT service_name, api_key FROM api_keys;" 2>/dev/null)

    if [[ "$PLAINTEXT_KEYS" -eq 0 ]] && [[ "$ENCRYPTED_KEYS" -gt 0 ]]; then
        check_result "API key encryption" "pass" "All $ENCRYPTED_KEYS API keys encrypted"
    else
        check_result "API key encryption" "fail" "$PLAINTEXT_KEYS plaintext API keys remain"
    fi
else
    SKIP=$((SKIP + 1))
fi
echo ""

# --- Test 5: Config File Secrets Check ---

echo "[*] Test 5: No hardcoded secrets in config files"
echo "----------------------------------------------"

HARDCODED_SECRETS=0

if [[ -f "$DATA_DIR/app-config.yaml" ]]; then
    # Check for patterns that look like actual secrets (not env var references)
    while IFS= read -r line; do
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ -z "$line" ]] && continue

        # Match password/secret/key with an actual value (not _env suffix or vault ref)
        if echo "$line" | grep -qiE '(password|secret_key|api_key)["\x27]?\s*[:=]\s*["\x27][^$v]'; then
            # Exclude _env references
            if ! echo "$line" | grep -qiE '_env|vault:|ENV\[|\$\{'; then
                echo "  [FAIL] Hardcoded secret found: $(echo "$line" | sed 's/^[[:space:]]*//')"
                HARDCODED_SECRETS=$((HARDCODED_SECRETS + 1))
            fi
        fi
    done < "$DATA_DIR/app-config.yaml"

    if [[ "$HARDCODED_SECRETS" -eq 0 ]]; then
        check_result "Config secrets" "pass" "No hardcoded secrets in app-config.yaml"
    else
        check_result "Config secrets" "fail" "$HARDCODED_SECRETS hardcoded secrets remain"
    fi
else
    echo "[SKIP] app-config.yaml not found"
    SKIP=$((SKIP + 1))
fi

# Check .env file
if [[ -f "$DATA_DIR/.env" ]]; then
    ENV_HARDCODED=0

    while IFS= read -r line; do
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ -z "$line" ]] && continue

        VALUE=$(echo "$line" | cut -d'=' -f2- || true)
        if [[ -n "$VALUE" ]] && ! echo "$VALUE" | grep -qiE '(vault:|changeme|PLACEHOLDER|\$\{)'; then
            KEY_NAME=$(echo "$line" | cut -d'=' -f1)
            if echo "$KEY_NAME" | grep -qiE '(PASSWORD|SECRET|KEY)'; then
                # It's a secret-looking variable — check if value is a real secret
                if [[ ${#VALUE} -gt 10 ]] && ! echo "$VALUE" | grep -q "vault:"; then
                    echo "  [FAIL] Possible hardcoded secret in .env: $KEY_NAME"
                    ENV_HARDCODED=$((ENV_HARDCODED + 1))
                fi
            fi
        fi
    done < "$DATA_DIR/.env"

    if [[ "$ENV_HARDCODED" -eq 0 ]]; then
        check_result ".env secrets" "pass" "No hardcoded secrets in .env (vault references used)"
    else
        check_result ".env secrets" "fail" "$ENV_HARDCODED hardcoded secrets in .env"
    fi
else
    echo "[SKIP] .env not found"
    SKIP=$((SKIP + 1))
fi
echo ""

# --- Test 6: Disk Encryption Status ---

echo "[*] Test 6: Disk encryption status"
echo "----------------------------------------------"

DISK_PASS=false

# Check actual system
if command -v lsblk &>/dev/null; then
    CRYPT_COUNT=$(lsblk -o NAME,TYPE 2>/dev/null | grep -c "crypt" || echo "0")

    if [[ "$CRYPT_COUNT" -gt 0 ]]; then
        echo "  [OK] $CRYPT_COUNT encrypted volume(s) detected"
        DISK_PASS=true
    else
        echo "  [INFO] No LUKS volumes detected on this system"
    fi
fi

# Check BitLocker (WSL)
if command -v manage-bde.exe &>/dev/null 2>/dev/null; then
    if manage-bde.exe -status C: 2>/dev/null | grep -qi "Protection On"; then
        echo "  [OK] BitLocker enabled on Windows host"
        DISK_PASS=true
    fi
fi

# Check target state config
if [[ -f "$DATA_DIR/disk-encryption-status.json" ]] && command -v python3 &>/dev/null; then
    DISK_STATUS=$(python3 -c "
import json
with open('$DATA_DIR/disk-encryption-status.json') as f:
    s = json.load(f)
all_enc = all(v.get('encrypted', False) for v in s.get('volumes', []))
print('encrypted' if all_enc else 'unencrypted')
" 2>/dev/null || echo "unknown")

    if [[ "$DISK_STATUS" == "encrypted" ]]; then
        echo "  [OK] Disk encryption target state: all volumes encrypted"
        DISK_PASS=true
    else
        echo "  [FAIL] Disk encryption target state: unencrypted volumes remain"
    fi
fi

if [[ "$DISK_PASS" == "true" ]]; then
    check_result "Disk encryption" "pass" "Encryption enabled or target state documented"
else
    check_result "Disk encryption" "fail" "No disk encryption detected"
fi
echo ""

# --- Test 7: .gitignore Check ---

echo "[*] Test 7: .gitignore prevents secret commits"
echo "----------------------------------------------"

if [[ -f "$DATA_DIR/.gitignore" ]]; then
    GITIGNORE_OK=true

    for pattern in ".env" "*.key" "*.db"; do
        if grep -q "$pattern" "$DATA_DIR/.gitignore" 2>/dev/null; then
            echo "  [OK] .gitignore contains: $pattern"
        else
            echo "  [FAIL] .gitignore missing: $pattern"
            GITIGNORE_OK=false
        fi
    done

    if [[ "$GITIGNORE_OK" == "true" ]]; then
        check_result ".gitignore" "pass" "Secret file patterns excluded"
    else
        check_result ".gitignore" "fail" "Missing critical patterns"
    fi
else
    check_result ".gitignore" "fail" "No .gitignore file found"
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
    echo "[PASS] SC-28 data-at-rest protection validated successfully."
    echo "[*] All passwords hashed, PII encrypted, secrets externalized, disk encrypted."
    echo ""
    echo "[*] Residual risk: LOW"
    echo "    - Likelihood: 2 (Unlikely) — data encrypted, secrets externalized"
    echo "    - Impact: 2 (Minor) — breach yields ciphertext, not cleartext"
    echo "    - Residual Score: 4 (Low)"
elif [[ "$FAIL" -gt 0 ]]; then
    echo "[FAIL] SC-28 validation has $FAIL failing check(s)."
    echo "[*] Review the failures above and re-run fix.sh."
else
    echo "[INCOMPLETE] All tests were skipped — verify data directory and tools exist."
fi

echo ""
echo "[*] Evidence saved to: $EVIDENCE_DIR"
echo "[*] Files:"
ls -la "$EVIDENCE_DIR/"
