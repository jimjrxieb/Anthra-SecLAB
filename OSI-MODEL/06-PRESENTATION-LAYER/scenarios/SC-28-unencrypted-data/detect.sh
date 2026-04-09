#!/usr/bin/env bash
set -euo pipefail

# SC-28 Unencrypted Data at Rest — Detect
#
# Detects unprotected data at rest using:
#   1. Database query — find plaintext passwords and unencrypted PII
#   2. Config audit — scan for hardcoded secrets in config files
#   3. Disk encryption check — verify BitLocker/LUKS status
#   4. Secrets scan — grep for API keys, passwords, and tokens in files
#
# REQUIREMENTS:
#   - sqlite3 (for database checks)
#   - grep (for secrets scanning)
#   - lsblk (for disk encryption check on Linux)
#
# USAGE:
#   ./detect.sh [data_dir]
#
# EXAMPLE:
#   ./detect.sh /tmp/sc28-data-lab
#   ./detect.sh ./test-data

# --- Argument Validation ---

DATA_DIR="${1:-/tmp/sc28-data-lab}"

EVIDENCE_DIR="/tmp/sc28-unencrypted-data-detect-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$EVIDENCE_DIR"

echo "============================================"
echo "SC-28 Unencrypted Data at Rest — Detection"
echo "============================================"
echo ""
echo "[*] Data dir:     $DATA_DIR"
echo "[*] Evidence dir: $EVIDENCE_DIR"
echo ""

FINDINGS=0

# --- Method 1: Database Plaintext Password Check ---

echo "[*] Method 1: Database plaintext password analysis"
echo "----------------------------------------------"

DB_PATH="$DATA_DIR/app.db"

if [[ -f "$DB_PATH" ]] && command -v sqlite3 &>/dev/null; then
    echo "[*] Querying users table for password format..."

    # Extract passwords and analyze format
    PASSWORDS=$(sqlite3 "$DB_PATH" "SELECT username, password FROM users;" 2>/dev/null || echo "QUERY_FAILED")

    if [[ "$PASSWORDS" != "QUERY_FAILED" ]] && [[ -n "$PASSWORDS" ]]; then
        echo "$PASSWORDS" > "$EVIDENCE_DIR/extracted-passwords.txt"
        echo "[+] Extracted user credentials:"

        PLAINTEXT_COUNT=0
        while IFS='|' read -r username password; do
            # Check if password looks hashed (bcrypt starts with $2, SHA starts with hex string)
            if [[ "$password" =~ ^\$2[aby]\$ ]]; then
                echo "  [OK] $username: bcrypt hash detected"
            elif [[ "$password" =~ ^[a-f0-9]{64}$ ]]; then
                echo "  [WARN] $username: SHA-256 hash (acceptable for non-passwords)"
            elif [[ "$password" =~ ^[a-f0-9]{32}$ ]]; then
                echo "  [ALERT] $username: MD5 hash detected — weak, crackable"
                PLAINTEXT_COUNT=$((PLAINTEXT_COUNT + 1))
            else
                echo "  [ALERT] $username: PLAINTEXT password detected — '$password'"
                PLAINTEXT_COUNT=$((PLAINTEXT_COUNT + 1))
            fi
        done <<< "$PASSWORDS"

        if [[ "$PLAINTEXT_COUNT" -gt 0 ]]; then
            echo ""
            echo "[ALERT] Found $PLAINTEXT_COUNT plaintext/weak passwords in database"
            FINDINGS=$((FINDINGS + PLAINTEXT_COUNT))
        fi
    fi

    echo ""

    # Check for unencrypted PII (SSN format)
    echo "[*] Checking for unencrypted PII (SSN format)..."
    SSN_DATA=$(sqlite3 "$DB_PATH" "SELECT username, ssn FROM users WHERE ssn IS NOT NULL;" 2>/dev/null || echo "")

    if [[ -n "$SSN_DATA" ]]; then
        SSN_PLAINTEXT=0
        while IFS='|' read -r username ssn; do
            if [[ "$ssn" =~ ^[0-9]{3}-[0-9]{2}-[0-9]{4}$ ]]; then
                echo "  [ALERT] $username: SSN stored in plaintext — $ssn"
                SSN_PLAINTEXT=$((SSN_PLAINTEXT + 1))
            elif [[ "$ssn" =~ ^ENC\[ ]] || [[ ${#ssn} -gt 40 ]]; then
                echo "  [OK] $username: SSN appears encrypted"
            else
                echo "  [WARN] $username: SSN format unclear — manual review needed"
            fi
        done <<< "$SSN_DATA"

        if [[ "$SSN_PLAINTEXT" -gt 0 ]]; then
            echo ""
            echo "[ALERT] Found $SSN_PLAINTEXT unencrypted SSNs"
            FINDINGS=$((FINDINGS + SSN_PLAINTEXT))
        fi
    fi

    echo ""

    # Check for PHI
    echo "[*] Checking for unencrypted PHI (patient records)..."
    PHI_COUNT=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM patient_records;" 2>/dev/null || echo "0")

    if [[ "$PHI_COUNT" -gt 0 ]]; then
        echo "  [ALERT] Found $PHI_COUNT patient records with unencrypted PHI"
        echo "[*] Sample record:"
        sqlite3 "$DB_PATH" "SELECT patient_name, diagnosis FROM patient_records LIMIT 1;" 2>/dev/null \
            | tee -a "$EVIDENCE_DIR/phi-exposure.txt"
        FINDINGS=$((FINDINGS + PHI_COUNT))
    fi

    echo ""

    # Check for plaintext API keys
    echo "[*] Checking for plaintext API keys in database..."
    API_COUNT=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM api_keys;" 2>/dev/null || echo "0")

    if [[ "$API_COUNT" -gt 0 ]]; then
        EXPOSED_KEYS=0
        while IFS='|' read -r service key; do
            if [[ "$key" =~ ^ENC\[ ]] || [[ "$key" =~ ^vault: ]]; then
                echo "  [OK] $service: API key appears encrypted or vault-referenced"
            else
                echo "  [ALERT] $service: API key stored in PLAINTEXT — ${key:0:20}..."
                EXPOSED_KEYS=$((EXPOSED_KEYS + 1))
            fi
        done < <(sqlite3 "$DB_PATH" "SELECT service_name, api_key FROM api_keys;" 2>/dev/null)

        if [[ "$EXPOSED_KEYS" -gt 0 ]]; then
            echo ""
            echo "[ALERT] Found $EXPOSED_KEYS plaintext API keys in database"
            FINDINGS=$((FINDINGS + EXPOSED_KEYS))
        fi
    fi
else
    echo "[INFO] No SQLite database found at $DB_PATH or sqlite3 not installed"

    # Check for CSV fallback
    if [[ -f "$DATA_DIR/users.csv" ]]; then
        echo "[*] Checking CSV file for plaintext passwords..."
        PLAINTEXT_IN_CSV=$(tail -n +2 "$DATA_DIR/users.csv" | wc -l)
        echo "[ALERT] Found $PLAINTEXT_IN_CSV rows with plaintext passwords in CSV"
        FINDINGS=$((FINDINGS + PLAINTEXT_IN_CSV))
    fi
fi
echo ""

# --- Method 2: Config File Secrets Scan ---

echo "[*] Method 2: Configuration file secrets scan"
echo "----------------------------------------------"

CONFIG_FINDINGS=0

# Check YAML config
if [[ -f "$DATA_DIR/app-config.yaml" ]]; then
    echo "[*] Scanning $DATA_DIR/app-config.yaml for secrets..."

    # Pattern: password, secret, key, token followed by a value
    while IFS= read -r line; do
        # Skip comments and empty lines
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ -z "$line" ]] && continue

        if echo "$line" | grep -qiE '(password|secret|key|token)["\x27]?\s*[:=]\s*["\x27]?.{4,}'; then
            # Check if it's a vault reference or env var
            if echo "$line" | grep -qiE '(vault://|\$\{|ENV\[|ssm:|arn:)'; then
                echo "  [OK] Vault/env reference: $(echo "$line" | sed 's/^[[:space:]]*//')"
            else
                echo "  [ALERT] Hardcoded secret: $(echo "$line" | sed 's/^[[:space:]]*//')"
                CONFIG_FINDINGS=$((CONFIG_FINDINGS + 1))
            fi
        fi
    done < "$DATA_DIR/app-config.yaml"

    if [[ "$CONFIG_FINDINGS" -gt 0 ]]; then
        echo ""
        echo "[ALERT] Found $CONFIG_FINDINGS hardcoded secrets in app-config.yaml"
        FINDINGS=$((FINDINGS + CONFIG_FINDINGS))
    fi
    cp "$DATA_DIR/app-config.yaml" "$EVIDENCE_DIR/config-with-secrets.yaml"
fi

echo ""

# Check .env file
if [[ -f "$DATA_DIR/.env" ]]; then
    echo "[*] Scanning $DATA_DIR/.env for secrets..."

    ENV_SECRETS=0
    while IFS= read -r line; do
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ -z "$line" ]] && continue

        if echo "$line" | grep -qiE '(PASSWORD|SECRET|KEY|TOKEN)=.{4,}'; then
            # Check if value references a vault or is a placeholder
            VALUE=$(echo "$line" | cut -d'=' -f2-)
            if echo "$VALUE" | grep -qiE '(vault://|\$\{|changeme|PLACEHOLDER)'; then
                echo "  [OK] Reference/placeholder: $(echo "$line" | cut -d'=' -f1)"
            else
                echo "  [ALERT] Plaintext secret: $(echo "$line" | cut -d'=' -f1)=$(echo "$VALUE" | head -c 15)..."
                ENV_SECRETS=$((ENV_SECRETS + 1))
            fi
        fi
    done < "$DATA_DIR/.env"

    if [[ "$ENV_SECRETS" -gt 0 ]]; then
        echo ""
        echo "[ALERT] Found $ENV_SECRETS plaintext secrets in .env file"
        FINDINGS=$((FINDINGS + ENV_SECRETS))
    fi
    cp "$DATA_DIR/.env" "$EVIDENCE_DIR/dotenv-exposed.txt"
fi
echo ""

# --- Method 3: Disk Encryption Status ---

echo "[*] Method 3: Disk encryption verification"
echo "----------------------------------------------"

DISK_ENCRYPTED=false

# Linux: Check for LUKS/dm-crypt
if command -v lsblk &>/dev/null; then
    echo "[*] Checking for encrypted volumes (Linux)..."
    CRYPT_COUNT=$(lsblk -o NAME,TYPE 2>/dev/null | grep -c "crypt" || echo "0")

    if [[ "$CRYPT_COUNT" -gt 0 ]]; then
        echo "  [OK] Found $CRYPT_COUNT encrypted volume(s)"
        DISK_ENCRYPTED=true
    else
        echo "  [ALERT] No encrypted volumes (LUKS/dm-crypt) detected"
        FINDINGS=$((FINDINGS + 1))
    fi

    lsblk -o NAME,FSTYPE,SIZE,TYPE,MOUNTPOINT 2>/dev/null \
        | tee "$EVIDENCE_DIR/disk-layout.txt"
fi

echo ""

# Windows/WSL: Check BitLocker
if [[ -f /proc/version ]] && grep -qi "microsoft" /proc/version 2>/dev/null; then
    echo "[*] WSL environment detected — checking BitLocker..."

    if command -v manage-bde.exe &>/dev/null 2>/dev/null; then
        BITLOCKER_OUT=$(manage-bde.exe -status C: 2>/dev/null || echo "ACCESS_DENIED")

        if echo "$BITLOCKER_OUT" | grep -qi "Protection On"; then
            echo "  [OK] BitLocker is ENABLED on C: drive"
            DISK_ENCRYPTED=true
        elif [[ "$BITLOCKER_OUT" == "ACCESS_DENIED" ]]; then
            echo "  [INFO] Cannot check BitLocker — requires admin PowerShell"
            echo "  [INFO] Run manually: manage-bde -status C:"
        else
            echo "  [ALERT] BitLocker is DISABLED on C: drive"
            FINDINGS=$((FINDINGS + 1))
        fi

        echo "$BITLOCKER_OUT" > "$EVIDENCE_DIR/bitlocker-status.txt"
    else
        echo "  [INFO] manage-bde.exe not accessible from WSL"
        echo "  [INFO] Run on Windows host: manage-bde -status C:"
    fi
fi

# Check simulated status file
if [[ -f "$DATA_DIR/disk-encryption-status.json" ]]; then
    echo ""
    echo "[*] Checking simulated disk encryption status..."

    if command -v python3 &>/dev/null; then
        python3 -c "
import json

with open('$DATA_DIR/disk-encryption-status.json') as f:
    status = json.load(f)

unencrypted = 0
for vol in status.get('volumes', []):
    if not vol.get('encrypted', False):
        print(f'  [ALERT] {vol[\"device\"]} ({vol[\"mount\"]}): {vol[\"status\"]}')
        unencrypted += 1
    else:
        print(f'  [OK] {vol[\"device\"]} ({vol[\"mount\"]}): encrypted with {vol[\"encryption_method\"]}')

if status.get('tpm_available') and not status.get('tpm_used'):
    print('  [ALERT] TPM is available but NOT used for encryption')
    unencrypted += 1

print(f'\\n[*] Unencrypted volumes: {unencrypted}')
" 2>&1 | tee "$EVIDENCE_DIR/disk-encryption-audit.txt"
    fi
fi
echo ""

# --- Method 4: Broad Secrets Scan ---

echo "[*] Method 4: Broad secrets pattern scan"
echo "----------------------------------------------"

echo "[*] Scanning $DATA_DIR for secret patterns..."
SECRET_PATTERNS=(
    'AKIA[0-9A-Z]{16}'                    # AWS Access Key
    'sk_live_[0-9a-zA-Z]{24}'             # Stripe Secret Key
    'sk-proj-[a-zA-Z0-9]{20,}'            # OpenAI API Key
    'SG\.[a-zA-Z0-9_-]{22}\.'             # SendGrid API Key
    'hooks\.slack\.com/services/'          # Slack Webhook
    '[0-9]{3}-[0-9]{2}-[0-9]{4}'          # SSN Format
)

SECRET_HITS=0

for pattern in "${SECRET_PATTERNS[@]}"; do
    MATCHES=$(grep -rn "$pattern" "$DATA_DIR/" 2>/dev/null | grep -v "\.db$" || true)
    if [[ -n "$MATCHES" ]]; then
        echo "  [ALERT] Pattern match: $pattern"
        echo "$MATCHES" | head -3 | while IFS= read -r match; do
            echo "    $match"
        done
        SECRET_HITS=$((SECRET_HITS + 1))
    fi
done

if [[ "$SECRET_HITS" -gt 0 ]]; then
    echo ""
    echo "[ALERT] Found $SECRET_HITS secret patterns in files"
    FINDINGS=$((FINDINGS + SECRET_HITS))
else
    echo "  [OK] No common secret patterns detected in files"
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
    echo "[ALERT] Data at rest protection is MISSING or INSUFFICIENT!"
    echo ""
    echo "[*] Key risks:"
    echo "    - Plaintext passwords: database dump exposes all credentials"
    echo "    - Unencrypted PII: SSNs and PHI readable without decryption"
    echo "    - Hardcoded secrets: config files contain production credentials"
    echo "    - No disk encryption: physical access yields all data"
    echo "    - API keys exposed: third-party services compromisable"
    echo ""
    echo "[*] IBM 2024 Cost of a Data Breach:"
    echo "    - Global average per record: \$164"
    echo "    - Healthcare per record: \$185"
    echo "    - Stolen credentials initial vector: \$4.81M average total"
    echo ""
    echo "[*] Run fix.sh to encrypt data, migrate secrets to vault, and enable disk encryption."
else
    echo "[OK] No unencrypted data-at-rest issues detected."
fi

echo ""
echo "[*] Evidence saved to: $EVIDENCE_DIR"
echo "[*] Files:"
ls -la "$EVIDENCE_DIR/"
