#!/usr/bin/env bash
set -euo pipefail

# SC-28 Unencrypted Data at Rest — Break
#
# Creates a SQLite database with plaintext passwords and PII, writes secrets
# directly into application config files, and disables disk encryption checks.
# This simulates a production environment where sensitive data is stored without
# cryptographic protection — enabling mass credential theft, regulatory fines,
# and per-record breach costs of $164-$185 per record (IBM 2024).
#
# REQUIREMENTS:
#   - sqlite3
#   - openssl (for verification)
#   - python3 (optional, for PII generation)
#
# USAGE:
#   ./break.sh [data_dir]
#
# EXAMPLE:
#   ./break.sh /tmp/sc28-data-lab
#   ./break.sh ./test-data
#
# WARNING: This script is for authorized security testing only.
#          Unauthorized use is illegal under the CFAA and equivalent laws.

# --- Argument Validation ---

DATA_DIR="${1:-/tmp/sc28-data-lab}"

EVIDENCE_DIR="/tmp/sc28-unencrypted-data-evidence-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$EVIDENCE_DIR"
mkdir -p "$DATA_DIR"

echo "============================================"
echo "SC-28 Unencrypted Data at Rest — Break"
echo "============================================"
echo ""
echo "[*] Data dir:     $DATA_DIR"
echo "[*] Evidence dir: $EVIDENCE_DIR"
echo ""

# --- Record Pre-Break State ---

echo "[*] Recording pre-break state..."

# Check if disk encryption is available
if command -v lsblk &>/dev/null; then
    lsblk -o NAME,FSTYPE,SIZE,MOUNTPOINT,TYPE 2>/dev/null \
        > "$EVIDENCE_DIR/disk-layout-before.txt" || true
    echo "[+] Captured disk layout"
fi

# Check for existing databases
if [[ -f "$DATA_DIR/app.db" ]]; then
    cp "$DATA_DIR/app.db" "$EVIDENCE_DIR/app-db-before.db"
    echo "[+] Backed up existing database"
fi
echo ""

# --- Create Vulnerable Database with Plaintext Passwords ---

echo "[*] Creating database with plaintext passwords and PII..."

if command -v sqlite3 &>/dev/null; then
    DB_PATH="$DATA_DIR/app.db"

    sqlite3 "$DB_PATH" << 'SQLEOF'
-- SC28-BREAK: Database with plaintext passwords and unencrypted PII
-- DO NOT use in production — for security testing only

DROP TABLE IF EXISTS users;
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    email TEXT NOT NULL,
    full_name TEXT NOT NULL,
    ssn TEXT,
    date_of_birth TEXT,
    phone TEXT,
    created_at TEXT DEFAULT (datetime('now'))
);

-- VULNERABILITY: Passwords stored in plaintext — no hashing
-- VULNERABILITY: SSNs stored without encryption — PII exposure
-- VULNERABILITY: No column-level encryption on any sensitive field
INSERT INTO users (username, password, email, full_name, ssn, date_of_birth, phone) VALUES
    ('jsmith', 'Welcome2024!', 'john.smith@anthra.local', 'John Smith', '123-45-6789', '1985-03-15', '555-0101'),
    ('mjones', 'Password123', 'mary.jones@anthra.local', 'Mary Jones', '234-56-7890', '1990-07-22', '555-0102'),
    ('admin', 'admin', 'admin@anthra.local', 'System Admin', '345-67-8901', '1978-11-08', '555-0103'),
    ('bwilson', 'Qwerty!2024', 'bob.wilson@anthra.local', 'Bob Wilson', '456-78-9012', '1995-01-30', '555-0104'),
    ('alee', 'Summer2024#', 'alice.lee@anthra.local', 'Alice Lee', '567-89-0123', '1988-09-14', '555-0105');

DROP TABLE IF EXISTS api_keys;
CREATE TABLE api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    service_name TEXT NOT NULL,
    api_key TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
);

-- VULNERABILITY: API keys stored in plaintext in the database
INSERT INTO api_keys (service_name, api_key) VALUES
    ('stripe', 'sk_live_4eC39HqLyjWDarjtT1zdp7dc'),
    ('sendgrid', 'SG.xxxxxxxxxxxxxxxxxxxxx.yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy'),
    ('aws_access_key', 'AKIAIOSFODNN7EXAMPLE'),
    ('slack_webhook', 'https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXX');

DROP TABLE IF EXISTS patient_records;
CREATE TABLE patient_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_name TEXT NOT NULL,
    diagnosis TEXT NOT NULL,
    medication TEXT NOT NULL,
    insurance_id TEXT NOT NULL,
    notes TEXT
);

-- VULNERABILITY: PHI stored without encryption — HIPAA violation
INSERT INTO patient_records (patient_name, diagnosis, medication, insurance_id, notes) VALUES
    ('John Smith', 'Type 2 Diabetes', 'Metformin 500mg', 'INS-12345-A', 'Monitor A1C quarterly'),
    ('Mary Jones', 'Hypertension', 'Lisinopril 10mg', 'INS-23456-B', 'Blood pressure check monthly'),
    ('Bob Wilson', 'Major Depression', 'Sertraline 50mg', 'INS-34567-C', 'Referred to counseling');
SQLEOF

    echo "[+] Created SQLite database at $DB_PATH"
    echo "[+]   - 5 users with plaintext passwords"
    echo "[+]   - 5 SSNs stored unencrypted"
    echo "[+]   - 4 API keys stored in plaintext"
    echo "[+]   - 3 patient records (PHI) without encryption"
    cp "$DB_PATH" "$EVIDENCE_DIR/app-db-plaintext.db"
else
    echo "[WARN] sqlite3 not installed — creating CSV-based demonstration"

    cat > "$DATA_DIR/users.csv" << 'CSVEOF'
id,username,password,email,full_name,ssn,date_of_birth
1,jsmith,Welcome2024!,john.smith@anthra.local,John Smith,123-45-6789,1985-03-15
2,mjones,Password123,mary.jones@anthra.local,Mary Jones,234-56-7890,1990-07-22
3,admin,admin,admin@anthra.local,System Admin,345-67-8901,1978-11-08
4,bwilson,Qwerty!2024,bob.wilson@anthra.local,Bob Wilson,456-78-9012,1995-01-30
5,alee,Summer2024#,alice.lee@anthra.local,Alice Lee,567-89-0123,1988-09-14
CSVEOF

    echo "[+] Created CSV with plaintext passwords at $DATA_DIR/users.csv"
    cp "$DATA_DIR/users.csv" "$EVIDENCE_DIR/users-plaintext.csv"
fi
echo ""

# --- Create Config Files with Embedded Secrets ---

echo "[*] Creating application config files with embedded secrets..."

cat > "$DATA_DIR/app-config.yaml" << 'YAMLEOF'
# SC28-BREAK: Application configuration with embedded secrets
# DO NOT use in production — for security testing only

application:
  name: anthra-seclab
  environment: production

database:
  host: db.anthra.local
  port: 5432
  name: app_production
  username: app_user
  # VULNERABILITY: Database password in plaintext config
  password: "Pr0duction_DB_P@ss2024!"

redis:
  host: redis.anthra.local
  port: 6379
  # VULNERABILITY: Redis auth in plaintext config
  password: "R3dis_Auth_S3cret!"

smtp:
  host: smtp.anthra.local
  port: 587
  username: notifications@anthra.local
  # VULNERABILITY: SMTP credentials in plaintext config
  password: "Smtp_N0tify_2024"

api_keys:
  # VULNERABILITY: Third-party API keys in plaintext config
  stripe_secret: "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
  openai_key: "sk-proj-abcdefghijklmnopqrstuvwxyz123456"
  datadog_api_key: "abcdef1234567890abcdef1234567890"

encryption:
  # VULNERABILITY: Encryption disabled
  enabled: false
  algorithm: "none"
  at_rest: false
YAMLEOF

echo "[+] Wrote vulnerable config to $DATA_DIR/app-config.yaml"
cp "$DATA_DIR/app-config.yaml" "$EVIDENCE_DIR/app-config-insecure.yaml"

cat > "$DATA_DIR/.env" << 'ENVEOF'
# SC28-BREAK: Environment file with secrets (often committed to git)
# DO NOT use in production — for security testing only

DB_PASSWORD=Pr0duction_DB_P@ss2024!
REDIS_PASSWORD=R3dis_Auth_S3cret!
JWT_SECRET=super-secret-jwt-key-never-rotate
STRIPE_SECRET_KEY=sk_live_4eC39HqLyjWDarjtT1zdp7dc
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
ENCRYPTION_AT_REST=false
ENVEOF

echo "[+] Wrote vulnerable .env to $DATA_DIR/.env"
cp "$DATA_DIR/.env" "$EVIDENCE_DIR/dotenv-insecure.txt"
echo ""

# --- Disable Disk Encryption Check ---

echo "[*] Simulating disabled disk encryption..."

cat > "$DATA_DIR/disk-encryption-status.json" << 'JSONEOF'
{
  "_comment": "SC28-BREAK: Simulated disk encryption status",
  "volumes": [
    {
      "device": "/dev/sda1",
      "mount": "/",
      "filesystem": "ext4",
      "encrypted": false,
      "encryption_method": "none",
      "status": "UNPROTECTED"
    },
    {
      "device": "/dev/sda2",
      "mount": "/data",
      "filesystem": "ext4",
      "encrypted": false,
      "encryption_method": "none",
      "status": "UNPROTECTED"
    }
  ],
  "bitlocker_status": "disabled",
  "luks_status": "not_configured",
  "tpm_available": true,
  "tpm_used": false
}
JSONEOF

echo "[+] Wrote disk encryption status (all disabled) to $DATA_DIR/disk-encryption-status.json"
cp "$DATA_DIR/disk-encryption-status.json" "$EVIDENCE_DIR/disk-encryption-disabled.json"

# Check actual disk encryption status on the running system
echo ""
echo "[*] Checking actual disk encryption on this system..."

if command -v lsblk &>/dev/null; then
    CRYPT_DEVS=$(lsblk -o NAME,TYPE | grep -c "crypt" 2>/dev/null || echo "0")
    if [[ "$CRYPT_DEVS" -gt 0 ]]; then
        echo "[INFO] Found $CRYPT_DEVS encrypted volume(s) on this system"
    else
        echo "[ALERT] No encrypted volumes detected on this system"
    fi
    lsblk -o NAME,FSTYPE,SIZE,TYPE,MOUNTPOINT 2>/dev/null \
        | tee "$EVIDENCE_DIR/actual-disk-status.txt"
fi

# Windows BitLocker check (WSL environment)
if command -v manage-bde.exe &>/dev/null 2>/dev/null; then
    echo ""
    echo "[*] Checking BitLocker status (Windows host)..."
    manage-bde.exe -status C: 2>/dev/null \
        | tee "$EVIDENCE_DIR/bitlocker-status.txt" || echo "[INFO] Cannot access manage-bde (requires admin)"
elif [[ -f /proc/version ]] && grep -qi "microsoft" /proc/version 2>/dev/null; then
    echo "[INFO] WSL detected — BitLocker check requires elevated PowerShell on Windows host"
    echo "[INFO] Run: manage-bde -status C: (in admin PowerShell)"
fi

echo ""
echo "============================================"
echo "Break Summary"
echo "============================================"
echo ""
echo "[!] Data at rest is now UNPROTECTED:"
echo "[!]   - Database passwords: PLAINTEXT (no hashing)"
echo "[!]   - SSNs: PLAINTEXT (no column encryption)"
echo "[!]   - PHI/patient records: PLAINTEXT (HIPAA violation)"
echo "[!]   - API keys in database: PLAINTEXT"
echo "[!]   - Config file secrets: PLAINTEXT (database, Redis, SMTP, API keys)"
echo "[!]   - .env file: Contains all secrets in cleartext"
echo "[!]   - Disk encryption: DISABLED"
echo ""
echo "[*] This configuration is vulnerable to:"
echo "    - Database dump → all passwords readable without cracking"
echo "    - Config file read → all service credentials exposed"
echo "    - Disk theft → all data accessible without decryption"
echo "    - Backup exposure → unencrypted backups contain all secrets"
echo "    - SQL injection → plaintext passwords exfiltrated directly"
echo "    - HIPAA/PCI violation → per-record fines and breach notification"
echo ""
echo "[*] IBM 2024: Average cost per breached record: \$164 (global), \$185 (healthcare)"
echo "[*] 5 users + 3 patients + 4 API keys = 12 records minimum exposure"
echo ""
echo "[*] Run detect.sh to confirm the exposure, then fix.sh to remediate."
echo "[*] Evidence saved to: $EVIDENCE_DIR"
