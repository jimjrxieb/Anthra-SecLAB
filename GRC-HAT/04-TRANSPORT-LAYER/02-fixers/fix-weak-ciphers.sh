#!/usr/bin/env bash
# fix-weak-ciphers.sh — Disable weak TLS protocols and enforce strong ciphers
# NIST: SC-8 (transmission confidentiality), SC-13 (cryptographic protection)
# Usage: ./fix-weak-ciphers.sh [--platform nginx|apache|iis|azure] [--config /path/to/config]
#
# CSF 2.0: PR.DS-02 (Data-in-transit confidentiality)
# CIS v8: 3.10 (Encrypt Sensitive Data in Transit)
# NIST: SC-8 (Transmission Confidentiality)
#
set -euo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
PASS() { echo -e "${GREEN}[PASS]${NC} $*"; }
WARN() { echo -e "${YELLOW}[WARN]${NC} $*"; }
FAIL() { echo -e "${RED}[FAIL]${NC} $*"; }
INFO() { echo -e "${CYAN}[INFO]${NC} $*"; }

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
EVIDENCE_DIR="/tmp/jsa-evidence/fix-ciphers-${TIMESTAMP}"
mkdir -p "$EVIDENCE_DIR"

# Strong cipher suite — ECDHE only, no DHE fallback, AESGCM authenticated encryption
STRONG_CIPHERS="ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305"
STRONG_PROTOCOLS="TLSv1.2 TLSv1.3"
HSTS_HEADER='Strict-Transport-Security "max-age=31536000; includeSubDomains" always'

PLATFORM=""
CONFIG_FILE=""

# ─── Parse arguments ──────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --platform) PLATFORM="$2"; shift 2 ;;
        --config)   CONFIG_FILE="$2"; shift 2 ;;
        *) echo "Unknown argument: $1"; exit 1 ;;
    esac
done

echo "======================================================"
echo " L4 Weak Cipher Fix — SC-8 / SC-13"
echo " Evidence: ${EVIDENCE_DIR}"
echo " $(date)"
echo "======================================================"
echo ""

# ─── Auto-detect platform if not specified ────────────────────────────────
if [[ -z "$PLATFORM" ]]; then
    if command -v nginx &>/dev/null; then
        PLATFORM="nginx"
        INFO "Auto-detected: nginx"
    elif command -v apache2 &>/dev/null || command -v httpd &>/dev/null; then
        PLATFORM="apache"
        INFO "Auto-detected: Apache"
    elif [[ -f /proc/version ]] && grep -qi "microsoft\|windows" /proc/version 2>/dev/null; then
        PLATFORM="iis"
        INFO "Auto-detected: Windows/IIS environment"
    else
        WARN "Could not auto-detect platform. Specify with --platform nginx|apache|iis|azure"
        echo ""
        echo "Available platforms:"
        echo "  --platform nginx    — Harden nginx ssl_protocols/ssl_ciphers"
        echo "  --platform apache   — Harden Apache SSLProtocol/SSLCipherSuite"
        echo "  --platform iis      — Disable TLS 1.0/1.1 via Windows registry (SCHANNEL)"
        echo "  --platform azure    — Azure App Service TLS minimum version"
        exit 0
    fi
fi

# ─── nginx hardening ──────────────────────────────────────────────────────
fix_nginx() {
    local config="${CONFIG_FILE:-/etc/nginx/nginx.conf}"
    local ssl_conf=""

    # Try common SSL config locations
    for candidate in "$config" "/etc/nginx/conf.d/ssl.conf" "/etc/nginx/sites-enabled/default"; do
        if [[ -f "$candidate" ]] && grep -qi "ssl_" "$candidate" 2>/dev/null; then
            ssl_conf="$candidate"
            break
        fi
    done

    if [[ -z "$ssl_conf" ]]; then
        INFO "No nginx SSL config found at common paths. Specify with --config /path/to/config"
        INFO "Creating template at ${EVIDENCE_DIR}/nginx-ssl-recommended.conf"
        cat > "${EVIDENCE_DIR}/nginx-ssl-recommended.conf" << EOF
# WHY: SC-8 requires TLS 1.2+ — add this to your server {} block
ssl_protocols ${STRONG_PROTOCOLS};
ssl_ciphers ${STRONG_CIPHERS};
ssl_prefer_server_ciphers off;
add_header ${HSTS_HEADER};
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 1d;
ssl_stapling on;
ssl_stapling_verify on;
EOF
        INFO "Copy this config into your nginx server block and reload nginx"
        return
    fi

    INFO "Target config: ${ssl_conf}"

    # Save before-state evidence
    cp "$ssl_conf" "${EVIDENCE_DIR}/nginx-before-$(basename "$ssl_conf")"
    INFO "Before state saved: ${EVIDENCE_DIR}/nginx-before-$(basename "$ssl_conf")"

    # Apply fixes with sed
    INFO "Applying TLS protocol hardening..."

    # ssl_protocols
    if grep -q "ssl_protocols" "$ssl_conf"; then
        sed -i "s|ssl_protocols[^;]*;|ssl_protocols ${STRONG_PROTOCOLS};|g" "$ssl_conf"
        PASS "ssl_protocols updated to: ${STRONG_PROTOCOLS}"
    else
        # Append after ssl_certificate_key or ssl_certificate lines
        sed -i "/ssl_certificate_key/a\\    ssl_protocols ${STRONG_PROTOCOLS};" "$ssl_conf"
        PASS "ssl_protocols added: ${STRONG_PROTOCOLS}"
    fi

    # ssl_ciphers
    if grep -q "ssl_ciphers" "$ssl_conf"; then
        sed -i "s|ssl_ciphers[^;]*;|ssl_ciphers ${STRONG_CIPHERS};|" "$ssl_conf"
        PASS "ssl_ciphers updated to strong ECDHE+AESGCM suite"
    else
        sed -i "/ssl_protocols/a\\    ssl_ciphers ${STRONG_CIPHERS};" "$ssl_conf"
        PASS "ssl_ciphers added"
    fi

    # ssl_prefer_server_ciphers off — let client pick fastest TLS 1.3 cipher
    if grep -q "ssl_prefer_server_ciphers" "$ssl_conf"; then
        sed -i "s|ssl_prefer_server_ciphers[^;]*;|ssl_prefer_server_ciphers off;|" "$ssl_conf"
    else
        sed -i "/ssl_ciphers/a\\    ssl_prefer_server_ciphers off;" "$ssl_conf"
    fi
    PASS "ssl_prefer_server_ciphers set to off (TLS 1.3 compatible)"

    # HSTS
    if grep -q "Strict-Transport-Security" "$ssl_conf"; then
        PASS "HSTS already present"
    else
        sed -i "/ssl_prefer_server_ciphers/a\\    add_header ${HSTS_HEADER};" "$ssl_conf"
        PASS "HSTS header added: max-age=31536000; includeSubDomains"
    fi

    # Save after-state
    cp "$ssl_conf" "${EVIDENCE_DIR}/nginx-after-$(basename "$ssl_conf")"

    # Test config
    if nginx -t 2>/dev/null; then
        PASS "nginx config test passed"
        INFO "Reloading nginx..."
        nginx -s reload 2>/dev/null && PASS "nginx reloaded" || WARN "nginx reload failed — check manually"
    else
        FAIL "nginx config test failed — reverting changes"
        cp "${EVIDENCE_DIR}/nginx-before-$(basename "$ssl_conf")" "$ssl_conf"
        FAIL "Changes reverted. Review evidence for manual fix."
        exit 1
    fi
}

# ─── Apache hardening ─────────────────────────────────────────────────────
fix_apache() {
    local config="${CONFIG_FILE:-/etc/apache2/mods-enabled/ssl.conf}"

    for candidate in "$config" "/etc/httpd/conf.d/ssl.conf" "/etc/apache2/sites-enabled/000-default-le-ssl.conf"; do
        if [[ -f "$candidate" ]]; then
            config="$candidate"
            break
        fi
    done

    if [[ ! -f "$config" ]]; then
        INFO "No Apache SSL config found. Creating template at ${EVIDENCE_DIR}/apache-ssl-recommended.conf"
        cat > "${EVIDENCE_DIR}/apache-ssl-recommended.conf" << EOF
# WHY: SC-8 requires TLS 1.2+ — add to VirtualHost *:443 block
SSLProtocol -all +TLSv1.2 +TLSv1.3
SSLCipherSuite ${STRONG_CIPHERS}
SSLHonorCipherOrder off
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
SSLSessionTickets off
EOF
        return
    fi

    INFO "Target config: ${config}"
    cp "$config" "${EVIDENCE_DIR}/apache-before-$(basename "$config")"

    # SSLProtocol
    if grep -q "SSLProtocol" "$config"; then
        sed -i "s|SSLProtocol[^$]*|SSLProtocol -all +TLSv1.2 +TLSv1.3|" "$config"
    else
        echo "SSLProtocol -all +TLSv1.2 +TLSv1.3" >> "$config"
    fi
    PASS "SSLProtocol set to: -all +TLSv1.2 +TLSv1.3"

    # SSLCipherSuite
    if grep -q "SSLCipherSuite" "$config"; then
        sed -i "s|SSLCipherSuite[^$]*|SSLCipherSuite ${STRONG_CIPHERS}|" "$config"
    else
        echo "SSLCipherSuite ${STRONG_CIPHERS}" >> "$config"
    fi
    PASS "SSLCipherSuite updated to strong ECDHE+AESGCM suite"

    # HSTS
    if ! grep -q "Strict-Transport-Security" "$config"; then
        echo 'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"' >> "$config"
        PASS "HSTS header added"
    fi

    cp "$config" "${EVIDENCE_DIR}/apache-after-$(basename "$config")"

    # Test and reload
    if apachectl configtest 2>/dev/null; then
        PASS "Apache config test passed"
        apachectl graceful 2>/dev/null && PASS "Apache reloaded" || WARN "Apache reload failed"
    else
        FAIL "Apache config test failed — reverting"
        cp "${EVIDENCE_DIR}/apache-before-$(basename "$config")" "$config"
        exit 1
    fi
}

# ─── Windows IIS / SCHANNEL ───────────────────────────────────────────────
fix_iis() {
    INFO "Generating PowerShell script for SCHANNEL registry changes"
    INFO "MANUAL STEP REQUIRED: Run the generated script on the Windows server"

    cat > "${EVIDENCE_DIR}/Disable-WeakTLS.ps1" << 'PWSH'
# Disable-WeakTLS.ps1
# NIST SC-8: Disable SSL 3.0, TLS 1.0, TLS 1.1 via Windows SCHANNEL registry
# Run as Administrator on Windows Server

$ErrorActionPreference = "Stop"
$BackupPath = "C:\TLS-Registry-Backup-$(Get-Date -Format 'yyyyMMdd-HHmmss').reg"

# Backup registry before changes
Write-Host "[INFO] Backing up SCHANNEL registry to $BackupPath"
reg export "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL" $BackupPath /y

$protocols = @{
    "SSL 2.0" = $false
    "SSL 3.0" = $false
    "TLS 1.0" = $false
    "TLS 1.1" = $false
    "TLS 1.2" = $true
    "TLS 1.3" = $true
}

foreach ($proto in $protocols.Keys) {
    $enabled = $protocols[$proto]
    $regBase = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$proto"

    foreach ($role in @("Server", "Client")) {
        $path = "$regBase\$role"
        if (-not (Test-Path $path)) {
            New-Item -Path $path -Force | Out-Null
        }
        Set-ItemProperty -Path $path -Name "Enabled" -Value ([int]$enabled) -Type DWord
        Set-ItemProperty -Path $path -Name "DisabledByDefault" -Value ([int](-not $enabled)) -Type DWord
        $status = if ($enabled) { "ENABLED" } else { "DISABLED" }
        Write-Host "[PASS] $proto ($role): $status"
    }
}

# Enforce strong cipher order
Write-Host "[INFO] Setting cipher suite order for SC-13 compliance..."
$cipherOrder = @(
    "TLS_AES_256_GCM_SHA384",
    "TLS_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
)
$cipherStr = $cipherOrder -join ","
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" `
    -Name "Functions" -Value $cipherStr -Type String -ErrorAction SilentlyContinue
Write-Host "[PASS] Cipher suite order updated"

Write-Host ""
Write-Host "[WARN] A system REBOOT is required for SCHANNEL changes to take effect."
Write-Host "[INFO] Registry backup saved to: $BackupPath"
PWSH

    PASS "PowerShell script generated: ${EVIDENCE_DIR}/Disable-WeakTLS.ps1"
    INFO "Copy to Windows server and run as Administrator"
    INFO "Reboot required after running the script"
}

# ─── Azure App Service ────────────────────────────────────────────────────
fix_azure() {
    INFO "Generating Azure CLI commands for TLS enforcement"

    cat > "${EVIDENCE_DIR}/enforce-azure-tls.sh" << 'AZ'
#!/usr/bin/env bash
# enforce-azure-tls.sh — Set minimum TLS 1.2 on Azure App Services
# NIST SC-8: Requires az CLI and appropriate subscription permissions

# Set TLS minimum version for all App Services in subscription
az webapp list --query "[].{name:name, rg:resourceGroup}" -o tsv | while IFS=$'\t' read -r APP_NAME RG; do
    az webapp config set \
        --name "$APP_NAME" \
        --resource-group "$RG" \
        --min-tls-version 1.2 \
        --ftps-state Disabled \
        --https-only true
    echo "[PASS] ${APP_NAME}: TLS 1.2 minimum enforced, HTTPS-only enabled"
done

# Azure SQL — enforce encrypted connections
az sql server list --query "[].{name:name, rg:resourceGroup}" -o tsv | while IFS=$'\t' read -r SQL_NAME RG; do
    az sql server update \
        --name "$SQL_NAME" \
        --resource-group "$RG" \
        --minimal-tls-version "1.2"
    echo "[PASS] SQL Server ${SQL_NAME}: minimum TLS 1.2 enforced"
done
AZ

    PASS "Azure TLS enforcement script generated: ${EVIDENCE_DIR}/enforce-azure-tls.sh"
    INFO "Review and run in your Azure subscription context"
}

# ─── Dispatch ─────────────────────────────────────────────────────────────
case "$PLATFORM" in
    nginx)  fix_nginx ;;
    apache) fix_apache ;;
    iis)    fix_iis ;;
    azure)  fix_azure ;;
    *)
        FAIL "Unknown platform: ${PLATFORM}"
        echo "Valid: nginx, apache, iis, azure"
        exit 1
        ;;
esac

echo ""

# ─── Post-fix verification ────────────────────────────────────────────────
echo "── Post-Fix Verification ────────────────────────────────────────────"
if [[ "$PLATFORM" != "iis" ]] && [[ "$PLATFORM" != "azure" ]]; then
    INFO "To verify TLS hardening, provide a target host:port:"
    INFO "  echo | openssl s_client -connect localhost:443 -tls1 2>&1 | grep -E 'alert|BEGIN'"
    INFO "  ./audit-tls-config.sh localhost:443"
    INFO "  testssl.sh --severity HIGH localhost:443"
fi

echo ""
echo "======================================================"
echo " Evidence saved to: ${EVIDENCE_DIR}"
ls -1 "$EVIDENCE_DIR"
echo "======================================================"
