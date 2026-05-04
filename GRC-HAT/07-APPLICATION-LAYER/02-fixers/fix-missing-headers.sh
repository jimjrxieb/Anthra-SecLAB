#!/usr/bin/env bash
# fix-missing-headers.sh — Add security headers to web applications
# NIST: SI-10 (information input validation), SC-8 (transmission confidentiality/integrity)
# Usage: ./fix-missing-headers.sh [--nginx | --apache | --express] [--dry-run]
#
# CSF 2.0: PR.PS-01 (Configuration management applied)
# CIS v8: 16.12 (Implement Code-Level Security Checks)
# NIST: SI-10 (Information Input Validation)
#
set -euo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'; NC='\033[0m'
PASS() { echo -e "${GREEN}[PASS]${NC} $*"; }
WARN() { echo -e "${YELLOW}[WARN]${NC} $*"; }
FAIL() { echo -e "${RED}[FAIL]${NC} $*"; }
INFO() { echo -e "       $*"; }
SECTION() { echo -e "\n${BLUE}═══ $* ═══${NC}"; }

PLATFORM="${1:-detect}"
DRY_RUN=false
[[ "${2:-}" == "--dry-run" || "${1:-}" == "--dry-run" ]] && DRY_RUN=true
[[ "${2:-}" == "--dry-run" ]] && PLATFORM="${1:-detect}"
[[ "${1:-}" == "--dry-run" ]] && PLATFORM="detect"

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
EVIDENCE_DIR="/tmp/jsa-evidence/missing-headers-${TIMESTAMP}"
mkdir -p "$EVIDENCE_DIR"

# Required security headers and their values
declare -A SECURITY_HEADERS=(
    ["X-Content-Type-Options"]="nosniff"
    ["X-Frame-Options"]="DENY"
    ["X-XSS-Protection"]="1; mode=block"
    ["Strict-Transport-Security"]="max-age=31536000; includeSubDomains; preload"
    ["Content-Security-Policy"]="default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
    ["Referrer-Policy"]="strict-origin-when-cross-origin"
    ["Permissions-Policy"]="geolocation=(), microphone=(), camera=(), payment=(), usb=()"
)

echo "======================================================"
echo " Security Headers Remediation — SI-10 / SC-8"
echo " Platform: ${PLATFORM}"
echo " Dry run: ${DRY_RUN}"
echo " Evidence: ${EVIDENCE_DIR}"
echo " $(date)"
echo "======================================================"
echo ""

FIXES=0

# ─── Auto-detect platform ─────────────────────────────────────────────────────
if [[ "$PLATFORM" == "detect" ]]; then
    if command -v nginx &>/dev/null || systemctl is-active nginx &>/dev/null 2>&1; then
        PLATFORM="--nginx"
        PASS "Detected: nginx"
    elif command -v apache2 &>/dev/null || command -v httpd &>/dev/null || systemctl is-active apache2 &>/dev/null 2>&1; then
        PLATFORM="--apache"
        PASS "Detected: Apache"
    elif [[ -f "package.json" ]] && grep -q '"express"' package.json 2>/dev/null; then
        PLATFORM="--express"
        PASS "Detected: Express.js (package.json)"
    else
        WARN "Could not auto-detect platform"
        echo "Usage: $0 [--nginx | --apache | --express] [--dry-run]"
        echo ""
        echo "Available platforms:"
        echo "  --nginx    Add security headers to nginx.conf"
        echo "  --apache   Add security headers to Apache config"
        echo "  --express  Add helmet.js security headers to Express app"
        exit 1
    fi
fi

# ─── Check current headers ────────────────────────────────────────────────────
check_headers() {
    local URL="${1:-http://localhost}"
    echo "Checking current headers on $URL..."
    if command -v curl &>/dev/null; then
        curl -sk -I "$URL" 2>/dev/null > "$EVIDENCE_DIR/headers-before.txt" || true
        echo "Current headers:"
        for HEADER in "${!SECURITY_HEADERS[@]}"; do
            if grep -qi "$HEADER" "$EVIDENCE_DIR/headers-before.txt" 2>/dev/null; then
                PASS "Present: $HEADER"
            else
                WARN "Missing: $HEADER"
            fi
        done
    fi
}

check_headers "${CHECK_URL:-http://localhost}"

# ─── nginx ────────────────────────────────────────────────────────────────────
if [[ "$PLATFORM" == "--nginx" ]]; then
    SECTION "nginx Security Headers"

    NGINX_CONF_D="/etc/nginx/conf.d"
    HEADERS_CONF="${NGINX_CONF_D}/security-headers.conf"

    HEADERS_CONTENT="# Security Headers — JSA AppSec remediation — $(date)
# NIST: SI-10 (input validation), SC-8 (transmission integrity)
# Each header maps to a specific attack class

# Prevents MIME-type sniffing (content injection attacks)
add_header X-Content-Type-Options    'nosniff' always;

# Prevents clickjacking (UI redress attacks)
add_header X-Frame-Options           'DENY' always;

# Legacy XSS filter (Chrome/IE/Safari — deprecated but still checked by auditors)
add_header X-XSS-Protection          '1; mode=block' always;

# Forces HTTPS for 1 year, including subdomains (HSTS)
# WARNING: Test in staging first — this cannot be easily undone
add_header Strict-Transport-Security 'max-age=31536000; includeSubDomains; preload' always;

# Controls what resources the browser is allowed to load (prevents XSS exfil)
add_header Content-Security-Policy   \"default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'\" always;

# Controls referrer information (privacy + info disclosure)
add_header Referrer-Policy           'strict-origin-when-cross-origin' always;

# Restricts browser features (prevents sensor abuse via web APIs)
add_header Permissions-Policy        'geolocation=(), microphone=(), camera=(), payment=(), usb=()' always;

# Remove server information (reduces attack surface fingerprinting)
server_tokens off;
"

    if $DRY_RUN; then
        WARN "DRY RUN — would write to $HEADERS_CONF:"
        echo "$HEADERS_CONTENT"
    else
        if [[ -f "$HEADERS_CONF" ]]; then
            cp "$HEADERS_CONF" "$EVIDENCE_DIR/$(basename $HEADERS_CONF).before"
            WARN "Existing security headers config backed up"
        fi

        if [[ ! -d "$NGINX_CONF_D" ]]; then
            FAIL "nginx conf.d directory not found: $NGINX_CONF_D"
            INFO "Is nginx installed? Try: apt install nginx or yum install nginx"
            exit 1
        fi

        echo "$HEADERS_CONTENT" > "$HEADERS_CONF"
        PASS "Security headers config written: $HEADERS_CONF"
        FIXES=$((FIXES + 1))

        # Test config before reload
        if nginx -t 2>/dev/null; then
            PASS "nginx config test passed"
            systemctl reload nginx && PASS "nginx reloaded" || WARN "nginx reload failed — check logs"
        else
            FAIL "nginx config test failed — reverting"
            [[ -f "$EVIDENCE_DIR/$(basename $HEADERS_CONF).before" ]] && \
                cp "$EVIDENCE_DIR/$(basename $HEADERS_CONF).before" "$HEADERS_CONF"
            exit 1
        fi
    fi
fi

# ─── Apache ───────────────────────────────────────────────────────────────────
if [[ "$PLATFORM" == "--apache" ]]; then
    SECTION "Apache Security Headers"

    APACHE_CONF_AVAIL="/etc/apache2/conf-available"
    APACHE_CONF_ENABLED="/etc/apache2/conf-enabled"
    HEADERS_CONF="${APACHE_CONF_AVAIL}/security-headers.conf"

    HEADERS_CONTENT="# Security Headers — JSA AppSec remediation — $(date)
# NIST: SI-10 (input validation), SC-8 (transmission integrity)
# Requires: mod_headers (a2enmod headers)

<IfModule mod_headers.c>
    # Prevents MIME-type sniffing
    Header always set X-Content-Type-Options     \"nosniff\"

    # Prevents clickjacking
    Header always set X-Frame-Options            \"DENY\"

    # Legacy XSS filter
    Header always set X-XSS-Protection           \"1; mode=block\"

    # HSTS — forces HTTPS for 1 year
    Header always set Strict-Transport-Security  \"max-age=31536000; includeSubDomains; preload\"

    # Content Security Policy
    Header always set Content-Security-Policy    \"default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'\"

    # Referrer policy
    Header always set Referrer-Policy            \"strict-origin-when-cross-origin\"

    # Permissions policy
    Header always set Permissions-Policy         \"geolocation=(), microphone=(), camera=(), payment=(), usb=()\"

    # Remove Apache server signature
    ServerSignature Off
    ServerTokens Prod
</IfModule>
"

    if $DRY_RUN; then
        WARN "DRY RUN — would write to $HEADERS_CONF:"
        echo "$HEADERS_CONTENT"
    else
        # Enable mod_headers
        a2enmod headers 2>/dev/null && PASS "mod_headers enabled" || WARN "mod_headers may already be enabled"

        echo "$HEADERS_CONTENT" > "$HEADERS_CONF"
        PASS "Security headers config written: $HEADERS_CONF"

        # Enable the config
        ln -sf "$HEADERS_CONF" "${APACHE_CONF_ENABLED}/security-headers.conf" 2>/dev/null || \
            a2enconf security-headers 2>/dev/null || \
            WARN "Could not enable config — manual: a2enconf security-headers"

        # Test and reload
        apache2ctl configtest 2>/dev/null && \
            systemctl reload apache2 && \
            PASS "Apache reloaded with security headers" || \
            WARN "Apache reload failed — check apache2ctl configtest"
        FIXES=$((FIXES + 1))
    fi
fi

# ─── Express.js ───────────────────────────────────────────────────────────────
if [[ "$PLATFORM" == "--express" ]]; then
    SECTION "Express.js Security Headers (helmet.js)"

    INFO "Express.js security headers via helmet.js"
    INFO "helmet.js covers all OWASP recommended headers in one package"
    echo ""

    # Check if helmet is installed
    if [[ -f "package.json" ]]; then
        if grep -q '"helmet"' package.json 2>/dev/null; then
            PASS "helmet.js already in package.json"
        else
            if $DRY_RUN; then
                WARN "DRY RUN — would run: npm install helmet"
            else
                npm install helmet --save && PASS "helmet.js installed" || FAIL "npm install helmet failed"
                FIXES=$((FIXES + 1))
            fi
        fi
    fi

    # Generate helmet configuration snippet
    HELMET_SNIPPET="// Security headers via helmet.js
// NIST: SI-10 (input validation), SC-8 (transmission integrity)
// Install: npm install helmet
const helmet = require('helmet');

// Apply all default helmet headers + custom CSP
app.use(helmet({
    // Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    },
    // Content-Security-Policy
    contentSecurityPolicy: {
        directives: {
            defaultSrc: [\"'self'\"],
            scriptSrc: [\"'self'\"],
            objectSrc: [\"'none'\"],
            baseUri: [\"'self'\"],
            frameAncestors: [\"'none'\"]
        }
    },
    // X-Frame-Options: DENY (also covered by CSP frameAncestors)
    frameguard: { action: 'deny' },
    // X-Content-Type-Options: nosniff
    noSniff: true,
    // X-XSS-Protection: 1; mode=block (legacy — helmet disables this for modern browsers)
    xssFilter: true,
    // Referrer-Policy: strict-origin-when-cross-origin
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
}));"

    echo "$HELMET_SNIPPET" > "$EVIDENCE_DIR/helmet-snippet.js"
    PASS "Helmet configuration snippet saved to $EVIDENCE_DIR/helmet-snippet.js"
    echo ""
    echo "$HELMET_SNIPPET"
    echo ""
    INFO "Add this snippet to your app.js/server.js BEFORE route definitions"
fi

# ─── Verify Headers ───────────────────────────────────────────────────────────
if ! $DRY_RUN && [[ $FIXES -gt 0 ]]; then
    SECTION "Verification"
    sleep 2
    check_headers "${CHECK_URL:-http://localhost}"

    if command -v curl &>/dev/null; then
        curl -sk -I "${CHECK_URL:-http://localhost}" 2>/dev/null > "$EVIDENCE_DIR/headers-after.txt" || true
        diff "$EVIDENCE_DIR/headers-before.txt" "$EVIDENCE_DIR/headers-after.txt" > "$EVIDENCE_DIR/headers.diff" 2>/dev/null || true
        INFO "Header diff saved to $EVIDENCE_DIR/headers.diff"
    fi
fi

echo ""
echo "======================================================"
echo " Security Headers Remediation Complete"
echo " Fixes applied: $FIXES"
echo " Evidence: ${EVIDENCE_DIR}"
echo "======================================================"

{
    echo "timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "action: fix-missing-headers"
    echo "platform: $PLATFORM"
    echo "dry_run: $DRY_RUN"
    echo "fixes: $FIXES"
    echo "evidence_dir: $EVIDENCE_DIR"
} > "$EVIDENCE_DIR/fix-summary.txt"
