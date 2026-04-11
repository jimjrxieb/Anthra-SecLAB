# fix-tls-custom-check.md — Custom TLS Compliance Checks

**NIST Controls:** SC-8 (Transmission Confidentiality), SC-13 (Cryptographic Protection)
**Use Case:** Build custom TLS checks for CI gates, scheduled audits, or client-specific cipher requirements

---

## Overview

Standard scanners give you a grade. Custom checks give you a pass/fail gate that blocks deployment when
TLS requirements are not met. This guide shows how to build CI-grade TLS gates using testssl.sh,
OpenSSL, and nmap.

---

## 1. CI Gate: Fail Build if TLS 1.0 Accepted

The simplest gate. If the target accepts TLS 1.0, the build fails.

```bash
#!/usr/bin/env bash
# ci-tls-gate.sh — Fail CI if target accepts TLS 1.0
# Usage: ./ci-tls-gate.sh example.com:443
set -euo pipefail

TARGET="${1:?Usage: $0 host:port}"

# WHY: SC-8 requires cryptographic protection. TLS 1.0 is prohibited
# by PCI DSS 3.2.1+ and deprecated by RFC 8996.
if echo | openssl s_client -connect "$TARGET" -tls1 2>&1 | grep -q "BEGIN CERTIFICATE"; then
    echo "FAIL: Target accepts TLS 1.0 — SC-8 violation"
    exit 1
fi
echo "PASS: TLS 1.0 rejected"
```

**Add to CI pipeline (GitHub Actions example):**

```yaml
- name: TLS Gate
  run: |
    chmod +x ./ci-tls-gate.sh
    ./ci-tls-gate.sh ${{ env.APP_HOST }}:443
```

---

## 2. Full Protocol Gate (TLS 1.0, 1.1, SSLv3)

```bash
#!/usr/bin/env bash
# ci-tls-full-gate.sh — Check all weak protocols
set -euo pipefail

TARGET="${1:?Usage: $0 host:port}"
FAILED=0

check_protocol() {
    local flag="$1"
    local label="$2"
    if echo | openssl s_client -connect "$TARGET" "$flag" 2>&1 | grep -q "BEGIN CERTIFICATE"; then
        echo "FAIL: ${label} accepted — SC-8 violation"
        FAILED=1
    else
        echo "PASS: ${label} rejected"
    fi
}

check_protocol "-ssl3"   "SSLv3"
check_protocol "-tls1"   "TLS 1.0"
check_protocol "-tls1_1" "TLS 1.1"

# Verify TLS 1.2 still works
if ! echo | openssl s_client -connect "$TARGET" -tls1_2 2>&1 | grep -q "BEGIN CERTIFICATE"; then
    echo "FAIL: TLS 1.2 not supported — no acceptable protocol"
    FAILED=1
else
    echo "PASS: TLS 1.2 supported"
fi

exit $FAILED
```

---

## 3. testssl.sh: Specific Cipher Requirements

testssl.sh gives far more detail than openssl s_client. Use it for deep dives.

### Install

```bash
git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl
chmod +x /opt/testssl/testssl.sh
```

### Useful flags

```bash
# Check only HIGH and CRITICAL severity findings
/opt/testssl/testssl.sh --severity HIGH example.com:443

# Show which ciphers are accepted per protocol
/opt/testssl/testssl.sh --cipher-per-proto example.com:443

# Export-grade cipher check (FREAK/LOGJAM)
/opt/testssl/testssl.sh --vulnerable example.com:443

# JSON output for parsing in CI
/opt/testssl/testssl.sh --jsonfile /tmp/testssl-results.json example.com:443

# Check specific cipher
/opt/testssl/testssl.sh --openssl-cmd "openssl s_client -connect example.com:443 -cipher RC4-SHA"
```

### CI gate using testssl.sh JSON output

```bash
#!/usr/bin/env bash
# testssl-ci-gate.sh — Fail if HIGH+ findings
set -euo pipefail

TARGET="${1:?Usage: $0 host:port}"
RESULTS="/tmp/testssl-$(date +%s).json"

/opt/testssl/testssl.sh --jsonfile "$RESULTS" --severity HIGH --quiet "$TARGET"

HIGH_COUNT=$(python3 -c "
import json, sys
data = json.load(open('$RESULTS'))
findings = [f for f in data.get('findings',[]) if f.get('severity') in ('HIGH','CRITICAL')]
print(len(findings))
for f in findings:
    print(f'  {f[\"severity\"]}: {f[\"id\"]} - {f[\"finding\"]}', file=sys.stderr)
" 2>&1)

if [[ "$HIGH_COUNT" -gt 0 ]]; then
    echo "FAIL: ${HIGH_COUNT} HIGH/CRITICAL TLS findings"
    exit 1
fi
echo "PASS: No HIGH+ severity TLS findings"
```

---

## 4. Custom Cipher List Check

Verify only your approved ciphers are accepted.

```bash
#!/usr/bin/env bash
# check-approved-ciphers.sh — Verify no unapproved ciphers accepted
set -euo pipefail

TARGET="${1:?Usage: $0 host:port}"

# WHY SC-13: Only FIPS-compatible ECDHE+AESGCM ciphers allowed
APPROVED_CIPHERS=(
    "ECDHE-ECDSA-AES128-GCM-SHA256"
    "ECDHE-RSA-AES128-GCM-SHA256"
    "ECDHE-ECDSA-AES256-GCM-SHA384"
    "ECDHE-RSA-AES256-GCM-SHA384"
    "ECDHE-ECDSA-CHACHA20-POLY1305"
    "ECDHE-RSA-CHACHA20-POLY1305"
)

UNAPPROVED_CIPHERS=(
    "RC4-SHA"
    "RC4-MD5"
    "DES-CBC3-SHA"
    "AES128-SHA"           # No forward secrecy
    "AES256-SHA"           # No forward secrecy
    "DHE-RSA-AES128-SHA"   # CBC mode — BEAST/POODLE exposure
    "ECDHE-RSA-AES128-SHA" # CBC mode
)

FAILED=0
for cipher in "${UNAPPROVED_CIPHERS[@]}"; do
    RESULT=$(echo | openssl s_client -connect "$TARGET" -cipher "$cipher" 2>&1 || true)
    if echo "$RESULT" | grep -q "BEGIN CERTIFICATE"; then
        echo "FAIL: Unapproved cipher accepted: ${cipher}"
        FAILED=1
    else
        echo "PASS: ${cipher} rejected"
    fi
done

exit $FAILED
```

---

## 5. nmap ssl-enum-ciphers Alternative

Use when openssl s_client is unavailable or for network-level scanning.

```bash
# Install: apt-get install nmap
# List all accepted ciphers with strength grades
nmap --script ssl-enum-ciphers -p 443 example.com

# Save output for evidence
nmap --script ssl-enum-ciphers -p 443 example.com -oN /tmp/nmap-tls-$(date +%Y%m%d).txt

# Flag weak ciphers (grade C or below)
nmap --script ssl-enum-ciphers -p 443 example.com | grep -E "^\s+[C-F]|weak|WEAK"
```

### nmap output interpretation

```
|   TLSv1.2:
|     ciphers:
|       TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (secp256r1) - A   ← PASS
|       TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (secp384r1) - A   ← PASS
|       TLS_RSA_WITH_AES_128_CBC_SHA (rsa 2048)           - C   ← WARN: no PFS
|       TLS_RSA_WITH_RC4_128_SHA     (rsa 2048)           - F   ← FAIL: RC4
```

Grade A = approved. Grade B or below = investigate. Grade F = immediate remediation.

---

## 6. HSTS Preload Check

```bash
# Check if HSTS is set with correct max-age for preload eligibility
check_hsts_preload() {
    local host="$1"
    local headers
    headers=$(curl -sI "https://${host}" 2>/dev/null)
    local hsts
    hsts=$(echo "$headers" | grep -i "strict-transport-security" || echo "MISSING")
    local max_age
    max_age=$(echo "$hsts" | grep -oP 'max-age=\K\d+' || echo 0)

    echo "HSTS: $hsts"
    [[ "$max_age" -ge 31536000 ]] && echo "PASS: max-age >= 1 year" || echo "WARN: max-age < 1 year"
    echo "$hsts" | grep -q "includeSubDomains" && echo "PASS: includeSubDomains" || echo "WARN: missing includeSubDomains"
    echo "$hsts" | grep -q "preload" && echo "PASS: preload directive" || echo "INFO: preload not set (optional)"
}
```

---

## Extending for Custom Requirements

To add a check for a new cipher or protocol requirement:

1. Add the cipher to `UNAPPROVED_CIPHERS` in `check-approved-ciphers.sh`
2. Use `-cipher` flag with `openssl s_client` to test
3. Exit 1 on match to gate CI pipelines
4. Log evidence to `/tmp/jsa-evidence/` for audit trail

For protocol requirements, use the `-tls1`, `-tls1_1`, `-tls1_2`, `-tls1_3`, `-ssl3` flags with `openssl s_client`.
