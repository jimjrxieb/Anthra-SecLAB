# 02-fix-SC8-tls.md — TLS Hardening: SC-8 and SC-13 Remediation

| Field | Value |
|---|---|
| **NIST Controls** | SC-8, SC-13 |
| **Tools** | nginx, Apache, IIS (PowerShell), az CLI, OpenSSL |
| **Fixer Script** | `02-fixers/fix-weak-ciphers.sh` |
| **Time** | 30–60 minutes |
| **Rank** | D (E for config changes; D for verification) |

---

## When to Use This

Run this playbook when `01-assess.md` or `01a-tls-audit.md` finds:
- SSLv3, TLS 1.0, or TLS 1.1 accepted
- Weak cipher suites (RC4, DES, 3DES, CBC mode, NULL, EXPORT)
- Missing HSTS header
- ssl_prefer_server_ciphers on (should be off for TLS 1.3)

---

## Automated Fix

For most environments, run the fixer script directly:

```bash
# Auto-detect platform and apply fixes
./02-fixers/fix-weak-ciphers.sh

# Specify platform explicitly
./02-fixers/fix-weak-ciphers.sh --platform nginx
./02-fixers/fix-weak-ciphers.sh --platform apache
./02-fixers/fix-weak-ciphers.sh --platform iis
./02-fixers/fix-weak-ciphers.sh --platform azure
```

The script:
1. Saves before-state evidence
2. Applies cipher list from `03-templates/tls/nginx-tls.conf` (or equivalent)
3. Tests config before reloading
4. Reverts automatically if config test fails

---

## Manual: nginx TLS Hardening

Use when you need to apply changes to a specific config file.

### Before state (save this)
```bash
grep -E "ssl_protocols|ssl_ciphers|ssl_prefer_server|Strict-Transport" /etc/nginx/nginx.conf
```

### Apply from template

```bash
# Copy template to nginx conf.d
cp 03-templates/tls/nginx-tls.conf /etc/nginx/conf.d/tls-hardening.conf

# Add to your server {} block if not using include:
# include /etc/nginx/conf.d/tls-hardening.conf;

# Test and reload
nginx -t && nginx -s reload
```

### Manual changes (if not using template file)

```bash
# Edit your nginx SSL config
# Change or add these lines in your server {} block:

ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
ssl_prefer_server_ciphers off;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

# Test and reload
nginx -t && nginx -s reload
```

---

## Manual: Apache TLS Hardening

```bash
# Edit /etc/apache2/mods-enabled/ssl.conf or /etc/httpd/conf.d/ssl.conf

SSLProtocol -all +TLSv1.2 +TLSv1.3
SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305
SSLHonorCipherOrder off
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
SSLSessionTickets off

# Enable ssl and headers modules if not already
a2enmod ssl headers
apachectl configtest && apachectl graceful
```

---

## Windows IIS / SCHANNEL

The fixer script generates a PowerShell script for IIS. Apply it on the Windows server:

```bash
# Generate the PowerShell script
./02-fixers/fix-weak-ciphers.sh --platform iis
# Script saved to: /tmp/jsa-evidence/fix-ciphers-TIMESTAMP/Disable-WeakTLS.ps1
```

Copy `Disable-WeakTLS.ps1` to the Windows server and run as Administrator:

```powershell
# On Windows Server — run as Administrator
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
.\Disable-WeakTLS.ps1
# REBOOT REQUIRED after running
```

---

## Azure — az CLI

```bash
# App Services: enforce TLS 1.2 minimum
./02-fixers/fix-weak-ciphers.sh --platform azure

# Or directly with az CLI:
az webapp config set \
  --name myapp \
  --resource-group myRG \
  --min-tls-version 1.2 \
  --https-only true

# Azure SQL
az sql server update \
  --name mySqlServer \
  --resource-group myRG \
  --minimal-tls-version "1.2"

# Storage
az storage account update \
  --name mystorageaccount \
  --resource-group myRG \
  --https-only true \
  --min-tls-version TLS1_2
```

See `03-templates/defender-cloud/tls-policy.md` for full Defender for Cloud remediation.

---

## Add HSTS to Kubernetes Ingress

If HSTS is missing from your Kubernetes ingress:

```yaml
# nginx ingress controller annotation
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: my-ingress
  annotations:
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
    nginx.ingress.kubernetes.io/configuration-snippet: |
      more_set_headers "Strict-Transport-Security: max-age=31536000; includeSubDomains";
```

---

## Verification

After applying changes, verify with:

```bash
# Test weak protocols are rejected
echo | openssl s_client -connect HOST:PORT -tls1 2>&1 | grep -E "alert|BEGIN CERT"
# Expected: "alert handshake failure" or "no peer certificate"

echo | openssl s_client -connect HOST:PORT -tls1_1 2>&1 | grep -E "alert|BEGIN CERT"
# Expected: rejection

# Test TLS 1.2 still works
echo | openssl s_client -connect HOST:PORT -tls1_2 2>&1 | grep "BEGIN CERT"
# Expected: "-----BEGIN CERTIFICATE-----"

# Check HSTS
curl -sI https://HOST:PORT | grep -i "strict-transport"
# Expected: strict-transport-security: max-age=31536000; includeSubDomains

# Run full auditor
./01-auditors/audit-tls-config.sh HOST:PORT
```

---

## Next Steps

- Certificate lifecycle issues: `02a-fix-IA5-certs.md`
- Validation evidence: `03-validate.md`
