# Layer 4 Transport — Break/Fix Scenarios

## Purpose

Run each scenario's break → detect → fix → validate cycle to demonstrate the control's value and produce evidence for governance reporting.

## How to Run a Scenario

Each scenario is in `scenarios/{CONTROL-ID}-{name}/` and contains 5 files:

| File | Purpose | Format |
|------|---------|--------|
| `break.sh` | Creates the misconfiguration (weak TLS, expired cert) | Bash script |
| `detect.sh` | Detects the misconfiguration using security tools | Bash script |
| `fix.sh` | Remediates the finding | Bash script |
| `validate.sh` | Confirms the fix is effective | Bash script |
| `governance.md` | CISO brief with risk, cost, ROI | Governance report |

All scripts use `set -euo pipefail` and require appropriate privileges.

## Scenario Execution Order

### Scenario 1: SC-8 Weak TLS Configuration

TLS 1.0/1.1 enabled with weak cipher suites. Simulates a server vulnerable to BEAST, POODLE, and downgrade attacks.

1. **Break** — Deploy weak TLS configuration
   ```bash
   sudo ./scenarios/SC-8-weak-tls/break.sh 4443
   ```
   Creates an nginx server (or openssl s_server) on port 4443 with TLS 1.0 enabled, weak ciphers (RC4, DES, EXPORT), and no HSTS.

2. **Detect** — Scan for weak TLS
   ```bash
   ./scenarios/SC-8-weak-tls/detect.sh localhost 4443
   ```
   Runs testssl.sh, nmap ssl-enum-ciphers, and OpenSSL manual checks. Produces evidence files in `/tmp/sc8-weak-tls-detect-*`.

3. **Fix** — Enforce strong TLS
   ```bash
   sudo ./scenarios/SC-8-weak-tls/fix.sh 4443
   ```
   Reconfigures to TLS 1.2+ only, ECDHE+AESGCM ciphers, HSTS header, and 2048-bit certificate.

4. **Validate** — Confirm the fix
   ```bash
   ./scenarios/SC-8-weak-tls/validate.sh localhost 4443
   ```
   Verifies TLS 1.0/1.1 rejected, weak ciphers unavailable, HSTS present, certificate key size adequate.

5. **Governance** — Review the CISO brief
   Read `scenarios/SC-8-weak-tls/governance.md` for the business case: $976K ALE, $3K fix cost, 292x ROSI.

### Scenario 2: IA-5 Expired Certificate

Expired self-signed certificate with no renewal automation. Simulates the Equifax 2017 failure mode.

1. **Break** — Deploy expired certificate
   ```bash
   sudo ./scenarios/IA-5-expired-cert/break.sh 4444
   ```
   Generates an expired self-signed certificate and deploys it to a server on port 4444.

2. **Detect** — Check certificate validity
   ```bash
   ./scenarios/IA-5-expired-cert/detect.sh localhost 4444
   ```
   Checks expiry date, self-signed status, chain validation, key size, and renewal automation. Produces evidence files in `/tmp/ia5-expired-cert-detect-*`.

3. **Fix** — Generate valid cert and configure lifecycle management
   ```bash
   sudo ./scenarios/IA-5-expired-cert/fix.sh secure-lab.anthra.local 4444
   ```
   Generates a valid certificate, configures certbot auto-renewal, installs monitoring script, sets up cron jobs.

4. **Validate** — Confirm the fix
   ```bash
   ./scenarios/IA-5-expired-cert/validate.sh localhost 4444
   ```
   Verifies certificate is valid, key size adequate, auto-renewal configured, monitoring active.

5. **Governance** — Review the CISO brief
   Read `scenarios/IA-5-expired-cert/governance.md` for the business case: Equifax precedent ($1.4B), $312K ALE, $4.4K fix cost, 66x ROSI.

## Evidence Collection

After each scenario, save evidence to `evidence/YYYY-MM-DD/`:
- testssl.sh output files (protocols, ciphers, vulnerabilities)
- nmap ssl-enum-ciphers output
- OpenSSL certificate details
- Before/after nginx configurations
- Validation test results (pass/fail counts)
- Governance brief (completed with environment-specific data)

## Scenario Dependencies

| Scenario | Requires | Ports |
|----------|----------|-------|
| SC-8 Weak TLS | nginx or openssl, testssl.sh, nmap | 4443 |
| IA-5 Expired Cert | nginx or openssl, certbot (optional) | 4444 |

Install prerequisites:
```bash
# Debian/Ubuntu
apt-get install nginx openssl nmap

# testssl.sh
git clone https://github.com/drwetter/testssl.sh.git /opt/testssl.sh
ln -s /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh

# certbot
apt-get install certbot python3-certbot-nginx
```
