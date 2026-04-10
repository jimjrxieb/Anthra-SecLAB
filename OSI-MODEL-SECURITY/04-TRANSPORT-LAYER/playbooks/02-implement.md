# Layer 4 Transport — Implement Controls

## Purpose

Implement transport-layer security controls based on assessment findings. Start with highest-risk gaps from the 01-assess output. TLS hardening and certificate management are the two pillars — both must be addressed to close SC-8 and IA-5.

## Implementation Order

Priority by risk and cost-efficiency:

### Priority 1: TLS Hardening (Week 1, ~$2,400)

1. **Disable TLS 1.0 and TLS 1.1** on all endpoints
   - nginx: `ssl_protocols TLSv1.2 TLSv1.3;`
   - Apache: `SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1`
   - IIS: Registry keys to disable TLS 1.0/1.1 (or IIS Crypto tool)
   - Load balancers: Update TLS policy to TLS 1.2 minimum
   - PCI-DSS: TLS 1.0 was banned June 30, 2018 — no exceptions

2. **Enforce strong cipher suites** (ECDHE + AESGCM only)
   - nginx: `ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305';`
   - Reference: Mozilla SSL Configuration Generator — Modern profile
   - Remove: RC4, DES, 3DES, EXPORT, NULL, MD5, CBC-mode ciphers

3. **Enable HSTS** on all HTTPS endpoints
   - `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`
   - Start with a short max-age (300 seconds) and increase after validation
   - Submit to HSTS preload list after confirming correctness

4. **Generate custom DH parameters** (2048-bit minimum)
   - `openssl dhparam -out /etc/ssl/dhparam.pem 2048`
   - nginx: `ssl_dhparam /etc/ssl/dhparam.pem;`

5. **Configure HTTP-to-HTTPS redirect** on all public endpoints
   - nginx: `return 301 https://$host$request_uri;`
   - Ensure no mixed content warnings remain

### Priority 2: Certificate Management (Week 1-2, ~$1,600)

1. **Build certificate inventory**
   - Document: domain, issuer, expiry, key size, SAN entries, deployment location
   - Use `check-cert-expiry.sh` from fix.sh or build your own
   - Flag any certificates expiring within 90 days

2. **Replace expired and weak certificates**
   - Minimum: 2048-bit RSA or 256-bit ECDSA
   - Signature: SHA-256 or stronger
   - Include Subject Alternative Names (SAN) for all valid hostnames
   - Use Let's Encrypt for public-facing endpoints (free, automated)

3. **Configure certbot auto-renewal**
   - Install: `apt-get install certbot python3-certbot-nginx`
   - Enable timer: `systemctl enable certbot.timer`
   - Test renewal: `certbot renew --dry-run`
   - Add deploy hook: `--deploy-hook 'systemctl reload nginx'`

4. **Deploy certificate monitoring**
   - Install `check-cert-expiry.sh` (from IA-5 fix.sh)
   - Run daily via cron: `0 8 * * * /usr/local/bin/check-cert-expiry.sh`
   - Alert at 30 days (warning) and 7 days (critical)
   - Integrate with PagerDuty/Slack/email for on-call alerting

### Priority 3: Advanced TLS Controls (Week 3-4, ~$2,000)

1. **OCSP stapling** — reduce certificate validation latency
   - nginx: `ssl_stapling on; ssl_stapling_verify on;`
   - Requires CA chain certificate

2. **Certificate Transparency** monitoring
   - Subscribe to CT logs for your domains
   - Detect unauthorized certificate issuance

3. **Session configuration hardening**
   - Disable session tickets: `ssl_session_tickets off;`
   - Limit session timeout: `ssl_session_timeout 1d;`
   - Use shared session cache: `ssl_session_cache shared:SSL:10m;`

4. **Internal service encryption**
   - Ensure service-to-service communication uses mTLS
   - For Kubernetes: implement service mesh (Istio/Linkerd) for automatic mTLS

### Priority 4: Ongoing Operations (Monthly, ~$400/month)

1. **Monthly certificate expiry audit** — run inventory check
2. **Quarterly TLS configuration scan** — testssl.sh across all endpoints
3. **Annual cipher suite review** — update based on current best practices
4. **Immediate response plan** for compromised private keys (revocation + reissuance)

## Cost Summary

| Phase | Time | One-Time Cost | Annual Cost |
|-------|------|-------------|-------------|
| TLS Hardening | Week 1 | $2,400 | $600 |
| Certificate Management | Week 1-2 | $1,600 | $1,200 |
| Advanced Controls | Week 3-4 | $2,000 | $400 |
| Ongoing Operations | Monthly | $0 | $4,800 |
| **Total** | **4 weeks** | **$6,000** | **$7,000** |

## Verification After Each Implementation

After each control is implemented, run the corresponding scenario's `validate.sh` to confirm it works. Do not proceed to the next priority without validation.
