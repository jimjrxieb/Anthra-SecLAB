# Layer 4 Transport — Assess Current State

## Purpose

Document the current transport-layer security posture before implementing any controls. This assessment covers TLS configuration, certificate management, cipher suites, and encryption-in-transit enforcement. The baseline established here measures improvement after remediation.

## Assessment Checklist

### SC-8 Transmission Confidentiality and Integrity

- [ ] Inventory all TLS-enabled endpoints (web servers, APIs, load balancers, mail servers)
- [ ] For each endpoint: what TLS versions are accepted? (SSLv3, TLS 1.0, 1.1, 1.2, 1.3)
- [ ] Are any endpoints still accepting TLS 1.0 or 1.1?
- [ ] What cipher suites are offered? List them by endpoint
- [ ] Are weak ciphers present? (RC4, DES, 3DES, EXPORT, NULL)
- [ ] Is forward secrecy enforced? (ECDHE or DHE key exchange required)
- [ ] Are any endpoints using CBC-mode ciphers with TLS 1.0? (BEAST-vulnerable)
- [ ] Is HSTS enabled on all HTTPS endpoints?
- [ ] If HSTS is enabled: what is the max-age? Is includeSubDomains set? Is preload set?
- [ ] Are any internal services communicating over unencrypted HTTP?
- [ ] Is HTTP-to-HTTPS redirect configured on all public endpoints?
- [ ] What is the DH parameter size? (must be >= 2048-bit)

### SC-13 Cryptographic Protection

- [ ] What signature algorithms are in use? (SHA-1 is deprecated; SHA-256+ required)
- [ ] What key sizes are in use? (RSA < 2048-bit and ECDSA < 256-bit are non-compliant)
- [ ] Are FIPS 140-2 validated cryptographic modules required? (FedRAMP High: yes)
- [ ] Is key material stored securely? (HSM, vault, or filesystem with restricted permissions)

### IA-5 Authenticator (Certificate) Management

- [ ] Create a certificate inventory: domain, issuer, expiry date, key size, location
- [ ] How many certificates are currently deployed?
- [ ] How many certificates expire within 30 days? 60 days? 90 days?
- [ ] Are any certificates already expired?
- [ ] Are any certificates self-signed in production?
- [ ] Is there a certificate authority (CA) hierarchy? (Internal CA, public CA, or mixed)
- [ ] Is certificate auto-renewal configured? (certbot, ACME, Venafi, etc.)
- [ ] Is there a certificate monitoring system? What does it alert on?
- [ ] What is the process for certificate rotation when a private key is compromised?
- [ ] Are certificate revocation lists (CRL) or OCSP responders configured?

### SC-23 Session Authenticity

- [ ] Are session tokens transmitted only over encrypted channels?
- [ ] Is certificate pinning implemented for mobile/API clients?
- [ ] Are session cookies marked with Secure and HttpOnly flags?

## Tools for Assessment

| Tool | Command | What It Checks |
|------|---------|----------------|
| testssl.sh | `testssl.sh --protocols --ciphers <host>` | TLS versions, cipher suites, vulnerabilities |
| nmap | `nmap --script ssl-enum-ciphers -p 443 <host>` | Cipher suite enumeration and grading |
| OpenSSL | `openssl s_client -connect <host>:443` | Certificate details, chain validation |
| SSLyze | `sslyze --regular <host>` | Comprehensive TLS analysis |
| Defender for Cloud | Portal → Secure Score → Networking | TLS compliance across Azure resources |
| curl | `curl -sI https://<host>` | HSTS and security headers |

## Output

Complete the checklist above and produce:
1. TLS endpoint inventory spreadsheet (host, port, TLS versions, ciphers, cert expiry)
2. Certificate inventory (domain, issuer, expiry, key size, renewal method)
3. Gap analysis: which SC-8, IA-5, SC-13, and SC-23 controls have findings?
4. Risk ranking of findings using 5x5 matrix
