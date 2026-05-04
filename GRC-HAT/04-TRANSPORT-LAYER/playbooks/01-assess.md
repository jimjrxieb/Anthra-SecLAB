# 01-assess.md — L4 Transport Layer Security Assessment

| Field | Value |
|---|---|
| **NIST Controls** | SC-8, SC-13, SC-23, IA-5 |
| **Tools** | testssl.sh, OpenSSL, cert-manager, Defender for Cloud |
| **Enterprise Equiv** | Qualys SSL Labs Enterprise ($50K+/yr), Venafi ($200K+/yr), DigiCert CertCentral ($100K+/yr) |
| **Time** | 1.5 hours |
| **Rank** | D (scripted assessment, no decisions required) |

---

## Assessment Scope

L4 Transport covers all encrypted communication between clients and services, and between services
(east-west). The assessment answers: Are communications encrypted with approved protocols? Are
certificates valid and auto-renewing? Is mTLS enforced for service-to-service traffic?

---

## TLS Version Compliance — SC-8

- [ ] SSLv3 disabled on all endpoints
- [ ] TLS 1.0 disabled on all endpoints (PCI DSS prohibited since June 2018)
- [ ] TLS 1.1 disabled on all endpoints (deprecated RFC 8996, March 2021)
- [ ] TLS 1.2 enabled as minimum protocol version
- [ ] TLS 1.3 enabled where server/client support allows
- [ ] Protocol version verified with `openssl s_client -tls1` (should return no certificate)
- [ ] All load balancers and reverse proxies (nginx, Apache, IIS, Azure App Service) checked
- [ ] Database connections (SQL, PostgreSQL, MongoDB) using TLS 1.2+

---

## Certificate Management — IA-5

- [ ] Full certificate inventory created (all endpoints, all namespaces)
- [ ] No certificates expired
- [ ] No certificates expiring within 30 days without automated renewal
- [ ] Certificate validity period ≤ 398 days (Apple/browser policy)
- [ ] Auto-renewal configured (cert-manager, certbot, or equivalent)
- [ ] cert-manager ClusterIssuer(s) in READY state
- [ ] cert-manager pods running and healthy in cert-manager namespace
- [ ] CA chain complete (leaf → intermediate → root — no missing intermediates)

---

## Cipher Suite Compliance — SC-13

- [ ] RC4 cipher suites disabled (statistical attacks)
- [ ] 3DES/DES cipher suites disabled (SWEET32 birthday attack)
- [ ] NULL cipher suites disabled (no encryption)
- [ ] EXPORT cipher suites disabled (FREAK/Logjam — intentionally weak)
- [ ] CBC mode cipher suites removed from TLS 1.2 (BEAST/POODLE — prefer AESGCM)
- [ ] Only ECDHE+AESGCM or ECDHE+CHACHA20 suites in use

---

## HSTS and Transport Headers — SC-8(1)

- [ ] Strict-Transport-Security header present on all HTTPS endpoints
- [ ] HSTS max-age ≥ 31536000 (1 year minimum)
- [ ] HSTS includeSubDomains flag set
- [ ] HSTS preload considered for public-facing domains
- [ ] No HTTP → HTTPS redirects that bypass HSTS (check http:// response)

---

## Mutual TLS (Service-to-Service) — SC-23

- [ ] Service mesh deployed (Istio or Linkerd) OR explicit mTLS configured
- [ ] PeerAuthentication mode = STRICT (not PERMISSIVE) if using Istio
- [ ] All pods in production namespace have sidecar injected
- [ ] Internal API endpoints require client certificate
- [ ] mTLS cert rotation automated (via service mesh or cert-manager)

---

## Implementation Priority

| Priority | Finding | NIST Control | Effort |
|---|---|---|---|
| P1 (Critical) | SSLv3 or TLS 1.0 accepted | SC-8 | Low — disable config flag |
| P1 (Critical) | Expired certificate | IA-5 | Low — run fix-expired-cert.sh |
| P2 (High) | TLS 1.1 accepted | SC-8 | Low — same config change |
| P2 (High) | No HSTS header | SC-8(1) | Low — add header line |
| P2 (High) | cert-manager not deployed | IA-5 | Medium — deploy + configure |
| P3 (Medium) | Weak cipher suites (CBC) | SC-13 | Medium — cipher list update |
| P3 (Medium) | No mTLS enforcement | SC-23 | High — service mesh deployment |
| P4 (Low) | TLS 1.3 not supported | SC-13 | Low — server upgrade |
| P4 (Low) | HSTS max-age < 1 year | SC-8(1) | Low — config change |

---

## Baseline Commands

Run these to establish the current state before making any changes:

```bash
# 1. Quick TLS check — identify weak protocols
echo | openssl s_client -connect HOST:PORT -tls1 2>&1 | grep -E "alert|BEGIN CERT"

# 2. Certificate expiry
echo | openssl s_client -connect HOST:PORT 2>/dev/null | openssl x509 -noout -enddate

# 3. cert-manager status (if Kubernetes)
kubectl get clusterissuers,certificates --all-namespaces

# 4. Run full L4 audit
cd 01-auditors && ./audit-tls-config.sh HOST:PORT
```

---

## Deep-Dive Playbooks

After completing this checklist, proceed to:
- `01a-tls-audit.md` — full testssl.sh cipher analysis
- `01b-cert-lifecycle-audit.md` — complete certificate inventory
- `02-fix-SC8-tls.md` — remediate weak protocols/ciphers
- `02a-fix-IA5-certs.md` — remediate certificate issues
