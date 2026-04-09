# Layer 4 Transport — Control Map

| NIST Control | Control Name | Tool | Enterprise Equivalent | What Misconfiguration Looks Like |
|-------------|-------------|------|----------------------|--------------------------------|
| SC-8 | Transmission Confidentiality | testssl.sh, Nmap, Defender for Cloud | Qualys SSL Labs, Venafi | TLS 1.0/1.1 enabled, weak ciphers (RC4, DES), no HSTS |
| SC-23 | Session Authenticity | OpenSSL, testssl.sh | F5, Akamai | No certificate pinning, session tokens over unencrypted channel |
| IA-5 | Authenticator Management | OpenSSL, certbot | Venafi, DigiCert CertCentral | Expired certs, self-signed in production, no renewal automation |
| SC-13 | Cryptographic Protection | OpenSSL, SSLyze | Thales HSM, Venafi | Non-FIPS algorithms, key length below minimum, hardcoded keys |
