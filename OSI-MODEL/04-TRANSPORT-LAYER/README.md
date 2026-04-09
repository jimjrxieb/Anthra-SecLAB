# Layer 4 — Transport

## What This Layer Covers

TLS configuration, port security, encryption in transit, certificate management. This is the layer that protects data as it moves between systems.

## Why It Matters

Weak TLS (1.0/1.1) is a known broken protocol — downgrade attacks let an attacker read encrypted traffic. Expired certificates cause outages and erode user trust. Missing encryption in transit means anyone on the network path can read the data. Certificate management failures caused multiple high-profile outages in 2024-2025.

## NIST 800-53 Controls

| Control ID | Control Name | What It Requires |
|-----------|-------------|-----------------|
| SC-8 | Transmission Confidentiality and Integrity | Encrypt data in transit |
| SC-23 | Session Authenticity | Protect session integrity |
| IA-5 | Authenticator Management | Certificate lifecycle management |
| SC-13 | Cryptographic Protection | Use approved cryptographic algorithms |

## Tools

| Tool | Type | Cost | Purpose |
|------|------|------|---------|
| Microsoft Defender for Cloud | Microsoft | Free tier | Secure Score, TLS compliance |
| OpenSSL | Open source | Free | Certificate inspection, generation |
| testssl.sh | Open source | Free | TLS configuration audit |
| Nmap | Open source | Free | SSL/TLS enumeration |
| SSLyze | Open source | Free | TLS analysis |

## Scenarios

| Scenario | Control | Format |
|----------|---------|--------|
| [SC-8 Weak TLS](scenarios/SC-8-weak-tls/) | SC-8 | Scripts (.sh) |
| [IA-5 Expired Certificate](scenarios/IA-5-expired-cert/) | IA-5 | Scripts (.sh) |
