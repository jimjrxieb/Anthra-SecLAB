# OSI-MODEL Security Lab — Design Spec

## Purpose

Build a 7-layer OSI security lab that maps every layer to NIST 800-53 controls, implements them with tools (Microsoft free-tier where available, open source for the rest), breaks configurations to demonstrate cost of failure, fixes them, validates the fix, and communicates governance value to CISO leadership.

This is not a DevSecOps tool showcase. This is a security analyst training lab grounded in CySA+, Cloud+, and CISSP fundamentals. The audience is a security analyst learning to explain WHY controls exist and translate technical findings into business risk language.

## Scope

- All 7 OSI layers, no exceptions
- NIST 800-53 controls mapped per layer
- Microsoft tools where free tier covers it; open source for the rest
- Minimum 2 scenarios per layer to establish structure; expand later
- Every scenario produces a CISO governance brief with dollar-value risk analysis
- Target application: Anthra-SecLAB portfolio app (FastAPI + React + PostgreSQL)

## Certification Alignment

| Cert | How OSI-MODEL Maps |
|------|-------------------|
| CompTIA CySA+ | Threat detection, vulnerability management, incident response across all layers |
| CompTIA Cloud+ | Cloud security controls (Azure NSGs, Defender for Cloud, identity) |
| CISSP | Risk management frameworks, governance, security architecture, all 8 domains |

---

## Layer Package Structure

Every layer follows the same internal layout:

```
OSI-MODEL/0X-LAYER-NAME/
├── README.md              # Layer overview, why it matters, NIST controls covered
├── control-map.md         # NIST control → tool → misconfiguration description
├── scenarios/
│   └── XX-X-control-name/
│       ├── break.sh       # Break the control (or break.md if not scriptable)
│       ├── detect.sh      # Detect the misconfiguration (or detect.md)
│       ├── fix.sh         # Remediate (or fix.md)
│       ├── validate.sh    # Confirm the fix holds (or validate.md)
│       └── governance.md  # CISO brief: risk, cost, ROI, recommendation
├── playbooks/
│   ├── 01-assess.md       # Assess current state of this layer
│   ├── 02-implement.md    # Implement controls for this layer
│   ├── 03-break-fix.md    # Run break/fix scenarios
│   └── 04-ciso-report.md  # Generate governance report for this layer
└── evidence/
    └── .gitignore
```

**Script vs. Markdown rule:** If the scenario can be executed against the lab environment (VM, container, cloud), it gets `.sh` scripts. If it's physical or policy-based (L1 badge access, L5 session policy), it gets `.md` documents describing the scenario, what to observe, and how to validate.

---

## Governance Template (governance.md)

Every scenario includes a CISO governance brief following this structure:

```markdown
# [Control ID] [Control Name] — CISO Governance Brief

## Executive Summary
One paragraph: what was broken, what it costs if exploited, what we did.

## NIST 800-53 Control Requirement
What the control says (quoted from 800-53). Why it exists.
Which compliance frameworks require it (FedRAMP, HIPAA, PCI-DSS, SOC 2).

## Risk Assessment
- Likelihood: [1-5] — [justification]
- Impact: [1-5] — [justification]
- Inherent Risk Score: [L x I]
- Risk Level: [Low / Medium / High / Very High]

## Business Impact
- Attack path: [technical finding → what attacker achieves step by step]
- Data exposure: [record count, PII type, customer count]
- Estimated breach cost: [IBM per-record cost x records, cite source]
- Regulatory exposure: [HIPAA/PCI/GDPR fine range]
- Compliance gap: [which certification or ATO is at risk]

## Proportionality Analysis (Gordon-Loeb)
- Asset value protected: [$X]
- Annualized Loss Expectancy (ALE): [$X]
- Control implementation cost: [$X]
- ROSI: [(ALE x risk_reduction% - cost) / cost]
- Gordon-Loeb ceiling: [37% of ALE = $X]
- Verdict: [proportional / overinvestment / underinvestment]

## Remediation Summary
- What was fixed
- Time to remediate
- Residual risk score after fix: [L x I]

## Metrics Impact
- MTTD for this finding: [Xh]
- MTTR: [Xh]
- Control coverage change: [before% → after%]
- Vulnerability SLA status: [within/outside SLA]

## Recommendation to Leadership
Decision: [Accept / Mitigate / Transfer / Avoid]
Justification: [1-2 sentences in business language]
```

---

## Layer Definitions

### 01-PHYSICAL-LAYER

**What it covers:** Physical access to facilities, environmental controls, hardware security, media protection.

**NIST 800-53 Controls:**
- PE-1 Physical and Environmental Protection Policy
- PE-2 Physical Access Authorizations
- PE-3 Physical Access Control
- PE-6 Monitoring Physical Access
- PE-13 Fire Protection
- PE-14 Environmental Controls (HVAC, humidity, temperature)

**Tools:**
- Badge access / RFID systems (physical)
- CCTV / NVR camera systems (physical)
- Environmental monitoring sensors (HVAC, temperature alerts)
- Asset inventory (Snipe-IT — open source)

**Starting scenarios (2):**

| ID | Control | Break | Detect | Fix |
|----|---------|-------|--------|-----|
| PE-3-physical-access | PE-3 | Tailgating — unauthorized person follows employee through badge door | Review access logs for entries without badge swipe | Implement anti-tailgating policy, mantrap/turnstile, visitor escort requirement |
| PE-14-environmental | PE-14 | HVAC failure — server room temperature exceeds threshold | Temperature monitoring alerts, review environmental logs | Implement redundant HVAC, automated shutdown threshold, alerting to NOC |

**Format:** All `.md` (not scriptable — physical scenarios described as tabletop exercises)

---

### 02-DATA-LINK-LAYER

**What it covers:** MAC address security, switch port security, ARP protection, VLAN segmentation, 802.1X network access control.

**NIST 800-53 Controls:**
- SC-7 Boundary Protection (L2 segmentation)
- AC-3 Access Enforcement (port-level)
- SI-4 Information System Monitoring (L2 anomalies)

**Tools:**
- Wireshark (open source — packet capture, ARP analysis)
- Microsoft Defender for IoT (free tier — OT/IoT network monitoring)
- arpwatch (open source — ARP change detection)
- macchanger (open source — for break scenarios)

**Starting scenarios (2):**

| ID | Control | Break | Detect | Fix |
|----|---------|-------|--------|-----|
| SC-7-arp-spoofing | SC-7 | ARP spoof to intercept traffic between two hosts | Wireshark ARP analysis, arpwatch alerts | Enable Dynamic ARP Inspection (DAI), static ARP entries for critical systems |
| AC-3-vlan-hopping | AC-3 | VLAN hopping via double tagging or switch spoofing | Wireshark 802.1Q analysis, switch log review | Disable DTP, set native VLAN to unused, prune unused VLANs from trunks |

**Format:** Mix of `.sh` (Wireshark captures, arpwatch) and `.md` (switch configuration)

---

### 03-NETWORK-LAYER

**What it covers:** IP segmentation, firewall rules, routing security, intrusion detection/prevention.

**NIST 800-53 Controls:**
- SC-7 Boundary Protection (firewall, segmentation)
- AC-4 Information Flow Enforcement
- SI-3 Malicious Code Protection
- SI-4 Information System Monitoring (IDS/IPS)

**Tools:**
- Azure NSGs (free with Azure account)
- Windows Defender Firewall (free with Windows)
- pfSense (open source firewall)
- Suricata (open source IDS/IPS)
- Nmap (open source — network scanning)

**Starting scenarios (2):**

| ID | Control | Break | Detect | Fix |
|----|---------|-------|--------|-----|
| SC-7-firewall-misconfig | SC-7 | Open inbound rule allowing 0.0.0.0/0 on management port (RDP 3389 or SSH 22) | Nmap scan shows open port, Azure NSG flow logs, Suricata alert | Restrict source IP to admin CIDR, enable NSG flow logging, Suricata rule for unauthorized access |
| AC-4-flat-network | AC-4 | Remove network segmentation — all subnets can reach all subnets | Nmap sweep across subnets, Suricata lateral movement detection | Implement subnet segmentation, firewall rules between zones, micro-segmentation |

**Format:** `.sh` scripts (Nmap, Suricata, Azure CLI for NSG scenarios)

---

### 04-TRANSPORT-LAYER

**What it covers:** TLS configuration, port security, encryption in transit, certificate management.

**NIST 800-53 Controls:**
- SC-8 Transmission Confidentiality and Integrity
- SC-23 Session Authenticity
- IA-5 Authenticator Management (certificate lifecycle)
- SC-13 Cryptographic Protection

**Tools:**
- Microsoft Defender for Cloud (free tier — Secure Score covers TLS)
- OpenSSL (open source — cert inspection, generation)
- testssl.sh (open source — TLS configuration audit)
- Nmap (open source — SSL/TLS enumeration)
- SSLyze (open source — TLS analysis)

**Starting scenarios (2):**

| ID | Control | Break | Detect | Fix |
|----|---------|-------|--------|-----|
| SC-8-weak-tls | SC-8 | Configure service with TLS 1.0/1.1 and weak cipher suites (RC4, DES) | testssl.sh audit, Nmap ssl-enum-ciphers, Defender for Cloud Secure Score drop | Enforce TLS 1.2+ minimum, strong cipher suites only, HSTS header |
| IA-5-expired-cert | IA-5 | Deploy service with expired or self-signed TLS certificate | OpenSSL s_client check, browser warning, Defender for Cloud alert | Implement cert renewal automation (certbot/ACME), certificate monitoring |

**Format:** `.sh` scripts (testssl.sh, OpenSSL, Nmap)

---

### 05-SESSION-LAYER

**What it covers:** Session management, authentication state, token handling, session termination.

**NIST 800-53 Controls:**
- AC-12 Session Termination
- SC-23 Session Authenticity
- IA-2 Identification and Authentication
- IA-8 Identification and Authentication (Non-Organizational Users)

**Tools:**
- Microsoft Entra ID (free tier — conditional access policies, session lifetime)
- Burp Suite Community Edition (free — session analysis, cookie inspection)
- Browser DevTools (free — cookie/token inspection)
- OWASP ZAP (open source — session testing)

**Starting scenarios (2):**

| ID | Control | Break | Detect | Fix |
|----|---------|-------|--------|-----|
| AC-12-no-session-timeout | AC-12 | Configure application with no session timeout — tokens never expire | Burp Suite session analysis, check token expiry in DevTools, Entra ID sign-in logs | Set session timeout (15min idle, 8hr max), implement token refresh rotation, Entra ID conditional access |
| SC-23-session-fixation | SC-23 | Reuse session token across authentication boundary (pre-auth token survives login) | Burp Suite — compare session IDs before/after login, ZAP session management scan | Regenerate session ID on authentication, bind session to client fingerprint |

**Format:** Mix of `.sh` (ZAP, curl-based token tests) and `.md` (Entra ID configuration)

---

### 06-PRESENTATION-LAYER

**What it covers:** Data encoding, encryption at rest, input/output sanitization, cryptographic protection.

**NIST 800-53 Controls:**
- SC-28 Protection of Information at Rest
- SI-10 Information Input Validation
- SC-13 Cryptographic Protection
- SI-15 Information Output Filtering

**Tools:**
- Microsoft BitLocker (free with Windows Pro — disk encryption)
- Azure Key Vault (free tier — secret/key management)
- OpenSSL (open source — encryption verification)
- CyberChef (open source — encoding/decoding analysis)
- hashcat (open source — for demonstrating weak hash cracking in break scenarios)

**Starting scenarios (2):**

| ID | Control | Break | Detect | Fix |
|----|---------|-------|--------|-----|
| SC-28-unencrypted-data | SC-28 | Store sensitive data (passwords, PII) in plaintext in database | Query database for plaintext fields, BitLocker status check, Azure Key Vault audit | Encrypt at rest (BitLocker for disk, column-level encryption for DB), migrate secrets to Key Vault |
| SC-13-weak-crypto | SC-13 | Use MD5 for password hashing, SHA1 for integrity checks | hashcat demonstration (crack MD5 in seconds), OpenSSL audit of algorithms in use | Migrate to bcrypt/argon2 for passwords, SHA-256+ for integrity, document crypto standards |

**Format:** `.sh` scripts (OpenSSL, hashcat demo, database queries)

---

### 07-APPLICATION-LAYER

**What it covers:** Application security, authentication, authorization, API security, input validation, logging.

**NIST 800-53 Controls:**
- SA-11 Developer Testing and Evaluation
- RA-5 Vulnerability Scanning
- AC-6 Least Privilege (application-level)
- SI-10 Information Input Validation
- AU-2 Event Logging
- AU-6 Audit Record Review

**Tools:**
- Microsoft Sentinel + KQL (free tier — 10 GB/day, log analysis)
- Microsoft Defender for Cloud Apps (free trial)
- Splunk (existing setup)
- OWASP ZAP (open source — DAST)
- Semgrep (open source — SAST)
- Nikto (open source — web server scanner)
- SQLMap (open source — SQL injection testing)

**Starting scenarios (2):**

| ID | Control | Break | Detect | Fix |
|----|---------|-------|--------|-----|
| SI-10-sql-injection | SI-10 | Introduce unsanitized SQL query in API endpoint (string concatenation) | ZAP active scan, SQLMap test, Semgrep SAST rule match, Sentinel/Splunk alert on anomalous queries | Parameterized queries, input validation, WAF rule, Semgrep CI gate |
| AU-2-missing-logging | AU-2 | Disable application audit logging — auth events, failed logins, data access not recorded | Check Sentinel/Splunk for log gaps, review application log configuration | Enable structured audit logging, ship to Sentinel/Splunk, create alert rules for auth failures, KQL detection queries |

**Format:** `.sh` scripts (ZAP, Semgrep, SQLMap, KQL queries)

---

## Scenario Numbering Convention

Each scenario folder is named: `{CONTROL-ID}-{short-description}`

Examples:
- `PE-3-physical-access`
- `SC-7-arp-spoofing`
- `SC-7-firewall-misconfig`
- `SC-8-weak-tls`
- `AC-12-no-session-timeout`
- `SC-28-unencrypted-data`
- `SI-10-sql-injection`

Same control ID can appear in multiple layers (SC-7 at L2 and L3) because the control applies differently at each layer.

---

## Playbook Structure

Each layer has 4 playbooks following a consistent progression:

### 01-assess.md
- What to check at this layer
- Tools to run and what output to look for
- How to read the results
- Current state documentation checklist

### 02-implement.md
- Step-by-step guide to implement each control
- Tool configuration (with screenshots/commands)
- Verification that the control is active
- Common mistakes and how to avoid them

### 03-break-fix.md
- How to run each scenario's break/detect/fix/validate cycle
- Expected output at each stage
- Troubleshooting if something doesn't match
- How to document evidence for each run

### 04-ciso-report.md
- How to compile scenario results into a governance report
- Risk scoring methodology (5x5 matrix, FAIR if quantitative data available)
- ROSI calculation walkthrough
- Template for presenting findings to leadership
- Key terminology and how to use it correctly

---

## Key Terminology (used throughout)

| Term | Definition |
|------|-----------|
| ALE | Annualized Loss Expectancy — expected loss per year (probability x impact) |
| FAIR | Factor Analysis of Information Risk — quantitative risk model |
| ROSI | Return on Security Investment — (risk_reduction - cost) / cost |
| Gordon-Loeb | Never spend more than 37% of expected loss on a control |
| POA&M | Plan of Action and Milestones — remediation tracking |
| SAR | Security Assessment Report — formal assessment output |
| SSP | System Security Plan — how controls are implemented |
| MTTD | Mean Time to Detect |
| MTTR | Mean Time to Respond |
| Inherent Risk | Risk before controls |
| Residual Risk | Risk after controls |
| Risk Appetite | How much risk the organization formally accepts |

---

## Constraints

- All scripts must be idempotent — safe to run multiple times
- Break scripts must have a matching fix before committing
- No simulated output — every evidence file from a real tool run
- Governance briefs use real dollar figures from IBM breach reports and regulatory fine schedules
- Each layer stands alone — no cross-layer dependencies in the structure
- Microsoft tools used where free tier is available; open source for the rest
- Splunk stays as existing SIEM alongside Sentinel

## What This Is Not

- Not a DevSecOps pipeline (that's a different track)
- Not Kubernetes-focused (controls are vendor-neutral / Microsoft-leaning)
- Not a tool demo — the tool is secondary to the control and the governance communication
