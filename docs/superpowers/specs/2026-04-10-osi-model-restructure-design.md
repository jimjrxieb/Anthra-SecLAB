# OSI-MODEL-SECURITY SecLAB Restructure Design

**Date:** 2026-04-10
**Goal:** Align SecLAB OSI-MODEL-SECURITY to mirror GP-CONSULTING/09-OSI-MODEL-SECURITY structure, focused on CySA+ daily operations with dual-stack tooling (Microsoft Sentinel + Splunk/open-source).

---

## Architecture

Each of the 7 OSI layers adopts the GP-CONSULTING directory structure:

```
XX-LAYER-NAME/
├── README.md
├── control-map.md
├── 01-auditors/
├── 02-fixers/
├── 03-templates/
├── playbooks/
│   ├── 00-install-validate.md
│   ├── 01-assess.md
│   ├── 01a-<tool>-audit.md
│   ├── 01b-<tool>-audit.md
│   ├── 02-fix-<CONTROL>.md
│   ├── 02a-fix-<CONTROL>.md (where needed)
│   ├── 03-validate.md
│   └── 04-triage-alerts.md
├── scenarios/
│   └── <CONTROL>-<name>/
│       ├── break.sh
│       ├── detect.sh
│       ├── fix.sh
│       ├── validate.sh
│       └── governance.md
├── evidence/
└── tools/
```

No `05-ciso-report.md` per layer. Per-scenario `governance.md` files handle CISO-level translation (5x5 risk matrix, FAIR scoring, ROSI calculations).

---

## Tool Stack

Dual-stack: Microsoft (CySA+ default) and open-source (alternative). Shared tools where both stacks use the same tooling.

| Domain | Microsoft Stack (CySA+ default) | Open-Source Stack (alt) |
|--------|--------------------------------|------------------------|
| SIEM | Microsoft Sentinel | Splunk / Security Onion |
| EDR | Microsoft Defender | Wazuh |
| IAM | Entra ID | Keycloak |
| Secrets | Azure Key Vault | HashiCorp Vault |
| Encryption | BitLocker / Azure Disk Encryption | LUKS / SOPS + age |
| IDS/IPS | Suricata (shared) | Suricata (shared) |
| Flow Analysis | Zeek (shared) | Zeek (shared) |
| TLS Audit | testssl.sh (shared) | testssl.sh (shared) |
| Vuln Scanning | Trivy, Grype, ZAP (shared) | Same |

---

## Fixer Philosophy

Generic best-practice remediation only. No environment-specific paths, IPs, or configs.

Each fixer answers: "The tool isn't catching or preventing what it should."

Content per fixer:
1. Tool update procedure (signature updates, rule pulls)
2. How to create a custom signature/rule within the tool
3. Working example of that signature/rule
4. Generic best-practice config correction

---

## What Changes vs. What Stays

### Replace
- Playbooks: current 4-file cycle replaced with GP-CONSULTING engagement cycle (00-install through 04-triage)

### Add
- `01-auditors/` per layer with audit-*.sh scripts
- `02-fixers/` per layer with fix-*.sh scripts
- `03-templates/` per layer with dual-stack configs (Microsoft + open-source, WHY comments per directive)
- `tools/` per layer with run-all-audits.sh orchestration
- Dual SIEM playbooks at L7: `01a-sentinel-audit.md` + `01a-splunk-audit.md`

### Keep
- All existing scenarios with break/detect/fix/validate/governance.md
- Existing control-map.md files (update to reflect new tools and auditor/fixer mappings)
- Evidence directories
- Root README.md (update to reflect new structure)

### GP-CONSULTING Side Change
- Rename `07-APPLICATION-LAYER/playbooks/01a-siem-audit.md` to `01a-splunk-audit.md`

---

## Per-Layer Breakdown

### Layer 1 — Physical (01-PHYSICAL-LAYER)
- Tabletop exercises only (cloud/physical boundary)
- Auditors: facility access checklists, environmental monitoring validation
- Templates: PE control assessment templates
- Scenarios: PE-3 physical access, PE-14 environmental (keep existing)

### Layer 2 — Data Link (02-DATA-LINK-LAYER)
- Auditors: ARP table integrity, VLAN config, 802.1X status
- Fixers: arpwatch setup, port security, 802.1X enforcement
- Templates: arpwatch config, Defender IoT policies
- Scenarios: AC-3 VLAN hopping, SC-7 ARP spoofing (keep existing)
- Tools: keep existing setup-l2-tools.sh, teardown, attacker-container

### Layer 3 — Network (03-NETWORK-LAYER)
- Auditors: firewall rules, IDS health (Suricata), flow logging (Zeek), network segmentation
- Fixers: Suricata rule updates, custom signature creation (with example), firewall hardening, default-deny NetworkPolicy
- Templates: suricata.yaml, local.rules, zeek/local.zeek, NetworkPolicy YAML, Security Onion overlay — dual-stack (Windows Firewall + iptables/nftables)
- Scenarios: AC-4 flat network, SC-7 firewall misconfiguration (keep existing)

### Layer 4 — Transport (04-TRANSPORT-LAYER)
- Auditors: TLS config (testssl.sh), certificate lifecycle, mTLS status
- Fixers: weak cipher remediation, HSTS enforcement, cert renewal, CA rotation
- Templates: nginx-tls.conf, envoy-tls.yaml, cert-manager manifests, openssl.cnf — dual-stack where applicable
- Scenarios: SC-8 weak TLS, IA-5 expired cert (keep existing)

### Layer 5 — Session (05-SESSION-LAYER)
- Auditors: RBAC privileges, service account exposure, session policy, MFA status
- Fixers: overprivileged SA remediation, session timeout enforcement, MFA enablement, cookie flags
- Templates: Entra ID conditional access JSON + Keycloak realm-export, RBAC role YAML, Vault K8s auth
- Scenarios: AC-12 no session timeout, SC-23 session fixation (keep existing)

### Layer 6 — Presentation (06-PRESENTATION-LAYER)
- Auditors: encryption at rest, key rotation, crypto standards (MD5/SHA-1/DES detection), secrets exposure
- Fixers: key rotation procedure, weak hashing migration, plaintext secrets migration
- Templates: Azure Key Vault policy + Vault config.hcl, SOPS config, K8s EncryptionConfiguration, openssl strong defaults
- Scenarios: SC-13 weak crypto, SC-28 unencrypted data (keep existing)

### Layer 7 — Application (07-APPLICATION-LAYER)
- Auditors: SIEM ingest health, EDR agent status, vuln scan coverage, alert rules, log retention
- Fixers: alert rule creation (with example), missing log source onboarding, FIM path config, vulnerable image remediation
- Templates: Sentinel analytics rules + Splunk index/input/dashboard, Defender policies + Wazuh config, kube-bench profiles, Kubescape policies
- Dual SIEM playbooks: `01a-sentinel-audit.md` and `01a-splunk-audit.md`
- Scenarios: AU-2 missing logging, SI-10 SQL injection (keep existing)

---

## Playbook Content Standard

Each playbook follows CySA+ daily operations perspective:
- Written as if you are a SOC analyst or security engineer performing the task
- Tool commands are copy-paste ready
- Output interpretation guidance (what good looks like, what bad looks like)
- NIST control reference on every check
- Rank classification for findings (E/D/C/B/S)

---

## Template Content Standard

Every template config file includes:
- WHY comment per directive (maps to NIST control requirement)
- Both Microsoft and open-source variants in the same `03-templates/` directory
- Clearly labeled: `sentinel/`, `splunk/`, `entra-id/`, `keycloak/`, etc.
