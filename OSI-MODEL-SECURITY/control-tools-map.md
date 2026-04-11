# Cross-Layer Control-Tools Map

Quick reference: NIST control to auditor, fixer, and template across all OSI layers.

## Physical & Environmental (Layer 1)

| NIST Control | Control Name | Auditor | Fixer | Template |
|-------------|-------------|---------|-------|----------|
| PE-3 | Physical Access Control | audit-physical-access.sh | fix-access-policy.md | pe-assessment-checklist.md |
| PE-14 | Environmental Controls | audit-environmental-controls.sh | fix-environmental-monitoring.md | pe-assessment-checklist.md |

## Data Link (Layer 2)

| NIST Control | Control Name | Auditor | Fixer | Template |
|-------------|-------------|---------|-------|----------|
| SC-7 | Boundary Protection (L2) | audit-arp-integrity.sh | fix-arp-monitoring.sh | arpwatch/arpwatch.conf |
| AC-3 | Access Enforcement | audit-vlan-config.sh, audit-802.1x-status.sh | fix-port-security.md | defender-iot/network-detection-policy.json |
| AC-4 | Information Flow (L2) | audit-vlan-config.sh | fix-port-security.md | defender-iot/network-detection-policy.json |
| SI-4 | Monitoring (L2) | audit-arp-integrity.sh | fix-arp-monitoring.sh | arpwatch/arpwatch.conf |

## Network (Layer 3)

| NIST Control | Control Name | Auditor | Fixer | Template |
|-------------|-------------|---------|-------|----------|
| SC-7 | Boundary Protection | audit-firewall-rules.sh | fix-management-ports.sh, fix-default-deny.sh | windows-firewall/hardened-gpo.md, azure-nsg/nsg-baseline.json |
| AC-4 | Information Flow | audit-network-segmentation.sh | fix-default-deny.sh | network-policies/default-deny.yaml |
| SI-3 | Malicious Code Protection | audit-suricata-config.sh | fix-suricata-rule-update.sh, fix-suricata-custom-signature.md | suricata/suricata.yaml, suricata/local.rules |
| SI-4 | Monitoring (L3) | audit-zeek-config.sh, audit-suricata-config.sh | fix-suricata-rule-update.sh | zeek/local.zeek |

## Transport (Layer 4)

| NIST Control | Control Name | Auditor | Fixer | Template |
|-------------|-------------|---------|-------|----------|
| SC-8 | Transmission Confidentiality | audit-tls-config.sh | fix-weak-ciphers.sh | tls/nginx-tls.conf, tls/envoy-tls.yaml |
| SC-13 | Cryptographic Protection | audit-tls-config.sh | fix-weak-ciphers.sh | openssl/openssl.cnf |
| IA-5 | Authenticator Management | audit-cert-lifecycle.sh | fix-expired-cert.sh | cert-manager/clusterissuer.yaml, cert-manager/certificate.yaml |
| SC-23 | Session Authenticity (TLS) | audit-mtls-status.sh | — | tls/envoy-tls.yaml |

## Session (Layer 5)

| NIST Control | Control Name | Auditor | Fixer | Template |
|-------------|-------------|---------|-------|----------|
| AC-2 | Account Management | audit-mfa-status.sh | fix-mfa-enforcement.md | entra-id/conditional-access-baseline.json |
| AC-6 | Least Privilege | audit-rbac-privileges.sh, audit-service-accounts.sh | fix-overprivileged-sa.sh | rbac/least-privilege-role.yaml, rbac/read-only-clusterrole.yaml |
| AC-12 | Session Termination | audit-session-policy.sh | fix-session-timeout.sh | keycloak/realm-export.json, entra-id/conditional-access-baseline.json |
| IA-2 | Identification & Auth | audit-mfa-status.sh | fix-mfa-enforcement.md, fix-conditional-access-policy.md | entra-id/mfa-enforcement-policy.json |
| SC-23 | Session Authenticity | audit-session-policy.sh | fix-session-timeout.sh | keycloak/client-config.json |

## Presentation (Layer 6)

| NIST Control | Control Name | Auditor | Fixer | Template |
|-------------|-------------|---------|-------|----------|
| SC-28 | Protection of Info at Rest | audit-encryption-at-rest.sh | fix-etcd-encryption.sh, fix-bitlocker-enforcement.md | k8s/encryption-config.yaml |
| SC-13 | Cryptographic Protection | audit-crypto-standards.sh | fix-weak-hashing.md | openssl/strong-defaults.cnf |
| SC-12 | Key Management | audit-key-rotation.sh | fix-key-rotation.sh | azure-key-vault/key-rotation-policy.json, hashicorp-vault/transit-policy.hcl |
| SI-10 | Secrets Exposure | audit-secrets-exposure.sh | fix-plaintext-secrets.sh | sops/.sops.yaml |

## Application (Layer 7)

| NIST Control | Control Name | Auditor | Fixer | Template |
|-------------|-------------|---------|-------|----------|
| AU-2 | Event Logging | audit-siem-ingest.sh, audit-log-retention.sh | fix-missing-log-source.sh | sentinel/analytics-rule-brute-force.json, splunk/inputs.conf |
| AU-6 | Audit Record Review | audit-alert-rules.sh | fix-sentinel-analytics-rule.md, fix-splunk-alert-rules.sh | sentinel/workbook-soc-overview.json, splunk/savedsearches.conf |
| SI-4 | Monitoring (L7) | audit-edr-agents.sh | fix-defender-active-response.md, fix-wazuh-fim-paths.sh | wazuh/ossec.conf, defender/endpoint-policy.json |
| SI-7 | Software/Info Integrity | audit-edr-agents.sh | fix-wazuh-fim-paths.sh | wazuh/local_rules.xml |
| RA-5 | Vulnerability Scanning | audit-vuln-scan-coverage.sh | fix-cis-failures.sh | kube-bench/job.yaml, kubescape/framework-nsa.yaml |
| SI-10 | Input Validation | — (use ZAP/Semgrep from playbooks) | fix-missing-headers.sh | — |
| SA-11 | Developer Testing | audit-vuln-scan-coverage.sh | — (CI pipeline setup in playbooks) | — |

## How to Use This Map

1. **Assessment:** Identify which NIST control you're auditing
2. **Find the auditor:** Run the corresponding audit-*.sh script
3. **If it fails:** Run the corresponding fixer
4. **For gold-standard config:** Diff your running config against the template
5. **For compliance evidence:** Auditor output + before/after fixer evidence = audit package
