# Anthra-SecLAB Control Map

Maps each lab scenario to OSI layer, GP-Copilot 5 C's package, NIST 800-53 control, and tooling.

| Scenario | NIST Control | OSI Layer | 5 C's Package | Type | Preventive Tool | Detective Tool |
|----------|-------------|-----------|---------------|------|-----------------|----------------|
| SC-7 Boundary Protection | SC-7 | L3 Network | 02-CLUSTER-HARDEN | Preventive + Detective | NetworkPolicy (kubectl) | kube-hunter, Falco |
| CM-7 Least Functionality | CM-7 | L3 Network | 02-CLUSTER-HARDEN | Preventive | NetworkPolicy (kubectl) | Kubescape, Polaris |
| AC-6 Least Privilege | AC-6 | L3 Cluster | 02-CLUSTER-HARDEN | Preventive | RBAC (kubectl) | kubescape, kubectl auth can-i |

## Planned (not yet implemented)

| Scenario | NIST Control | OSI Layer | 5 C's Package | Type | Preventive Tool | Detective Tool |
|----------|-------------|-----------|---------------|------|-----------------|----------------|
| SA-11 Developer Testing | SA-11 | L7 App | 01-APP-SEC | Detective | Semgrep | ZAP |
| RA-5 Vulnerability Scanning | RA-5 | L7 App | 01-APP-SEC | Detective | Trivy | ZAP |
| SC-8 Transmission Confidentiality | SC-8 | L4 Transport | 02-CLUSTER-HARDEN | Preventive | mTLS (Linkerd/Istio) | openssl s_client |
| SC-7 Cloud Boundary | SC-7 | Cloud | 04-CLOUD-SECURITY | Preventive | Security Groups | Prowler |
