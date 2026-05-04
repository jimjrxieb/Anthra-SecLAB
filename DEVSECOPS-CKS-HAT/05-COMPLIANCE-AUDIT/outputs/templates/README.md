# FedRAMP Moderate Best Practice Templates

This folder contains "Copy-and-Paste" style templates for implementing FedRAMP Moderate security controls (NIST 800-53 Rev 5). Use these to ensure your application meets the Ghost Protocol hardening standards.

## Template Index

| File | NIST Control | Purpose |
|------|--------------|---------|
| `01-ci-cd-pipeline-template.yml` | **SA-11, SI-2, IA-5** | Security scanning pipeline for GitHub Actions. |
| `02-security-context-template.yaml` | **AC-6, CM-2** | Hardened pod security settings (non-root, drop capabilities). |
| `03-secrets-management-template.yaml`| **IA-5(7), SC-28** | Safe credential injection via K8s Secrets. |
| `04-network-policy-template.yaml` | **SC-7** | Default-deny network segmentation for Kubernetes. |
| `05-password-hashing-template.py` | **IA-5(1), SC-13** | Secure `bcrypt` implementation for Python applications. |
| `06-audit-logging-template.py` | **AU-2, AU-3** | Structured JSON audit logging for security events. |

## How to Use

1.  **Review:** Open the relevant template and understand the NIST control it addresses.
2.  **Adapt:** Replace placeholders (e.g., `REPLACE_WITH_SECURE_PASSWORD`) with your specific values or logic.
3.  **Apply:** Copy the code or manifest into your project.
4.  **Verify:** Run the CI/CD pipeline or use `kubectl apply --dry-run=client` to validate the implementation.

---

*Powered by Ghost Protocol - Iron Legion Platform*
