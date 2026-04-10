# Changelog

## 2026-04-05 — Phase 1: Clean House

### Removed

**Application code (Anthra security monitoring SaaS):**
- `api/` — Python FastAPI backend (61KB main.py, bcrypt auth, JWT, PostgreSQL)
- `services/` — Go log-ingest microservice (TLS PostgreSQL, 4KB)
- `ui/` — React 18 dashboard (49KB App.jsx, Vite, security compliance display)
- `db/` — PostgreSQL initialization scripts (init.sql)

**Kustomize overlays (Anthra-specific):**
- `infrastructure/anthra-api/` — base + overlays (dev/staging/prod) + ArgoCD apps
- `infrastructure/anthra-ui/` — base + overlays + ArgoCD apps
- `infrastructure/anthra-db/` — base + overlays + ArgoCD apps
- `infrastructure/anthra-log-ingest/` — base + overlays + ArgoCD apps

**Configuration:**
- `docker-compose.yml` — Anthra local dev stack (PostgreSQL + API + UI + Go)
- `docker-compose.yml.bak` — Backup of above
- `PRE-DEPLOYMENT-IMPLEMENTATION.md` — Anthra-specific deployment guide

### Kept

**Infrastructure (Terraform modules):**
- `infrastructure/terraform/modules/vpc/` — 3-tier network (public/private/database subnets, NAT, flow logs)
- `infrastructure/terraform/modules/eks/` — EKS module (to be replaced by ec2/ module in Phase 3)
- `infrastructure/terraform/modules/iam/` — IAM roles, IRSA
- `infrastructure/terraform/modules/rds/` — PostgreSQL RDS (may not be needed — Portfolio uses ChromaDB)
- `infrastructure/terraform/modules/s3/` — Log archival buckets
- `infrastructure/terraform/modules/secrets/` — Secrets Manager
- `infrastructure/terraform/modules/security/` — CloudTrail, GuardDuty, SNS alerts
- `infrastructure/terraform/modules/cloudwatch/` — Logging, metrics, alarms

**Policies:**
- `policies/` — Kyverno, OPA/Conftest, Gatekeeper (transfer directly to new deploy)

**GP-Copilot engagement evidence:**
- `GP-Copilot/01-package/` — APP-SEC scan results, fixer scripts
- `GP-Copilot/02-package/` — CLUSTER-HARDENING Kyverno/OPA policies
- `GP-Copilot/03-package/` — DEPLOY-RUNTIME Falco setup
- `GP-Copilot/07-package/` — FEDRAMP-READY SSP, gap analysis

**Supporting files:**
- `.pre-commit-config.yaml`, `.bandit.yaml`, `.hadolint.yaml`, `.yamllint.yaml`
- `docs/`, `scripts/`, `.github/`

### Why

**FinOps decision.** The Anthra app is a fictional security monitoring SaaS built to demonstrate FedRAMP compliance gaps. Portfolio is the real production app serving linksmlm.com. Staging should test the real app against real infrastructure.

The infrastructure modules (VPC, IAM, S3, CloudWatch, security) are cloud-agnostic enough to reuse. The EKS module gets replaced with an EC2 module running k3s — same Kubernetes API at a fraction of the cost.

**What stays is what transfers:** Terraform modules, admission control policies, and engagement evidence. What goes is Anthra-specific application code that serves no purpose in a staging environment for a different app.

---

## 2026-04-05 — Phase 2 (partial): Copy Portfolio App

### Added

**Application code (Portfolio — same as linksmlm.com production):**

Application code at root — same layout as Portfolio production:

- `api/` — FastAPI backend (main.py, routes/chat.py, routes/health.py, Dockerfile)
- `backend/` — Shared Python modules (settings.py, engines/rag_engine.py, engines/llm_interface.py, personality/loader.py)
- `ui/` — React 18 + Vite + TailwindCSS + MUI (Dockerfile, src/, tests/, package.json)
- `data/chromadb-config/` — ChromaDB Dockerfile and health check
- `rag-pipeline/` — RAG ingestion scripts (run_pipeline.py, requirements.txt — no data)
- `docker-compose.yml` — Local dev stack (API + UI + ChromaDB)

**Supporting files:**
- `.env.example` — Environment template (no secrets)
- `Makefile` — Build and dev commands
- `package.json` — Root package wrapper
- `.eslintrc.json`, `.pylintrc` — Linting configs

**Updated:**
- `.gitignore` — Added node_modules, .env, .terraform, ChromaDB data, RAG pipeline data exclusions

### Source

Copied from `GP-PROJECTS/01-instance/slot-1/Portfolio-Prod/` (production). 79 files, no secrets, no runtime data, no node_modules.

### What's Next

- Phase 2 (remaining): Kustomize base + overlays for staging deploy, ArgoCD Application manifests
- Phase 3: Terraform EC2 module (replaces EKS) + Ansible playbooks for k3s

---

## 2026-04-05 — Phase 3: Terraform EC2 + Ansible k3s

### Added

**Terraform EC2 module** (`infrastructure/terraform/modules/ec2/`):
- EC2 instance (Ubuntu 22.04 LTS, gp3 encrypted EBS)
- Security group: SSH + HTTP/S + K8s API (admin CIDR restricted)
- IAM instance profile: CloudWatch, S3 logs, Secrets Manager, ECR pull
- Elastic IP for stable DNS
- IMDSv2 enforced, detailed monitoring enabled
- NIST: AC-3, CM-2, SC-7

**Ansible playbooks** (`infrastructure/ansible/`):
- `roles/k3s-install/` — k3s v1.31, Helm, secrets encryption at rest (CM-2)
- `roles/k3s-harden/` — sysctl hardening, SSH lockdown, UFW firewall, PSS labels (AC-6, SC-7, CM-6, CM-7)
- `roles/auditd/` — 15 audit rule categories: identity, sudo, SSH, k3s, cron, kernel, time, network, file deletion (AU-2, AU-3, AU-12)
- `roles/cloudwatch-agent/` — syslog + auditd + k3s-audit + auth.log → CloudWatch (AU-6, SI-4)
- `roles/app-deploy/` — Traefik ingress, ArgoCD, portfolio namespace with PSS (CM-3)
- `playbooks/site.yml` — Orchestrates all roles in order

**Root Terraform updates:**
- `main.tf` — EC2 module active, EKS/RDS/IAM commented with FinOps rationale
- `variables.tf` — EC2 vars active, EKS vars commented (switchable)
- `outputs.tf` — k3s IP, SSH command, Ansible inventory line
- `environments/staging/terraform.tfvars` — t3.small, 30GB, staging config

**CloudWatch module updated:**
- Replaced EKS/RDS alarms with EC2 host alarms (CPU, status check, memory, disk)
- Added log groups: k3s cluster, application, auditd
- Security alarms preserved: root account usage, signin failures, unauthorized API

### Kept (reference, not deployed)

- `modules/eks/` — Full EKS module. $73/mo control plane vs ~$15/mo k3s on EC2.
- `modules/iam/` — IRSA roles. Requires EKS OIDC provider.
- `modules/rds/` — PostgreSQL. Portfolio uses ChromaDB, not Postgres.

---

## 2026-04-05 — Phase 4: Observability Stack

### Added

**DAST Scanning:**
- `scripts/security/run-zap-scan.sh` — OWASP ZAP baseline + full active scan via Docker
- `scripts/security/zap-scan.conf` — Rule config with NIST control mapping per rule ID
- Outputs JSON + HTML reports to `reports/zap/` (NIST: RA-5, SA-11)

**Vulnerability Scanning:**
- `scripts/security/run-nuclei-scan.sh` — Nuclei scanner, local or Docker, severity filtering
- Outputs JSON + Markdown reports to `reports/nuclei/` (NIST: RA-5, SI-2)
- Finding counts by severity in terminal output

**SIEM — Loki + Promtail + Grafana** (`infrastructure/ansible/roles/loki-stack/`):
- Loki: single-binary mode, filesystem storage, 30-day retention, 256MB limit
- Promtail: collects pod logs + syslog + k3s-audit + auth.log + auditd
- Grafana: Loki pre-configured as datasource, K8s logs dashboard
- All deployed via Helm on k3s in monitoring namespace
- NIST: AU-6, AU-7, SI-4

**Already wired from Phase 3 (no new work needed):**
- CloudTrail → Terraform security module (active)
- Auditd → Ansible auditd role (15 rule categories)
- CloudWatch Agent → Ansible role (ships 4 log streams)

### SIEM Decision: Loki over Elastic

| Factor | Loki | Elasticsearch |
|--------|------|---------------|
| Memory | ~256MB | 2GB+ minimum |
| Fits t3.small | Yes | No |
| License cost | $0 | $0 (OSS) / $$$ (features) |
| Query language | LogQL (Prometheus-like) | KQL/Lucene |
| Enterprise equivalent | Splunk | Splunk |

Loki wins on FinOps. Same log aggregation, fraction of the resources.

### What's Next

- Phase 5: Compliance mapping — every Ansible task → NIST 800-53 control
- Phase 6: Break scenarios — intentional misconfigs, attack runbooks
