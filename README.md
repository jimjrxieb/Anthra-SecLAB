# Anthra-SecLAB

**Staging environment for [anthra.dev](https://anthra.dev)**
**Operator:** Ghost Protocol (LinkOps Industries)
**Purpose:** Break it. Fix it. Attack it. Remediate it. Prove the hardening works.

> **This is a security lab, not production.**
>
> Anthra-SecLAB is the staging version of my real portfolio site. It exists to validate that every hardening measure, policy, and security control actually holds up under pressure. Think of it as Conftest for the entire 5 C's — not just policy validation, but full-stack attack and remediation across Code, Container, Cluster, Cloud, and Compliance.
>
> Things will be intentionally broken here. Vulnerabilities will be introduced, exploited, and then remediated — with evidence at every step. If it survives SecLAB, it ships to production.

---

## What Happens Here

| Phase | What | Why |
|-------|------|-----|
| **Break** | Introduce real vulnerabilities — XSS, SQLi, misconfigs, permissive RBAC, missing NetworkPolicy | You can't prove a defense works if you've never tested it against an actual attack |
| **Attack** | Run offensive tools — DAST, manual exploitation, privilege escalation, container escape attempts | Scanners find patterns. Attacks find gaps. Both matter. |
| **Remediate** | Fix with GP-Copilot packages — auto-fix scripts, policy-as-code, runtime detection | The remediation is the deliverable. Prove it works, not just that it exists. |
| **Verify** | Rescan, retest, collect evidence — before/after metrics across all 5 C's | If the scanner still fires or the attack still lands, the fix isn't done. |

---

## The 5 C's — Lab Coverage

Every security domain gets tested end-to-end:

| C | Attack Surface | Tools | GP-Copilot Package |
|---|---------------|-------|--------------------|
| **Code** | SAST findings, dependency CVEs, hardcoded secrets, unsafe deserialization | Semgrep, Bandit, Gitleaks, Trivy, Grype | `01-APP-SEC` |
| **Container** | Root containers, unpinned images, missing healthchecks, writable filesystems | Hadolint, Checkov, Trivy image scan | `01-APP-SEC` |
| **Cluster** | Permissive RBAC, no PSS, missing NetworkPolicy, exposed service accounts | Kubescape, Polaris, Conftest, Kyverno | `02-CLUSTER-HARDEN` |
| **Cloud** | Open security groups, unencrypted storage, over-permissive IAM, missing logging | Checkov, Prowler, Trivy IaC | `04-CLOUD-SECURITY` |
| **Compliance** | Control gaps, missing evidence, incomplete SSP, stale POA&M | scan-and-map.py, gap-analysis.py | `05-COMPLIANCE-READY` |

---

## Architecture

```
+---------------------------------------------------------+
|                    ANTHRA PLATFORM                        |
+---------------------------------------------------------+
|                                                          |
|   UI Layer           API Layer          Ingest Layer     |
|                                                          |
|   React              FastAPI            Go Service       |
|   Dashboard    <-->   (Python)     <-->  Log Ingest      |
|   (Port 8080)        (Port 8080)        (Port 9090)     |
|                           |                  |           |
|                           +------+-----------+           |
|                                  v                       |
|                            PostgreSQL                    |
|                            (Port 5432)                   |
|                                                          |
|   Security Layer (GP-Copilot)                            |
|   ----------------------------------                     |
|   Kyverno (admission) | Falco (runtime) | ArgoCD (GitOps)
|                                                          |
+---------------------------------------------------------+
```

Stack: Python (FastAPI), Go, React, PostgreSQL on EKS

---

## Directory Structure

```
Anthra-SecLAB/
+-- README.md                        # This file
+-- PRE-DEPLOYMENT-IMPLEMENTATION.md # Implementation guide
+-- docker-compose.yml               # Local dev stack
|
+-- api/                             # Python FastAPI application
+-- services/                        # Go log-ingest microservice
+-- ui/                              # React dashboard
+-- db/                              # Database initialization
+-- policies/                        # App-level OPA policies
+-- scripts/                         # App scripts
|
+-- infrastructure/                  # All infrastructure-as-code
|   +-- anthra-api/                  # base/ + overlays/ + argocd/
|   +-- anthra-ui/
|   +-- anthra-log-ingest/
|   +-- anthra-db/
|   +-- kustomize/                   # Kustomize base + overlays (local/staging)
|   +-- terraform/                   # EKS infrastructure
|   +-- ansible/                     # EC2 provisioning + app deploy
|
+-- GP-Copilot/                      # Engagement artifacts + evidence
    +-- 01-package/                  # APP-SEC
    +-- 02-package/                  # CLUSTER-HARDEN
    +-- 03-package/                  # DEPLOY-RUNTIME
    +-- 05-package/                  # COMPLIANCE-READY
    +-- 07-package/                  # FEDRAMP-READY (legacy)
```

---

## Quick Start

```bash
# Start the platform locally
docker compose up -d

# Access UI
kubectl port-forward svc/novasec-ui -n anthra 8080:8080 &
open http://localhost:8080

# Run full 5C scan
PKG=~/linkops-industries/GP-copilot/GP-CONSULTING
bash $PKG/01-APP-SEC/tools/run-all-scanners.sh --target .

# Run gap analysis
python3 $PKG/07-FEDRAMP-READY/tools/gap-analysis.py --target . --output /tmp/gap-analysis/
```

---

## Reports

Scan outputs and evidence: `GP-S3/5-consulting-reports/01-instance/slot-3/`

---

*Break it. Fix it. Prove it. Ship it.*
