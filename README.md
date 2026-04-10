# Anthra-SecLAB

**Security home lab for hands-on NIST 800-53 control implementation, break/fix training, and CISO governance reporting.**

**Operator:** Jimmie (LinkOps Industries)
**Target Application:** [anthra.dev](https://anthra.dev) — deployed locally as the attack surface
**Certifications:** Security+ (completed), CySA+ (studying), CKA (completed), CKS (studying)

> Anthra is not a staging version of my portfolio. It is a deliberately vulnerable deployment of my portfolio application, running in a local k3s cluster with a full SOC tool stack, used as the target for security control validation across all 7 OSI layers.
>
> Two security tracks run against this single target application. Each track has its own playbooks, tools, templates, correct configurations, and best-practice recommendations — backed by the certifications I hold and the ones I'm studying for.

---

## Two Tracks, One Target

| Track | Directory | Backed By | Focus |
|-------|-----------|-----------|-------|
| **OSI-MODEL Security** | `OSI-MODEL/` | Security+ (completed), CySA+ (studying) | Secure by layer. NIST 800-53 controls mapped to each OSI layer. Microsoft Defender + open source tools. Governance reporting for CISO communication. |
| **DevSecOps CKS** | `OSS-Copilot/` | CKA (completed), CKS (studying) | Secure by pipeline. Kubernetes-native security — admission control, runtime detection, RBAC, Pod Security Standards. Open source tooling for the 5 C's. |

---

## What Happens Here

### Break/Fix Training

During live sessions, Claude Code breaks something — simulating a bad configuration push or a threat actor introducing a misconfiguration. I pinpoint the issue, map it to the NIST 800-53 control ID, identify which OSI layer it affects, and correct it using the playbooks and tools in this lab.

Every scenario follows the same cycle:

1. **Control** — understand the NIST 800-53 requirement and WHY it exists
2. **Break** — introduce the misconfiguration (Claude Code simulates the threat)
3. **Detect** — confirm the detective tools catch the gap
4. **Fix** — remediate using the correct tool and configuration
5. **Validate** — confirm the fix holds under re-test
6. **Govern** — translate the finding into business risk for CISO reporting (dollar value, ROSI, compliance impact)

### What This Proves

| Step | What It Demonstrates |
|------|---------------------|
| Control first | I think in frameworks, not tools |
| Break | I understand attack surface and failure modes |
| Detect | I understand defense in depth |
| Fix | I close the loop — finding without fixing is useless |
| Validate | I verify, not assume |
| Govern | I communicate business risk, not just technical findings |

---

## Directory Structure

```
Anthra-SecLAB/
|
|-- target-application/          # The app we attack (FastAPI + React + PostgreSQL)
|   |-- api/                     # Python FastAPI backend
|   |-- ui/                      # React frontend
|   |-- services/                # Go log-ingest microservice
|   |-- infrastructure/          # Kustomize manifests for k3s deployment
|   |-- docker-compose.yml       # Local dev stack
|
|-- OSI-MODEL/                   # Security by OSI layer (CySA+ track)
|   |-- 01-PHYSICAL-LAYER/       # PE controls — physical access, environmental
|   |-- 02-DATA-LINK-LAYER/      # SC-7, AC-3 — ARP, VLAN, 802.1X
|   |-- 03-NETWORK-LAYER/        # SC-7, AC-4 — firewalls, segmentation, IDS/IPS
|   |-- 04-TRANSPORT-LAYER/      # SC-8, IA-5 — TLS, certificates
|   |-- 05-SESSION-LAYER/        # AC-12, SC-23 — session mgmt, tokens
|   |-- 06-PRESENTATION-LAYER/   # SC-28, SC-13 — encryption at rest, crypto
|   |-- 07-APPLICATION-LAYER/    # SI-10, AU-2 — input validation, logging
|   Each layer contains:
|     control-map.md             # NIST control -> tool -> enterprise equivalent
|     scenarios/                 # break/detect/fix/validate/governance per control
|     playbooks/                 # assess, implement, break-fix, ciso-report
|
|-- OSS-Copilot/                 # DevSecOps by pipeline (CKS track)
|   |-- 01-APP-SEC/              # SAST, secrets, deps, Dockerfiles
|   |-- 02-CLUSTER-HARDEN/       # CIS benchmarks, admission control, RBAC
|   |-- 03-RUNTIME-SEC/          # Falco, watchers, responders
|   |-- 04-CLOUD-SEC/            # AWS/Azure controls
|   |-- 05-COMPLIANCE-AUDIT/     # NIST mapping, evidence packaging
|
|-- scenarios/                   # Practice break/fix scenarios
|   |-- SC-7-boundary-protection/
|   |-- CM-7-least-functionality/
|   |-- AC-6-least-privilege/
|   Each scenario has: break.sh, detect.sh, fix.sh, evidence-template.md
|
|-- SecLAB-setup/                # Lab environment setup
|   |-- 01-cluster-setup/        # k3d config, setup/teardown scripts
|   |-- 02-soc-stack/            # Falco, Prometheus, Grafana, Kyverno, Fluent Bit
|   Spins up a k3s cluster with IDS/IPS, admission control, metrics,
|   and log shipping to Splunk. Open source SOC stack favoring
|   Microsoft Defender equivalents where applicable.
|
|-- evidence/                    # Scanner output from scenario runs (gitignored)
|-- tools/                       # Evidence collection pipeline, SHA256 manifests
|-- docs/                        # Control map, POA&M template, specs, plans
```

---

## SOC Tool Stack

Deployed via `SecLAB-setup/02-soc-stack/deploy-stack.sh`:

| Tool | SOC Role | What It Replaces | NIST Controls |
|------|----------|-----------------|---------------|
| **Falco** | Runtime detection | CrowdStrike Falcon, Sysdig Secure | SI-4, AU-2, IR-4 |
| **Prometheus + Grafana** | Metrics + dashboards | Datadog, Dynatrace | SI-4, AU-6, CA-7 |
| **Kyverno** | Admission control | Styra DAS, OPA Enterprise | CM-7, AC-6, CM-2 |
| **Fluent Bit** | Log shipping | Splunk Universal Forwarder | AU-2, AU-3, AU-4 |
| **Splunk** | SIEM | Splunk ES, Microsoft Sentinel | AU-6, IR-4, IR-5 |

---

## Access

| Service | URL | Purpose |
|---------|-----|---------|
| Anthra UI | http://localhost:30000 | Target application |
| Anthra API | http://localhost:30080 | API health check |
| Splunk | http://localhost:8000 | SIEM — logs, alerts, investigation |
| Grafana | http://localhost:30030 | Dashboards — metrics, SOC overview |

---

## Reports

Evidence and governance reports land in:
- `evidence/` — working directory for scanner output (gitignored)
- `GP-S3/6-seclab-reports/` — finalized reports, CISO briefs, POA&M, AI training data

---

## Quick Start

```bash
# 1. Start the lab cluster + target app
bash SecLAB-setup/01-cluster-setup/setup-cluster.sh

# 2. Deploy SOC tool stack
bash SecLAB-setup/02-soc-stack/deploy-stack.sh

# 3. Run a break/fix scenario
bash scenarios/SC-7-boundary-protection/fix.sh    # Establish baseline
bash scenarios/SC-7-boundary-protection/break.sh   # Break the control
bash scenarios/SC-7-boundary-protection/detect.sh  # Detect the gap
bash scenarios/SC-7-boundary-protection/fix.sh     # Remediate

# 4. Collect evidence
bash tools/collect-evidence.sh
```

---

*Implement the control. Break it the way an attacker or a misconfigured AI would. Confirm the detection layer catches it. Fix it. Translate the finding into business risk. That's the full loop.*

---

## Labs and Scenarios to Master

The following are the skills this lab is designed to build. Claude Code introduces the misconfigurations. I investigate, identify, fix, and document.

### Control Implementation Across OSI Layers

| OSI Layer | NIST Controls | Tools | What Gets Broken |
|-----------|--------------|-------|------------------|
| **L7 Application** | SA-11 developer security testing, RA-5 vulnerability scanning | Semgrep, Bandit, OWASP ZAP, Nuclei | Insecure code patterns, unpatched dependencies, exposed debug endpoints |
| **L4 Transport** | SC-8 transmission confidentiality | mTLS enforcement, TLS policy validation | Disabled mTLS, expired certificates, plaintext service-to-service traffic |
| **L3 Network** | SC-7 boundary protection, CM-7 least functionality | NetworkPolicy, VPC segmentation, admission control gates | Deleted NetworkPolicies, over-permissive ingress rules, wildcard port ranges |
| **L3 Identity** | AC-6 least privilege, AC-2 account management | RBAC scoped service accounts, service account audit | Wildcard ClusterRoleBindings, default service accounts with elevated privileges |

### Break/Fix Methodology

Introduces deliberate misconfigurations in staging — deleted NetworkPolicies, wildcard ClusterRoleBindings, disabled mTLS, missing securityContext, over-permissive ingress rules — then validates that detective controls fire before remediating and rescanning to confirm fixes held.

### Vulnerability Management Lifecycle

1. **Identify** findings via scanner (RA-5)
2. **Risk-score** by CVSS severity, EPSS exploitation probability, and blast radius
3. **Prioritize** by asset criticality and exposure
4. **Remediate** (SI-2)
5. **Re-scan** to verify (CA-7)
6. **Document** evidence with SHA256 manifest
7. **Log** to POA&M

### Detective Control Validation

Falco eBPF rules verified against deliberate attack scenarios — privilege escalation attempts, lateral movement simulation, kube-hunter probes, unauthorized API calls — confirming rules fire before findings are closed.

### NIST 800-53 Evidence Chain

Every control traces: finding → fix → re-scan → evidence file. Control families covered:

| Family | Name |
|--------|------|
| AC | Access Control |
| AU | Audit and Accountability |
| CA | Assessment, Authorization, and Monitoring |
| CM | Configuration Management |
| IA | Identification and Authentication |
| IR | Incident Response |
| RA | Risk Assessment |
| SA | System and Services Acquisition |
| SC | System and Communications Protection |
| SI | System and Information Integrity |

### SIEM Integration

Falco alerts forwarded via Fluent Bit to Microsoft Sentinel — KQL correlation rules written to detect cross-layer attack patterns, reducing alert noise and surfacing true positives for analyst review.

### CISO Reporting

Technical findings translated to business risk language — lateral movement exposure, compliance gap, blast radius assessment, remediation timeline, and business impact — structured as executive risk summaries per scan cycle.

### Playbook-Driven

Each OSI layer scenario documented as a step-by-step runbook covering break procedure, expected detection, fix commands, and evidence collection — repeatable by any analyst on the team.

---

## Why This Lab Exists

This is the lab behind the resume line. Every bullet on the resume traces back to a scenario that ran here, against this target application, with this tool stack.

```
Resume bullet                          →  Lab proof
─────────────────────────────────────────────────────────────────────
OSI-layered control implementation     →  OSI-MODEL/ scenarios per layer
Vulnerability management lifecycle     →  evidence/ scan outputs + POA&M
Break/fix validation methodology       →  scenarios/ break.sh → detect.sh → fix.sh
NIST 800-53 evidence chain             →  tools/collect-evidence.sh + SHA256 manifests
SIEM operations                        →  SecLAB-setup/02-soc-stack/ Falco → Fluent Bit → Sentinel
Executive reporting                    →  GP-S3/6-seclab-reports/ CISO briefs
Documented playbooks                   →  OSI-MODEL/*/playbooks/ per layer
```

Nothing on the resume is theoretical. If an interviewer asks "show me," the answer is `git log`, the evidence directory, and a live demo on this cluster.
