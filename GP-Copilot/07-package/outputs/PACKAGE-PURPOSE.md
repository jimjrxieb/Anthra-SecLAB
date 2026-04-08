# What This Package Is

This is a FedRAMP compliance package for the Anthra Security Platform. It was built using `GP-CONSULTING/07-FEDRAMP-READY` — the same scanning, mapping, and documentation tools that a 3PAO auditor evaluates against.

The idea is simple: **use the auditor's own checklist to prepare for the audit.**

---

## What FedRAMP Actually Means

FedRAMP (Federal Risk and Authorization Management Program) is the US government's standard for cloud security. If you want to sell SaaS to a federal agency, your system must demonstrate compliance with NIST 800-53 security controls.

There are three impact levels:

| Level | Controls | Who Uses It |
|-------|----------|-------------|
| **Low** | ~125 | Internal tools, low-sensitivity data |
| **Moderate** | ~323 | Most federal SaaS (this is what Anthra targets) |
| **High** | ~421 | National security, law enforcement, PII at scale |

Each control is a requirement like "AC-6: Least Privilege" or "SC-7: Boundary Protection". The auditor (3PAO) checks whether your system actually implements each one and has evidence to prove it.

**The problem**: Manual FedRAMP authorization takes 12-18 months and costs $500K+. Most of that time is mapping controls, collecting evidence, and writing documentation — work that machines do better than humans.

---

## How We Accomplish It

We use the exact same tools and standards the auditor checks against, then generate the evidence they need to see — automatically.

### The Pipeline

```
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│  1. SCAN            run-fedramp-scan.sh                         │
│     │               Runs trivy, semgrep, gitleaks, checkov,     │
│     │               conftest against the application code       │
│     │               and K8s manifests.                          │
│     │                                                           │
│     ▼                                                           │
│  2. MAP             gap-analysis.py                             │
│     │               Reads raw scan output. Maps every finding   │
│     │               to a NIST 800-53 control. Outputs:          │
│     │                 - control-matrix.md   (MET/PARTIAL/MISSING│
│     │                 - poam.md             (what's still open) │
│     │                 - remediation-plan.md (fix order by rank) │
│     │                                                           │
│     ▼                                                           │
│  3. FIX             01-APP-SEC + 02-CLUSTER-HARDENING           │
│     │               Apply fixes using the same fixer scripts    │
│     │               and policy templates from the consulting    │
│     │               packages. Security contexts, RBAC,          │
│     │               NetworkPolicy, bcrypt, secrets management.  │
│     │                                                           │
│     ▼                                                           │
│  4. RE-SCAN         run-fedramp-scan.sh (again)                 │
│     │               Confirm gaps closed. Coverage goes up.      │
│     │               New evidence replaces old evidence.         │
│     │                                                           │
│     ▼                                                           │
│  5. DOCUMENT        compliance-templates/ + SSP-APPENDIX-A      │
│                     Generate the SSP, POA&M, SAR, and control   │
│                     matrix the 3PAO needs. Evidence paths point  │
│                     directly to scan artifacts.                  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### The Tools (Same Ones the Auditor Validates Against)

| Tool | What It Does | NIST Controls It Covers |
|------|-------------|------------------------|
| **Trivy** | CVE scanning, SBOM, misconfigs | SI-2 (Flaw Remediation), CM-8 (Inventory), RA-5 (Vuln Scanning) |
| **Semgrep** | SAST — SQLi, XSS, injection, insecure patterns | SA-11 (Developer Testing), SI-2 |
| **Gitleaks** | Hardcoded secrets, API keys, tokens | IA-5 (Authenticator Management) |
| **Checkov** | IaC scanning (Terraform, CloudFormation, K8s) | CM-6 (Configuration Settings), CM-7 (Least Functionality) |
| **Conftest/OPA** | Policy-as-code validation for K8s manifests | CM-6, CA-7 (Continuous Monitoring) |
| **Kyverno** | Admission control — blocks bad deploys at apply time | AC-6 (Least Privilege), CM-6 |
| **Falco** | Runtime threat detection in production | AU-2 (Event Logging), CA-7, SI-4 (System Monitoring) |

The auditor doesn't need to trust us. They can run the same scanners, check the same policies, and see the same results. That's the point.

---

## What's In This Directory

```
fedRAMP-package/
├── PACKAGE-PURPOSE.md                      ← You are here
├── SSP-APPENDIX-A-FINDINGS.md              ← Actual findings + remediations for Anthra
└── templates/                              ← Copy-paste templates for FedRAMP controls
    ├── 01-ci-cd-pipeline-template.yml      ← SA-11, SI-2, IA-5
    ├── 02-security-context-template.yaml   ← AC-6, CM-2
    ├── 03-secrets-management-template.yaml ← IA-5(7), SC-28
    ├── 04-network-policy-template.yaml     ← SC-7
    ├── 05-password-hashing-template.py     ← IA-5(1), SC-13
    └── 06-audit-logging-template.py        ← AU-2, AU-3
```

### SSP-APPENDIX-A-FINDINGS.md

This is the real output. It documents every finding from the initial scan, what NIST control it maps to, what was done to fix it, and whether the fix closed the gap. As of Feb 2026, all 41 findings across 5 control families are CLOSED:

- **AC (Access Control)** — 10 findings: containers running as root, excessive capabilities
- **IA (Identity & Auth)** — 9 findings: MD5 hashing, hardcoded credentials
- **SC (System & Comms)** — 9 findings: cleartext HTTP, disabled SSL
- **CM (Config Management)** — 14 findings: missing resource limits, `:latest` tags
- **SI (System Integrity)** — 2 findings: vulnerable dependencies, verbose errors

### templates/

These are the implementation patterns. When `gap-analysis.py` says a control is MISSING, you grab the matching template, adapt it to the application, and apply it. Each template has the NIST control ID in its filename so the auditor can trace directly from requirement to implementation.

---

## The Script That Turns Logs Into Readable Data

The key script is `gap-analysis.py` in `07-FEDRAMP-READY/tools/`. It takes raw scanner JSON (hundreds of lines of trivy/semgrep/gitleaks/checkov output) and produces three clean documents:

### 1. control-matrix.md — "Where do we stand?"

Maps 27 FedRAMP Moderate controls to four statuses:

| Status | Meaning |
|--------|---------|
| **MET** | Scanner evidence confirms the control is implemented |
| **PARTIAL** | Some evidence exists but gaps remain |
| **MISSING** | No evidence — needs full implementation |
| **MANUAL** | Can't be scanner-verified (requires policy docs, pen test, etc.) |

### 2. poam.md — "What's still open?"

Pre-populated Plan of Action & Milestones. This is a FedRAMP-required artifact. The script fills in control ID, name, status, priority, and finding count. You add target dates and owners.

### 3. remediation-plan.md — "Fix order"

Findings sorted by Iron Legion rank:

| Rank | Who Fixes It | Action |
|------|-------------|--------|
| **B** | Human | Review and decide — JADE provides intel |
| **C** | JADE | AI proposes fix, human approves |
| **D** | JSA agents | Auto-fix with logging |
| **E** | JSA agents | Auto-fix, no approval needed |

Work top to bottom. B-rank first (credential rotations, architecture decisions), then let the automation handle the rest.

### How to run it

```bash
# Full scan + gap analysis (one command)
bash ~/linkops-industries/GP-copilot/GP-CONSULTING/07-FEDRAMP-READY/tools/run-fedramp-scan.sh \
  --client-name "Anthra Security" \
  --target-dir ~/linkops-industries/GP-copilot/GP-PROJECTS/01-instance/slot-3/Anthra-SecLAB

# Output lands in ./evidence-YYYY-MM-DD/
#   scan-reports/    ← raw scanner JSON
#   gap-analysis/    ← control-matrix.md, poam.md, remediation-plan.md

# Gap analysis only (re-run after fixes without re-scanning)
python3 ~/linkops-industries/GP-copilot/GP-CONSULTING/07-FEDRAMP-READY/tools/gap-analysis.py \
  --client-name "Anthra Security" \
  --scan-dir ./evidence-2026-03-03/scan-reports \
  --output-dir ./evidence-2026-03-03/gap-analysis
```

---

## Anthra's Progress

```
Baseline (Feb 12):     42%  coverage — 15 MISSING, 11 PARTIAL, 0 MET
After hardening:       88%  coverage — 3 MISSING, 18 PARTIAL, 5 MET
Current (Feb 24):      ~85% readiness (technical controls done, monitoring pending)

Remaining gaps:
  AU-3  — Audit log content (closes when Falco is collecting)
  IR-4  — Incident response plan (requires written procedure)
  SI-4  — System monitoring (closes when jsa-infrasec is running)
```

---

## Connection to GP-CONSULTING/07-FEDRAMP-READY

This package is a **client instance** of `07-FEDRAMP-READY`. The relationship:

```
07-FEDRAMP-READY/                        ← The toolkit (scanning, policies, templates)
├── tools/run-fedramp-scan.sh            ← Orchestrates all scanners
├── tools/gap-analysis.py                ← Turns raw logs into readable reports
├── policies/                            ← OPA/Kyverno/Gatekeeper policies
├── compliance-templates/                ← SSP, POA&M, SAR skeletons
└── scanning-configs/                    ← Scanner config files

Anthra-SecLAB/GP-Copilot/fedRAMP-package/  ← The output (evidence for this client)
├── SSP-APPENDIX-A-FINDINGS.md           ← Anthra's actual findings + remediations
└── templates/                           ← Adapted templates applied to Anthra
```

The toolkit is reusable. Point it at any application, get the same structured output. The fedRAMP-package here is what that output looks like for a real engagement.

---

*Ghost Protocol — By the time you check the dashboard, it's already handled.*
