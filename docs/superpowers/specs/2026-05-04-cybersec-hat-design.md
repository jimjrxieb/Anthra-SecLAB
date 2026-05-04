# CYBERSEC-HAT Design Spec
**Date:** 2026-05-04
**Author:** Jimmie Coleman
**Status:** Approved

---

## Purpose

This is the CYSA hat folder. When Jimmie puts on the cybersecurity analyst hat, this is where he goes. It is distinct from `DEVSECOPS-CKS-HAT` (K8s/DevSecOps engineer) and `GRC-HAT` (compliance/controls). They overlap in some places — the same misconfiguration can be a finding in all three — but this folder lives in the analyst's POV: detect, investigate, remediate, prove.

---

## Organizing Principle

**4 analyst functions + 1 thin evidence crosswalk.**

Primary structure mirrors how a 3-5 year cybersecurity analyst operates day to day: triage alerts, hunt proactively, respond to incidents, manage vulnerabilities. ATT&CK technique IDs tag every scenario — they are not the structure, they are the label.

GRC evidence is embedded in every scenario (`governance.md` + `evidence-checklist.md`). A single `EVIDENCE-INDEX.md` at the root gives GRC one place to look up which scenario covers which NIST control, without the analyst folder being reorganized around compliance.

---

## Folder Structure

```
CYBERSEC-HAT/
├── EVIDENCE-INDEX.md               ← NIST control → scenario path (GRC crosswalk)
├── 01-SOC-TRIAGE/
├── 02-THREAT-HUNTING/
├── 03-INCIDENT-RESPONSE/
└── 04-VULN-MANAGEMENT/
```

---

## Standard Shape (all 4 sections)

```
01-SOC-TRIAGE/
├── README.md                       ← what this function covers, NIST controls, tools
├── control-map.md                  ← NIST/CIS/CSF → tool → enterprise equiv → gap indicator
├── 01-auditors/                    ← scripts that assess detection/coverage posture
├── 02-playbooks/                   ← numbered analyst workflows
├── scenarios/                      ← ATT&CK-tagged scenario folders
├── tools/                          ← SIEM queries, Sigma rules, log parsers
└── evidence/                       ← gitignored, collected artifacts
```

---

## Standard Scenario Template (all sections)

```
scenarios/T1566.001-phishing-email/
├── detect.sh                       ← SIEM query or log search to surface the technique
├── investigate.md                  ← triage checklist: what to look at, questions to answer
├── remediate.md                    ← what to fix
├── evidence-checklist.md           ← artifacts to collect for GRC (logs, screenshots, IOCs)
└── governance.md                   ← NIST/CIS/CSF control mapping + audit narrative
```

No `break.sh`. This is the analyst POV — detect and respond, not break and fix.

---

## 01-SOC-TRIAGE

**What it covers:** Alert intake, SIEM triage, escalation decisions, L1/L2 analyst workflows.

**NIST Controls:** SI-4 (System Monitoring), AU-6 (Audit Review), IR-6 (Incident Reporting)

**Tools:** Splunk, Elastic/ELK, Microsoft Sentinel, Wazuh

**Scenarios:**
| Scenario | ATT&CK | What It Tests |
|----------|--------|---------------|
| T1566.001-phishing-email | T1566.001 | Email alert triage, header analysis, sandbox verdict |
| T1078-valid-account-abuse | T1078 | Impossible travel, off-hours login, MFA bypass |
| T1110-brute-force-lockout | T1110 | Failed login spike, threshold analysis, lockout review |
| T1059.001-malicious-powershell | T1059.001 | Encoded command, suspicious parent process, EDR alert |

**Playbooks:**
- `01-alert-intake.md` — receive, classify, assign severity
- `02-triage-workflow.md` — investigate, document, decide
- `03-escalation-criteria.md` — when to escalate, how to hand off

---

## 02-THREAT-HUNTING

**What it covers:** Proactive, hypothesis-driven investigation. No alert required. Analyst goes looking.

**NIST Controls:** SI-4 (System Monitoring), CA-7 (Continuous Monitoring), RA-5 (Vulnerability Monitoring)

**Tools:** Velociraptor, OSQuery, Splunk Hunting, Elastic Hunting, Zeek logs

**Scenarios:**
| Scenario | ATT&CK | What It Tests |
|----------|--------|---------------|
| T1003-credential-dumping | T1003 | Hunt for LSASS access, unusual process memory reads |
| T1055-process-injection | T1055 | Unusual parent-child relationships, hollowing indicators |
| T1021.001-rdp-lateral-movement | T1021.001 | Internal RDP spikes, new src→dst pairs, odd-hours activity |
| T1053-persistence-scheduled-task | T1053 | New scheduled tasks, unusual authors/paths |

**Playbooks:**
- `01-hunt-hypothesis.md` — form hypothesis, define scope, define success
- `02-data-collection.md` — what logs/telemetry to pull, how to baseline normal
- `03-hunt-execution.md` — run queries, pivot on findings
- `04-findings-report.md` — document findings, convert to detections or findings

---

## 03-INCIDENT-RESPONSE

**What it covers:** Full lifecycle response. Contain → investigate → eradicate → recover → document.

**NIST Controls:** IR-4 (Incident Handling), IR-5 (Incident Monitoring), IR-8 (Incident Response Plan)

**Tools:** Velociraptor, TheHive, IRIS, Cortex, memory forensics (Volatility), disk forensics

**Scenarios:**
| Scenario | ATT&CK Coverage | What It Tests |
|----------|----------------|---------------|
| ransomware-response | T1486, T1490 | Contain → isolate → preserve evidence → eradicate → recover |
| phishing-compromise | T1566, T1078 | Account reset → MFA enforce → scope the blast radius |
| credential-theft-response | T1003, T1550 | Credential rotation → session kill → lateral movement audit |

**Playbooks:**
- `01-incident-declaration.md` — what triggers an incident, severity tiers
- `02-containment.md` — isolation procedures, network blocks, account locks
- `03-investigation.md` — evidence collection, timeline reconstruction
- `04-eradication.md` — remove the threat, patch the entry point
- `05-recovery.md` — restore, validate, monitor
- `06-post-incident-review.md` — lessons learned, detection gaps, control failures

---

## 04-VULN-MANAGEMENT

**What it covers:** Scan → prioritize → remediate → verify loop. CVSS scoring, compensating controls, patch tracking.

**NIST Controls:** RA-5 (Vulnerability Scanning), SI-2 (Flaw Remediation), CM-8 (System Component Inventory)

**Tools:** Nessus/OpenVAS, Trivy, Nuclei, Wazuh SCA, EPSS scoring

**Scenarios:**
| Scenario | Focus | What It Tests |
|----------|-------|---------------|
| critical-cve-unpatched | RA-5, SI-2 | CVSS ≥9, internet-facing, no compensating control |
| exposed-management-ports | SC-7, CM-7 | SSH/RDP/WinRM open to 0.0.0.0/0 (ties to OSI-MODEL SC-7) |
| missing-mfa-enforcement | IA-2, AC-7 | Privileged accounts without MFA, detection + enforcement |

**Playbooks:**
- `01-scan-and-inventory.md` — run scans, build asset inventory
- `02-prioritize-findings.md` — CVSS + EPSS + context = actual priority
- `03-remediate.md` — patch, config fix, or document compensating control
- `04-verify-and-close.md` — rescan, confirm fix, close the finding

---

## EVIDENCE-INDEX.md

Single table at the root. Maps NIST control to where the evidence lives:

| NIST Control | Control Name | Scenario Path | Evidence Artifact |
|-------------|-------------|---------------|-------------------|
| SI-4 | System Monitoring | 01-SOC-TRIAGE/scenarios/T1566.001-phishing-email | governance.md, evidence-checklist.md |
| IR-4 | Incident Handling | 03-INCIDENT-RESPONSE/scenarios/ransomware-response | governance.md, evidence-checklist.md |
| RA-5 | Vulnerability Scanning | 04-VULN-MANAGEMENT/scenarios/critical-cve-unpatched | governance.md, evidence-checklist.md |
| ... | ... | ... | ... |

GRC analyst opens this file, finds the control, follows the path. That's it.

---

## What This Is Not

- Not a red team / offensive folder. No `break.sh`. That's a different hat.
- Not the GRC controls folder. `GRC-HAT` owns control implementation and compliance packaging.
- Not the DevSecOps folder. `DEVSECOPS-CKS-HAT` owns K8s, containers, CI/CD.

The overlap is real — an exposed management port is a finding in all three hats. Here it gets detected, investigated, remediated, and evidenced. The other hats handle prevention and compliance packaging.
