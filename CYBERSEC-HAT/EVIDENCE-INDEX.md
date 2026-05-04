# Evidence Index — CYBERSEC-HAT

GRC crosswalk: NIST control → scenario → artifact. Navigate here when you need to answer "where's the evidence for control X?"

| NIST Control | Control Name | Section | Scenario Path | Artifacts |
|-------------|-------------|---------|---------------|-----------|
| AU-6 | Audit Review, Analysis, Reporting | 01-SOC-TRIAGE | scenarios/T1566.001-phishing-email | governance.md, evidence-checklist.md |
| AU-6 | Audit Review, Analysis, Reporting | 01-SOC-TRIAGE | scenarios/T1078-valid-account-abuse | governance.md, evidence-checklist.md |
| AU-6 | Audit Review, Analysis, Reporting | 01-SOC-TRIAGE | scenarios/T1110-brute-force-lockout | governance.md, evidence-checklist.md |
| SI-4 | Information System Monitoring | 01-SOC-TRIAGE | scenarios/T1059.001-malicious-powershell | governance.md, evidence-checklist.md |
| SI-4 | Information System Monitoring | 02-THREAT-HUNTING | scenarios/T1003-credential-dumping | governance.md, evidence-checklist.md |
| CA-7 | Continuous Monitoring | 02-THREAT-HUNTING | scenarios/T1055-process-injection | governance.md, evidence-checklist.md |
| CA-7 | Continuous Monitoring | 02-THREAT-HUNTING | scenarios/T1021.001-rdp-lateral-movement | governance.md, evidence-checklist.md |
| CM-3 | Configuration Change Control | 02-THREAT-HUNTING | scenarios/T1053-persistence-scheduled-task | governance.md, evidence-checklist.md |
| IR-4 | Incident Handling | 03-INCIDENT-RESPONSE | scenarios/ransomware-response | governance.md, evidence-checklist.md |
| IR-4 | Incident Handling | 03-INCIDENT-RESPONSE | scenarios/phishing-compromise | governance.md, evidence-checklist.md |
| IR-5 | Incident Monitoring | 03-INCIDENT-RESPONSE | scenarios/credential-theft-response | governance.md, evidence-checklist.md |
| RA-5 | Vulnerability Monitoring and Scanning | 04-VULN-MANAGEMENT | scenarios/critical-cve-unpatched | governance.md, evidence-checklist.md |
| SC-7 | Boundary Protection | 04-VULN-MANAGEMENT | scenarios/exposed-management-ports | governance.md, evidence-checklist.md |
| IA-2 | Identification and Authentication | 04-VULN-MANAGEMENT | scenarios/missing-mfa-enforcement | governance.md, evidence-checklist.md |

## How to Use This Index

1. Find the NIST control your auditor is asking about
2. Follow the scenario path (relative to the section folder)
3. Open `governance.md` — control mapping and audit narrative
4. Open `evidence-checklist.md` — artifacts that prove compliance
