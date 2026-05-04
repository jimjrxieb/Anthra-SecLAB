# T1566.001 Phishing Email — Governance

## NIST 800-53 Control Mapping

| Control | Name | How This Scenario Demonstrates Compliance |
|---------|------|------------------------------------------|
| SI-4 | Information System Monitoring | Detection script surfaces phishing indicators from system logs and network telemetry |
| AU-6 | Audit Review, Analysis, Reporting | Investigation checklist follows formal log review and analysis procedure |
| IR-2 | Incident Response Training | This scenario is training material for analyst recognition and response |
| AT-2 | Awareness and Training | User-facing remediation step includes phishing awareness |

## CIS Controls Mapping

| CIS Control | Description | Evidence |
|-------------|-------------|---------|
| CIS 9 | Email and Web Browser Protections | SPF/DKIM/DMARC check, mail gateway blocking |
| CIS 13 | Network Monitoring and Defense | Outbound connection analysis, C2 detection |

## MITRE ATT&CK

- **Tactic:** Initial Access
- **Technique:** T1566.001 — Spearphishing Attachment
- **Detection coverage:** Email header analysis, process tree analysis, network connection review

## Audit Narrative

*For SSP Appendix A or audit response:*

"The organization monitors for phishing-based initial access attempts through SIEM-based detection rules aligned to ATT&CK T1566.001. Upon alert, analysts follow a documented triage procedure that includes email header analysis, SPF/DKIM/DMARC verification, IOC enrichment, and host-based process tree review. Confirmed incidents trigger the documented email incident response procedure, including isolation, credential reset, session revocation, and IOC blocking. Evidence artifacts collected per the evidence checklist support audit trail requirements under AU-6 and IR-6."

## Evidence Artifacts for Auditor

1. `evidence-checklist.md` — list of required artifacts
2. `detect.sh` output — demonstrates automated detection capability
3. `investigate.md` — documents the analyst investigation procedure
4. `remediate.md` — documents the remediation procedure
