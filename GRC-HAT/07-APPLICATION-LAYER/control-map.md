# Layer 7 Application — Control Map

| NIST Control | Control Name | Tool | Enterprise Equivalent | What Misconfiguration Looks Like |
|-------------|-------------|------|----------------------|--------------------------------|
| SA-11 | Developer Testing | Semgrep, ZAP | Checkmarx, Veracode, Fortify | No SAST in CI, no DAST against staging, no security unit tests |
| RA-5 | Vulnerability Scanning | ZAP, Nikto, Nmap | Qualys, Tenable, Rapid7 | No regular scans, scan results not reviewed, no remediation SLA |
| AC-6 | Least Privilege (App) | Manual review, Sentinel | CyberArk, BeyondTrust | Admin endpoints accessible to regular users, no RBAC in app |
| SI-10 | Input Validation | SQLMap, Semgrep, ZAP | Imperva, Checkmarx | SQL injection, XSS, command injection via unsanitized input |
| AU-2 | Event Logging | Sentinel + KQL, Splunk | Splunk ES, Sentinel, Datadog | No auth logging, no failed login alerts, no data access audit trail |
| AU-6 | Audit Record Review | Sentinel + KQL, Splunk | Splunk ES, LogRhythm | Logs collected but never reviewed, no KQL detection rules, no dashboards |
