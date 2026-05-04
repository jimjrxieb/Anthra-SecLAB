# SOC Triage — Control Map

| NIST Control | Control Name | Tool | Enterprise Equivalent | What a Gap Looks Like |
|-------------|-------------|------|----------------------|----------------------|
| SI-4 | Information System Monitoring | Wazuh, Elastic, Splunk | Splunk Enterprise Security, Microsoft Sentinel | No SIEM deployed, alerts not reviewed, no baseline for normal behavior |
| AU-6 | Audit Review, Analysis, Reporting | Splunk, ELK, Wazuh | Splunk ES, IBM QRadar | Logs collected but never reviewed, no alert rules, no analyst assigned |
| IR-6 | Incident Reporting | TheHive, Jira, ticketing | ServiceNow, PagerDuty | No ticketing system, incidents go undocumented, no escalation path defined |
| AU-12 | Audit Record Generation | rsyslog, auditd, Windows Event Log | Splunk UF, CrowdStrike Falcon | Log sources not feeding SIEM, gaps in coverage, no authentication logging |
