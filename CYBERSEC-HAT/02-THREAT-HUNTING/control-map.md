# Threat Hunting — Control Map

| NIST Control | Control Name | Tool | Enterprise Equivalent | What a Gap Looks Like |
|-------------|-------------|------|----------------------|----------------------|
| SI-4 | Information System Monitoring | Velociraptor, OSQuery, Zeek | CrowdStrike Falcon, Darktrace, Vectra | No proactive hunting program, detection only reactive, no telemetry beyond SIEM alerts |
| CA-7 | Continuous Monitoring | Elastic, Zeek, OSQuery | Splunk ES, Microsoft Sentinel | No scheduled hunts, no hypothesis documentation, no hunt tracking |
| RA-3 | Risk Assessment | MITRE ATT&CK Navigator | Recorded Future, Mandiant Threat Intel | No threat model for the environment, hunts not tied to relevant threat actors |
| IR-4 | Incident Handling | TheHive, Jira | ServiceNow, PagerDuty | Hunt findings not connected to IR pipeline, no process for positive-hunt escalation |
