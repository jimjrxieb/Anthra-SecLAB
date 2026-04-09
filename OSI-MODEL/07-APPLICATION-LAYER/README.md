# Layer 7 — Application

## What This Layer Covers

Application security, authentication, authorization, API security, input validation, logging and monitoring. This is the layer users interact with directly — and the layer attackers target most.

## Why It Matters

SQL injection is still in the OWASP Top 10 after 20 years because developers still concatenate strings into queries. Missing audit logging means you cannot detect a breach, cannot investigate it, and cannot prove to an auditor what happened. Application-layer controls are where the rubber meets the road — every other layer protects the infrastructure, this layer protects the business logic.

## NIST 800-53 Controls

| Control ID | Control Name | What It Requires |
|-----------|-------------|-----------------|
| SA-11 | Developer Testing and Evaluation | Security testing in development |
| RA-5 | Vulnerability Scanning | Regular vulnerability assessment |
| AC-6 | Least Privilege | Minimum necessary access at app level |
| SI-10 | Information Input Validation | Validate all application input |
| AU-2 | Event Logging | Log security-relevant events |
| AU-6 | Audit Record Review | Review and analyze audit logs |

## Tools

| Tool | Type | Cost | Purpose |
|------|------|------|---------|
| Microsoft Sentinel + KQL | Microsoft | Free tier (10 GB/day) | SIEM, log analysis, detection rules |
| Microsoft Defender for Cloud Apps | Microsoft | Free trial | Cloud app security |
| Splunk | Existing | Existing setup | SIEM, log aggregation |
| OWASP ZAP | Open source | Free | DAST, web app scanning |
| Semgrep | Open source | Free | SAST, code pattern analysis |
| Nikto | Open source | Free | Web server scanning |
| SQLMap | Open source | Free | SQL injection testing |

## Scenarios

| Scenario | Control | Format |
|----------|---------|--------|
| [SI-10 SQL Injection](scenarios/SI-10-sql-injection/) | SI-10 | Scripts (.sh) |
| [AU-2 Missing Logging](scenarios/AU-2-missing-logging/) | AU-2 | Scripts (.sh) |
