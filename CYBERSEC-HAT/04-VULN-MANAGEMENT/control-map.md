# Vulnerability Management — Control Map

| NIST Control | Control Name | Tool | Enterprise Equivalent | What a Gap Looks Like |
|-------------|-------------|------|----------------------|----------------------|
| RA-5 | Vulnerability Monitoring and Scanning | OpenVAS, Trivy, Lynis, Nuclei | Tenable Nessus, Qualys, Rapid7 InsightVM | No regular scanning schedule, scan results not reviewed, no remediation tracking |
| SI-2 | Flaw Remediation | apt/yum patching, OS hardening | Tanium Patch, Ivanti, WSUS | Patches available but not applied, no SLA for critical patch deployment, no re-scan to verify |
| CM-8 | System Component Inventory | Nmap, asset management | ServiceNow CMDB, Tenable.io | No asset inventory, scanning coverage unknown, shadow IT unaccounted for |
| CM-6 | Configuration Settings | Lynis, CIS benchmarks, OpenSCAP | CIS-CAT Pro, Tenable SC | No hardening baseline, default configurations in production, no configuration drift detection |
