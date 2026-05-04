# 04 — Vulnerability Management

## What This Function Covers

The scan → prioritize → remediate → verify cycle. A 3-5 year analyst runs vulnerability scans, interprets results, prioritizes by actual risk (not just CVSS score), tracks remediation through completion, and re-scans to verify closure.

Vulnerability management is not scan-and-dump. CVSS 9.8 on an internal dev box with no internet access is not your top priority. CVSS 7.2 on a public-facing server with active exploitation in the wild is. Context is everything.

## Why It Matters

Unpatched vulnerabilities are the #1 initial access vector after phishing. 60% of breaches involve a known vulnerability that had a patch available (Verizon DBIR 2024). The organizations that get breached are not the ones that don't have a scanner — they're the ones that scan but don't remediate.

## NIST 800-53 Controls

| Control ID | Control Name | What It Requires |
|-----------|-------------|-----------------|
| RA-5 | Vulnerability Monitoring and Scanning | Scan for vulnerabilities, analyze results, remediate findings |
| SI-2 | Flaw Remediation | Identify, report, and correct flaws; test effectiveness of corrections |
| CM-8 | System Component Inventory | Maintain inventory of system components as basis for scanning |
| CM-6 | Configuration Settings | Establish and document configuration settings |

## Tools

| Tool | Type | Cost | Purpose |
|------|------|------|---------|
| OpenVAS / Greenbone | Open source | Free | Network vulnerability scanner |
| Trivy | Open source | Free | Container and filesystem scanning |
| Nuclei | Open source | Free | Template-based vulnerability scanner |
| Lynis | Open source | Free | Linux host security auditing |
| Nmap | Open source | Free | Port scanning, service discovery |
| EPSS (FIRST.org) | Free API | Free | Exploit probability scoring for prioritization |

## Scenarios

| Scenario | Controls | What It Tests |
|----------|----------|---------------|
| [Critical CVE Unpatched](scenarios/critical-cve-unpatched/) | RA-5, SI-2 | CVSS ≥9, internet-facing, no compensating control |
| [Exposed Management Ports](scenarios/exposed-management-ports/) | SC-7, CM-7 | SSH/RDP/WinRM open to 0.0.0.0/0 |
| [Missing MFA Enforcement](scenarios/missing-mfa-enforcement/) | IA-2, AC-7 | Privileged accounts without MFA |
