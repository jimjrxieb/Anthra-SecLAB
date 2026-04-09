# OSI-MODEL Security Lab

A 7-layer security lab mapped to the OSI model. Each layer maps NIST 800-53 controls to tools, breaks configurations to demonstrate cost of failure, fixes them, validates the fix, and communicates governance value to CISO leadership.

This is not a tool demo. The tool is secondary to the control and the governance communication.

## Certification Alignment

| Cert | How This Lab Maps |
|------|-------------------|
| CompTIA CySA+ | Threat detection, vulnerability management, incident response across all layers |
| CompTIA Cloud+ | Cloud security controls (Azure NSGs, Defender for Cloud, identity) |
| CISSP | Risk management frameworks, governance, security architecture, all 8 domains |

## Layer Index

| # | Layer | NIST Families | Primary Tools |
|---|-------|--------------|---------------|
| 01 | [Physical](01-PHYSICAL-LAYER/) | PE (Physical & Environmental) | Badge systems, CCTV, environmental monitoring |
| 02 | [Data Link](02-DATA-LINK-LAYER/) | SC, AC, SI | Wireshark, Defender for IoT, arpwatch |
| 03 | [Network](03-NETWORK-LAYER/) | SC, AC, SI | Azure NSGs, Windows Firewall, Suricata, Nmap |
| 04 | [Transport](04-TRANSPORT-LAYER/) | SC, IA | Defender for Cloud, testssl.sh, OpenSSL, Nmap |
| 05 | [Session](05-SESSION-LAYER/) | AC, SC, IA | Entra ID, Burp Suite CE, ZAP |
| 06 | [Presentation](06-PRESENTATION-LAYER/) | SC, SI | BitLocker, Azure Key Vault, OpenSSL, hashcat |
| 07 | [Application](07-APPLICATION-LAYER/) | SA, RA, AC, SI, AU | Sentinel + KQL, Splunk, ZAP, Semgrep, SQLMap |

## Methodology

Every scenario follows the same cycle:

1. **Control** — what NIST 800-53 says and WHY it exists (the business risk)
2. **Break** — misconfigure or remove the control to expose the vulnerability
3. **Detect** — use tooling to identify the misconfiguration or exploit
4. **Fix** — implement the control correctly
5. **Validate** — confirm the fix holds under re-test
6. **Govern** — translate the finding into CISO language (risk, cost, ROI)

## Governance Framework

Every scenario produces a CISO governance brief using:
- **5x5 Risk Matrix** — likelihood x impact scoring
- **IBM Cost of a Data Breach** — real dollar figures per record ($164 avg, $264 US)
- **Gordon-Loeb Model** — never spend more than 37% of expected loss on a control
- **ROSI** — Return on Security Investment = (risk_reduction - cost) / cost
- **FAIR** — Factor Analysis of Information Risk for quantitative scenarios

## Key Terminology

| Term | Definition |
|------|-----------|
| ALE | Annualized Loss Expectancy — expected loss per year |
| FAIR | Factor Analysis of Information Risk — quantitative risk model |
| ROSI | Return on Security Investment |
| Gordon-Loeb | Max security spend = 37% of expected annual loss |
| POA&M | Plan of Action and Milestones — remediation tracking |
| SAR | Security Assessment Report |
| SSP | System Security Plan |
| MTTD | Mean Time to Detect |
| MTTR | Mean Time to Respond |
| Inherent Risk | Risk before controls |
| Residual Risk | Risk after controls applied |
| Risk Appetite | How much risk leadership formally accepts |
