# Prioritize Findings

## Why CVSS Alone Is Wrong

CVSS measures severity in the abstract. Risk is contextual.

| Factor | Why It Matters |
|--------|---------------|
| Internet-facing? | Exploitable from anywhere vs. requires internal access |
| Active exploitation in wild? | EPSS score, CISA KEV status |
| Authentication required? | Pre-auth RCE >> post-auth RCE |
| Compensating control? | WAF, EDR, network segment may reduce exploitability |
| Data sensitivity of affected system? | PCI/HIPAA scope changes priority |
| Patch available? | No patch = compensating control only |

## Prioritization Framework

### Tier 1 — Fix This Week
- CVSS ≥ 9.0 AND internet-facing AND no compensating control
- Any CVE on the CISA Known Exploited Vulnerabilities (KEV) catalog
- Pre-authentication RCE or privilege escalation on a critical system
- Active exploitation observed in threat intel

### Tier 2 — Fix This Month
- CVSS ≥ 7.0 on internet-facing systems
- CVSS ≥ 9.0 on internal systems with no segmentation
- High EPSS score (>70%) regardless of CVSS
- Default credentials on any system

### Tier 3 — Fix This Quarter
- CVSS ≥ 4.0 on internal systems
- Configuration weaknesses (missing headers, deprecated TLS)
- Informational findings with attack chain potential

## EPSS Check

EPSS (Exploit Prediction Scoring System) scores the probability a CVE will be exploited in the next 30 days:
```bash
# Check EPSS score for a CVE
curl -s "https://api.first.org/data/v1/epss?cve=CVE-2021-44228" | python3 -m json.tool
```

## CISA KEV Check

CISA maintains a list of CVEs actively exploited in the wild:
```bash
curl -s https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json \
    | python3 -c "import json,sys; data=json.load(sys.stdin); [print(v['cveID'], v['vulnerabilityName']) for v in data['vulnerabilities']]" \
    | grep -i "CVE-YYYY-NNNNN"
```
