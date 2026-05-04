# 01a-tls-audit.md — Deep-Dive TLS Audit

| Field | Value |
|---|---|
| **NIST Controls** | SC-8, SC-13 |
| **Tools** | testssl.sh, OpenSSL, nmap, curl |
| **Enterprise Equiv** | Qualys SSL Labs Enterprise ($50K+/yr) |
| **Time** | 45 minutes per environment |
| **Rank** | D (scripted, no decisions required) |

---

## Overview

This playbook runs a thorough TLS cipher and protocol analysis using testssl.sh. It goes beyond the
baseline audit in `01-assess.md` to give you a full cipher grade, vulnerability checks, and HSTS
preload eligibility analysis.

---

## 1. Run testssl.sh Against All Endpoints

### Identify all TLS endpoints first

```bash
# Kubernetes ingress endpoints
kubectl get ingress --all-namespaces \
  -o jsonpath='{range .items[*]}{.spec.rules[*].host}{"\n"}{end}' | sort -u

# Services with NodePort/LoadBalancer
kubectl get svc --all-namespaces \
  -o jsonpath='{range .items[?(@.spec.type=="LoadBalancer")]}{.status.loadBalancer.ingress[*].hostname}{"\n"}{end}'

# Azure App Services
az webapp list --query "[].defaultHostName" -o tsv
```

### Run testssl.sh — comprehensive scan

```bash
# Full scan with HIGH+ severity filter
/opt/testssl/testssl.sh --severity HIGH your.domain.com:443

# Save JSON for parsing
/opt/testssl/testssl.sh \
  --severity HIGH \
  --jsonfile /tmp/jsa-evidence/testssl-$(date +%Y%m%d).json \
  your.domain.com:443

# Cipher per protocol — shows exactly which ciphers each protocol uses
/opt/testssl/testssl.sh --cipher-per-proto your.domain.com:443

# Vulnerability checks only (HEARTBLEED, POODLE, FREAK, LOGJAM, ROBOT, etc.)
/opt/testssl/testssl.sh --vulnerable your.domain.com:443
```

### Batch scan multiple endpoints

```bash
# Create endpoint list
cat > /tmp/endpoints.txt << 'EOF'
your-app.com:443
api.your-app.com:443
admin.your-app.com:443
EOF

# Scan all
while read -r endpoint; do
    echo "=== Scanning: $endpoint ==="
    /opt/testssl/testssl.sh --severity MEDIUM \
        --jsonfile "/tmp/jsa-evidence/testssl-${endpoint//:/-}.json" \
        "$endpoint"
done < /tmp/endpoints.txt
```

---

## 2. Grade Interpretation

testssl.sh uses letter grades for cipher suites:

| Grade | Meaning | Action |
|---|---|---|
| A | Strong ECDHE + AEAD (AESGCM/CHACHA20) | Keep |
| B | Acceptable — forward secrecy but CBC mode | Monitor — plan to remove |
| C | No forward secrecy (RSA key exchange) | Remediate — SC-13 gap |
| D | Weak MAC or algorithm | Remediate immediately |
| F | Known broken (RC4, DES, EXPORT, NULL) | Critical — disable now |

**Target state:** All cipher suites grade A. No B or below.

### Example testssl.sh output to look for

```
 Cipher order
  TLSv1.2   ECDHE-RSA-AES256-GCM-SHA384 ECDHE-RSA-AES128-GCM-SHA256           A
             ECDHE-RSA-AES256-SHA384                                            B  ← CBC
             AES256-SHA                                                         C  ← no PFS
  TLSv1.1   TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA                                B
  TLSv1.0   DES-CBC3-SHA                                                       D  ← SWEET32
```

---

## 3. Compare Against Template Cipher List

The approved cipher list (from `03-templates/tls/nginx-tls.conf`):

```
ECDHE-ECDSA-AES128-GCM-SHA256
ECDHE-RSA-AES128-GCM-SHA256
ECDHE-ECDSA-AES256-GCM-SHA384
ECDHE-RSA-AES256-GCM-SHA384
ECDHE-ECDSA-CHACHA20-POLY1305
ECDHE-RSA-CHACHA20-POLY1305
```

Parse testssl.sh JSON to find ciphers not on the approved list:

```bash
python3 << 'EOF'
import json

APPROVED = {
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-CHACHA20-POLY1305",
    "ECDHE-RSA-CHACHA20-POLY1305",
    # TLS 1.3 built-ins (auto-negotiated, not configurable)
    "TLS_AES_256_GCM_SHA384",
    "TLS_AES_128_GCM_SHA256",
    "TLS_CHACHA20_POLY1305_SHA256",
}

with open("/tmp/jsa-evidence/testssl-your.domain.com-443.json") as f:
    data = json.load(f)

for finding in data.get("findings", []):
    if finding.get("id", "").startswith("cipher_"):
        cipher = finding.get("finding", "")
        if cipher and not any(a in cipher for a in APPROVED):
            print(f"UNAPPROVED: {finding['id']} — {cipher}")
EOF
```

---

## 4. Mixed Content Check

Mixed content (HTTPS page loading HTTP resources) breaks SC-8 for those resources.

```bash
# Check for HTTP references in page source
curl -sk https://your.domain.com | grep -oE 'src="http://[^"]+"|href="http://[^"]+"' | head -20

# Check Content-Security-Policy for upgrade-insecure-requests
curl -sI https://your.domain.com | grep -i "content-security-policy"
# Look for: upgrade-insecure-requests directive
```

---

## 5. HSTS Preload Eligibility

HSTS preload hardcodes your domain into Chrome/Firefox — no first-visit HTTP risk.

```bash
# Check current HSTS configuration
curl -sI https://your.domain.com | grep -i "strict-transport"

# Requirements for preload:
# 1. HTTPS works with valid cert
# 2. Redirect all HTTP to HTTPS
# 3. Serve HSTS on base domain with:
#    - max-age >= 31536000 (1 year)
#    - includeSubDomains
#    - preload directive
# 4. All subdomains are also HTTPS-only

# Check if domain qualifies
curl -s "https://hstspreload.org/api/v2/status?domain=your.domain.com"
```

---

## 6. Evidence Archive

After completing the audit:

```bash
# Run built-in auditor (saves evidence automatically)
./01-auditors/audit-tls-config.sh your.domain.com:443

# Archive testssl.sh results
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
mkdir -p /tmp/jsa-evidence/l4-tls-audit-${TIMESTAMP}
cp /tmp/jsa-evidence/testssl-*.json /tmp/jsa-evidence/l4-tls-audit-${TIMESTAMP}/ 2>/dev/null || true

echo "Evidence archived. Proceed to 02-fix-SC8-tls.md for remediation."
```

---

## Next Steps

- Findings with grade F or D: go directly to `02-fix-SC8-tls.md`
- Findings with grade B or C: document in triage, remediate within 30 days
- Clean report (all A): proceed to `01b-cert-lifecycle-audit.md`
