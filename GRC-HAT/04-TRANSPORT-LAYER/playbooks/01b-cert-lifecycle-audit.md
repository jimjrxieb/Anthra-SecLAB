# 01b-cert-lifecycle-audit.md — Certificate Lifecycle Deep-Dive Audit

| Field | Value |
|---|---|
| **NIST Controls** | IA-5, SC-23 |
| **Tools** | cert-manager, OpenSSL, kubectl, crt.sh |
| **Enterprise Equiv** | Venafi TLS Protect ($200K+/yr), DigiCert CertCentral ($100K+/yr) |
| **Time** | 45 minutes |
| **Rank** | D (scripted, no decisions required) |

---

## Overview

This playbook produces a complete certificate inventory — every cert, its expiry, issuer, and renewal
status. The output answers: Are any certs expiring? Is auto-renewal working? Is the CA chain trusted?
Auditors ask for this inventory by name.

---

## 1. Certificate Inventory

### All certs accessible from Kubernetes

```bash
# cert-manager Certificate resources
kubectl get certificates --all-namespaces \
  -o custom-columns="NAMESPACE:.metadata.namespace,NAME:.metadata.name,READY:.status.conditions[0].status,EXPIRY:.status.notAfter,ISSUER:.spec.issuerRef.name"

# TLS secrets (certs that cert-manager wrote, or manually deployed)
kubectl get secrets --all-namespaces --field-selector type=kubernetes.io/tls \
  -o custom-columns="NAMESPACE:.metadata.namespace,NAME:.metadata.name,CREATED:.metadata.creationTimestamp"

# For each TLS secret, extract and check cert expiry
kubectl get secrets --all-namespaces --field-selector type=kubernetes.io/tls -o json | \
  python3 -c "
import json, sys, base64, subprocess
data = json.load(sys.stdin)
for secret in data['items']:
    ns = secret['metadata']['namespace']
    name = secret['metadata']['name']
    cert_b64 = secret['data'].get('tls.crt', '')
    if cert_b64:
        cert_pem = base64.b64decode(cert_b64)
        result = subprocess.run(
            ['openssl', 'x509', '-noout', '-enddate', '-subject'],
            input=cert_pem, capture_output=True, text=True
        )
        print(f'{ns}/{name}: {result.stdout.strip()}')
"
```

### Save full inventory as evidence

```bash
# Run the built-in cert lifecycle auditor
./01-auditors/audit-cert-lifecycle.sh

# Output includes: k8s-certificates.txt, clusterissuers.txt, cert-manager-pods.txt
```

---

## 2. Auto-Renewal Verification

### cert-manager renewal workflow

cert-manager renews certificates automatically at `renewBefore` before expiry. Verify it's working:

```bash
# Check cert-manager controller logs for renewal activity
kubectl logs -n cert-manager -l app=cert-manager --tail=50 | \
  grep -E "Renewing|Issuing|error|failed" | tail -20

# Check CertificateRequest resources (one created per issuance/renewal)
kubectl get certificaterequests --all-namespaces \
  -o custom-columns="NAMESPACE:.metadata.namespace,NAME:.metadata.name,APPROVED:.status.conditions[0].status,ISSUED:.status.conditions[1].status"

# Trigger a manual renewal to test (use staging issuer in production tests)
kubectl cert-manager renew <cert-name> -n <namespace>
# Then watch: kubectl get certificate <cert-name> -n <namespace> -w
```

### certbot renewal (if using Let's Encrypt directly)

```bash
# Check all managed certificates
certbot certificates

# Test renewal without making changes
certbot renew --dry-run

# Check cron/systemd for auto-renewal schedule
systemctl list-timers | grep certbot
cat /etc/cron.d/certbot 2>/dev/null || echo "No cron job found"
```

---

## 3. CA Chain Validation

### Verify complete chain

A broken chain (missing intermediate) causes browser errors even with a valid leaf cert.

```bash
# Full chain check
echo | openssl s_client -connect HOST:PORT -showcerts 2>/dev/null | \
  grep -E "subject=|issuer=|notAfter="

# Verify chain building
echo | openssl s_client -connect HOST:PORT 2>/dev/null | \
  openssl x509 -noout -text | grep -A5 "Authority Information Access"

# Check if chain is complete (should show Verify return code: 0 ok)
echo | openssl s_client -connect HOST:PORT -verify_return_error 2>&1 | \
  grep "Verify return code"
# Good: Verify return code: 0 (ok)
# Bad:  Verify return code: 20 (unable to get local issuer certificate)
```

### Extract all certs in chain

```bash
echo | openssl s_client -connect HOST:PORT -showcerts 2>/dev/null | \
  awk '/BEGIN CERTIFICATE/,/END CERTIFICATE/' | \
  csplit -z - '/BEGIN CERTIFICATE/' '{*}' 2>/dev/null

# Check each cert
for i in xx*; do
    echo "--- Cert: $i"
    openssl x509 -noout -subject -issuer -enddate -in "$i"
    echo ""
done
rm -f xx*
```

---

## 4. Certificate Transparency Log Check

Certificate Transparency (CT) logs record every publicly-issued certificate. Use this to:
- Find certificates issued for your domain that you didn't issue
- Detect unauthorized certificate issuance (SC-23: session authenticity)
- Verify your certificates were logged (required for CT compliance)

```bash
# Check crt.sh for all certs issued for your domain (last 90 days)
curl -s "https://crt.sh/?q=%.your-domain.com&output=json" | \
  python3 -c "
import json, sys
from datetime import datetime
certs = json.load(sys.stdin)
print(f'Total certs found: {len(certs)}')
print('')
print(f'{'Issued':12} {'Expires':12} {'CommonName':40} {'Issuer'}')
print('-' * 100)
for c in sorted(certs, key=lambda x: x.get('not_after',''), reverse=True)[:20]:
    issued = c.get('not_before','')[:10]
    expires = c.get('not_after','')[:10]
    cn = c.get('common_name','')[:40]
    issuer = c.get('issuer_name','')[:40]
    print(f'{issued:12} {expires:12} {cn:40} {issuer}')
"

# Alert on unexpected issuers
# Expected issuers: Let's Encrypt, your internal CA
# Unexpected: any CA you don't recognize
```

---

## 5. Expiry Alert Validation

Verify your monitoring will catch expiring certs BEFORE they expire.

```bash
# Simulate: what would expire in 30 days?
kubectl get certificates --all-namespaces -o json | \
  python3 -c "
import json, sys
from datetime import datetime, timezone, timedelta
data = json.load(sys.stdin)
now = datetime.now(timezone.utc)
warning_threshold = now + timedelta(days=30)

for cert in data['items']:
    ns = cert['metadata']['namespace']
    name = cert['metadata']['name']
    not_after = cert.get('status', {}).get('notAfter', '')
    if not_after:
        expiry = datetime.fromisoformat(not_after.replace('Z', '+00:00'))
        days = (expiry - now).days
        if days < 0:
            print(f'EXPIRED: {ns}/{name} (expired {-days} days ago)')
        elif days < 30:
            print(f'WARNING: {ns}/{name} expires in {days} days')
        else:
            print(f'OK:      {ns}/{name} expires in {days} days')
"
```

---

## 6. Evidence Archive

```bash
# Save all evidence together
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
EVIDENCE_DIR="/tmp/jsa-evidence/cert-lifecycle-full-${TIMESTAMP}"
mkdir -p "$EVIDENCE_DIR"

# Kubernetes cert inventory
kubectl get certificates --all-namespaces -o yaml > "${EVIDENCE_DIR}/all-certificates.yaml" 2>/dev/null || true
kubectl get secrets --all-namespaces --field-selector type=kubernetes.io/tls > "${EVIDENCE_DIR}/tls-secrets.txt" 2>/dev/null || true
kubectl get clusterissuers -o yaml > "${EVIDENCE_DIR}/clusterissuers.yaml" 2>/dev/null || true

echo "Evidence saved to: ${EVIDENCE_DIR}"
```

---

## Next Steps

- Expired or expiring certs: `02a-fix-IA5-certs.md`
- cert-manager not deployed: `00-install-validate.md` then deploy `03-templates/cert-manager/clusterissuer.yaml`
- Unauthorized CT log entries: escalate — potential SC-23 incident (unauthorized cert issuance)
- Clean: proceed to `02-fix-SC8-tls.md` if cipher findings remain
