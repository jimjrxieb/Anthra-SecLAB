# 04-triage-alerts.md — L4 Transport Layer: Daily Triage and Alert Response

| Field | Value |
|---|---|
| **NIST Controls** | SC-8, SC-13, SC-23, IA-5 |
| **Tools** | cert-manager events, Defender for Cloud, Certificate Transparency |
| **Time** | 15 minutes daily |
| **Rank** | D (monitoring and triage; escalate B/S rank findings) |

---

## Daily Triage Workflow

This is the daily L4 operator checklist. Run it every morning before stand-up.

---

## 1. Certificate Expiry Monitoring

### cert-manager events (fastest check)

```bash
# Check cert-manager events for failures or warnings
kubectl get events -n cert-manager --sort-by='.lastTimestamp' | \
  grep -i -E "failed|error|warning|expir" | tail -20

# Check all namespaces for cert events
kubectl get events --all-namespaces --sort-by='.lastTimestamp' | \
  grep -i "cert-manager\|certificate\|issuer" | tail -30

# Quick expiry dashboard — certs expiring within 30 days
kubectl get certificates --all-namespaces -o json | python3 -c "
import json, sys
from datetime import datetime, timezone, timedelta
data = json.load(sys.stdin)
now = datetime.now(timezone.utc)
threshold = now + timedelta(days=30)
found = False
for cert in data['items']:
    ns = cert['metadata']['namespace']
    name = cert['metadata']['name']
    not_after = cert.get('status', {}).get('notAfter', '')
    if not_after:
        expiry = datetime.fromisoformat(not_after.replace('Z', '+00:00'))
        days = (expiry - now).days
        if days < 0:
            print(f'EXPIRED  [{ns}/{name}] — {-days} days overdue')
            found = True
        elif days < 30:
            print(f'EXPIRING [{ns}/{name}] — {days} days remaining')
            found = True
if not found:
    print('OK — no certs expiring within 30 days')
"
```

### If any certs are EXPIRED or expiring < 7 days

Immediate action — do not wait for daily triage window:

```bash
./02-fixers/fix-expired-cert.sh --method certmanager --cert-name <name> --namespace <ns>
```

---

## 2. Defender for Cloud Recommendations

```bash
# Check for new TLS findings in Defender for Cloud
az security assessment list \
  --query "[?contains(displayName,'TLS') || contains(displayName,'SSL') || contains(displayName,'secure transfer')].{recommendation:displayName, severity:metadata.severity, status:status.code, resource:resourceDetails.id}" \
  -o table 2>/dev/null || echo "az CLI not configured — check Defender portal manually"

# Filter to only unhealthy
az security assessment list \
  --query "[?(contains(displayName,'TLS') || contains(displayName,'SSL')) && status.code!='Healthy'].{recommendation:displayName, severity:metadata.severity}" \
  -o table 2>/dev/null
```

---

## 3. TLS Error Log Review

### nginx TLS errors

```bash
# Last 100 SSL errors
grep -i "ssl_\|handshake\|protocol\|cipher" /var/log/nginx/error.log 2>/dev/null | tail -20

# Counts by error type
grep -i "ssl_\|handshake" /var/log/nginx/error.log 2>/dev/null | \
  grep -oP "(SSL_\w+|handshake\s\w+)" | sort | uniq -c | sort -rn | head -10
```

### Kubernetes ingress TLS errors

```bash
# nginx ingress controller logs
kubectl logs -n ingress-nginx -l app.kubernetes.io/name=ingress-nginx --tail=100 2>/dev/null | \
  grep -i -E "ssl|tls|handshake|cert" | tail -20
```

### Istio proxy TLS errors

```bash
# Check Envoy proxy logs for TLS failures
kubectl logs -n production <pod-name> -c istio-proxy 2>/dev/null | \
  grep -i "tls_error\|HANDSHAKE\|certificate" | tail -20

# Or across all pods in namespace
kubectl get pods -n production -o name 2>/dev/null | while read pod; do
    kubectl logs "$pod" -c istio-proxy -n production --tail=10 2>/dev/null | \
        grep -i "tls_error\|certificate_error" | xargs -I{} echo "$pod: {}" 2>/dev/null
done
```

---

## 4. Certificate Transparency Alerts

Check for unexpected certificate issuance (potential domain takeover or misissue):

```bash
# Check crt.sh for new certs issued in the last 24 hours
DOMAIN="your-domain.com"
curl -s "https://crt.sh/?q=%.${DOMAIN}&output=json" 2>/dev/null | \
  python3 -c "
import json, sys
from datetime import datetime, timezone, timedelta
certs = json.load(sys.stdin)
now = datetime.now(timezone.utc)
yesterday = now - timedelta(hours=24)
print('Certificates issued in last 24 hours:')
new_certs = [c for c in certs if c.get('not_before','') > yesterday.strftime('%Y-%m-%d')]
if not new_certs:
    print('  None')
else:
    for c in new_certs:
        print(f\"  {c.get('not_before','')[:10]} | {c.get('common_name',''):40} | {c.get('issuer_name','')[:50]}\")
" 2>/dev/null || echo "crt.sh check failed — check manually at https://crt.sh/?q=%.${DOMAIN}"
```

### Unexpected issuers to flag

If you see a cert for your domain from an issuer you don't recognize, this is a potential incident:

```
Known issuers:    Let's Encrypt Authority X3, Let's Encrypt R3, your-internal-CA
Unknown issuers:  Anything else — investigate immediately
```

---

## 5. Investigation Workflow for Unexpected Cert Changes

When you find a cert that wasn't expected:

### Step 1: Identify the cert

```bash
# Get full cert details from crt.sh
CERT_ID="<id from crt.sh>"
curl -s "https://crt.sh/?id=${CERT_ID}"

# Or from Kubernetes
kubectl get certificate <name> -n <namespace> -o yaml
kubectl describe certificate <name> -n <namespace>
```

### Step 2: Check when and how it was issued

```bash
# cert-manager audit trail
kubectl get certificaterequests --all-namespaces | grep <cert-name>
kubectl describe certificaterequest <name> -n <namespace>

# Check Kubernetes audit logs if available
# (requires audit logging configured on API server)
```

### Step 3: Verify the cert in use matches what was issued

```bash
# Compare fingerprint of running cert vs expected
echo | openssl s_client -connect HOST:PORT 2>/dev/null | \
  openssl x509 -noout -fingerprint -sha256

# Compare with what's in the Kubernetes secret
kubectl get secret <tls-secret> -n <ns> -o jsonpath='{.data.tls\.crt}' | \
  base64 -d | openssl x509 -noout -fingerprint -sha256
```

### Step 4: Escalation decision

| Finding | Rank | Action |
|---|---|---|
| cert-manager renewed cert on schedule | D | Log, no action |
| Cert renewed ahead of schedule (manual trigger) | D | Confirm who ran it, log |
| Cert from unknown issuer on your domain | B | Investigate source — potential misissue |
| Cert from unknown issuer on your domain AND active in production | S | Incident — revoke, rotate, investigate |

---

## Daily Triage Sign-Off

Paste this in your daily notes:

```
L4 Transport Triage — DATE
- Certs expiring: [none | list]
- cert-manager events: [clean | issues]
- Defender recommendations: [clean | count]
- TLS error spike: [no | yes - description]
- CT log new certs: [none unexpected | list]
- Actions taken: [none | description]
- Escalations: [none | description]
```
