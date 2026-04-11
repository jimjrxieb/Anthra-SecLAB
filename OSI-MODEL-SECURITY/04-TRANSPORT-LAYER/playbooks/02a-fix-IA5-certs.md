# 02a-fix-IA5-certs.md — Certificate Lifecycle Remediation: IA-5

| Field | Value |
|---|---|
| **NIST Controls** | IA-5, SC-23 |
| **Tools** | cert-manager, certbot, OpenSSL |
| **Fixer Script** | `02-fixers/fix-expired-cert.sh` |
| **Time** | 15–30 minutes |
| **Rank** | D (scripted; cert-manager makes renewal zero-touch) |

---

## When to Use This

Run this playbook when `01b-cert-lifecycle-audit.md` finds:
- Expired certificates in Kubernetes or on disk
- Certificates expiring within 30 days without auto-renewal configured
- cert-manager not deployed (manual renewal in place)
- ClusterIssuer in NOT READY state
- certbot renewal failing

---

## Automated Fix

```bash
# cert-manager: renew all not-ready certs automatically
./02-fixers/fix-expired-cert.sh --method certmanager

# cert-manager: renew a specific cert
./02-fixers/fix-expired-cert.sh --method certmanager --cert-name my-tls-cert --namespace production

# Let's Encrypt (certbot): force renew all
./02-fixers/fix-expired-cert.sh --method letsencrypt

# Manual (openssl): generate new self-signed for lab use
./02-fixers/fix-expired-cert.sh --method manual --domain lab.local
```

---

## cert-manager: Renew Specific Certificate

```bash
# Check current state
kubectl get certificate my-tls-cert -n production

# Method 1: kubectl cert-manager plugin (cleanest)
kubectl cert-manager renew my-tls-cert -n production

# Method 2: Delete the TLS secret — cert-manager recreates it
SECRET=$(kubectl get certificate my-tls-cert -n production -o jsonpath='{.spec.secretName}')
echo "Secret to delete: $SECRET"
# Backup first
kubectl get secret "$SECRET" -n production -o yaml > /tmp/backup-${SECRET}.yaml
# Delete (cert-manager will recreate within ~60 seconds)
kubectl delete secret "$SECRET" -n production

# Watch renewal progress
kubectl get certificate my-tls-cert -n production -w
# Wait for READY=True
```

---

## cert-manager: Fix NOT READY ClusterIssuer

### Check why it's not ready

```bash
kubectl describe clusterissuer letsencrypt-prod | grep -A10 "Conditions"
```

Common issues:

**ACME account not registered:**
```bash
# Check the account key secret
kubectl get secret letsencrypt-prod-account-key -n cert-manager
# If missing: delete and recreate the ClusterIssuer — cert-manager will re-register
kubectl delete clusterissuer letsencrypt-prod
kubectl apply -f 03-templates/cert-manager/clusterissuer.yaml
```

**HTTP-01 challenge failing (port 80 not accessible):**
```bash
# Check challenge status
kubectl get challenges --all-namespaces
kubectl describe challenge <challenge-name> -n <namespace>

# Verify port 80 is accessible from internet
curl -s http://your.domain.com/.well-known/acme-challenge/test
# Should return 404 (not connection refused)

# Switch to DNS-01 if port 80 is blocked
# Update ClusterIssuer to use dns01 solver — see 03-templates/cert-manager/clusterissuer.yaml
```

**Rate limited by Let's Encrypt:**
```bash
# Use staging issuer while debugging
kubectl patch certificate my-tls-cert -n production \
  --type merge -p '{"spec":{"issuerRef":{"name":"letsencrypt-staging"}}}'

# After testing with staging, switch back to prod
kubectl patch certificate my-tls-cert -n production \
  --type merge -p '{"spec":{"issuerRef":{"name":"letsencrypt-prod"}}}'
```

---

## Set Up Auto-Renewal (cert-manager not yet deployed)

Deploy cert-manager and configure a ClusterIssuer:

```bash
# 1. Install cert-manager
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/latest/download/cert-manager.yaml
kubectl wait --for=condition=Available deployment/cert-manager -n cert-manager --timeout=120s

# 2. Deploy ClusterIssuer
# Edit 03-templates/cert-manager/clusterissuer.yaml — update email and ingress class
kubectl apply -f 03-templates/cert-manager/clusterissuer.yaml

# 3. Deploy Certificate resource for existing services
# Edit 03-templates/cert-manager/certificate.yaml — update secretName and dnsNames
kubectl apply -f 03-templates/cert-manager/certificate.yaml

# 4. Verify
kubectl get clusterissuer              # READY=True
kubectl get certificates --all-namespaces  # READY=True
```

---

## CA Rotation Procedure

When the internal CA cert is expiring (10-year lifecycle):

```bash
# 1. Generate new CA cert
openssl ecparam -genkey -name prime256v1 -noout -out new-ca.key
openssl req -new -x509 -days 3650 -sha256 \
  -key new-ca.key -out new-ca.crt \
  -subj "/CN=SecLAB Internal CA/O=SecLAB/C=US"

# 2. Create new cert-manager CA secret (in parallel with old — dual-trust period)
kubectl create secret tls internal-ca-keypair-v2 \
  --cert=new-ca.crt --key=new-ca.key -n cert-manager

# 3. Create new ClusterIssuer referencing new CA
# (run old and new in parallel during transition — do NOT delete old immediately)

# 4. Re-issue all certificates using new CA
# cert-manager will handle this automatically when cert renewals come due

# 5. After all certs have been re-issued, delete old CA ClusterIssuer and secret
# Verify: kubectl get certificates --all-namespaces — all READY, all using new issuer

# 6. Remove old CA secret
kubectl delete secret internal-ca-keypair -n cert-manager
```

---

## certbot: Fix Renewal Failures

```bash
# Check renewal status
certbot certificates

# Test renewal (dry run — no changes)
certbot renew --dry-run

# Force renewal (even if cert is not near expiry)
certbot renew --force-renewal

# If webroot challenge fails (nginx can't serve .well-known)
certbot renew --standalone  # Stops nginx temporarily
# Or fix webroot config:
# Add to nginx server block:
# location /.well-known/acme-challenge/ { root /var/www/certbot; }

# Check certbot logs
cat /var/log/letsencrypt/letsencrypt.log | tail -50
```

---

## Verification

After renewing certificates:

```bash
# cert-manager: confirm READY
kubectl get certificates --all-namespaces

# Check new expiry
kubectl get certificate my-tls-cert -n production \
  -o jsonpath='{.status.notAfter}' | xargs -I{} date -d{} "+%Y-%m-%d"

# Verify the running endpoint is using the new cert
echo | openssl s_client -connect HOST:PORT 2>/dev/null | \
  openssl x509 -noout -enddate -subject

# Run cert lifecycle auditor
./01-auditors/audit-cert-lifecycle.sh
```

---

## Next Steps

- Verify all fixes: `03-validate.md`
- Daily monitoring setup: `04-triage-alerts.md`
