# 00-install-validate.md — L4 Transport Layer Tool Installation

| Field | Value |
|---|---|
| **NIST Controls** | SC-8, SC-13, IA-5 |
| **Tools** | testssl.sh, OpenSSL, cert-manager, Defender for Cloud |
| **Enterprise Equiv** | Qualys SSL Labs Enterprise ($50K+/yr), Venafi ($200K+/yr), DigiCert CertCentral ($100K+/yr) |
| **Time** | 1.5 hours |
| **Rank** | D (scripted, no decisions required) |

---

## What You're Installing

| Tool | Purpose | Source |
|---|---|---|
| testssl.sh | Comprehensive TLS cipher and protocol analysis | GitHub |
| OpenSSL | Certificate inspection, TLS handshake testing | System package |
| cert-manager | Automated certificate lifecycle in Kubernetes | Kubernetes manifest |
| Defender for Cloud | Azure TLS posture recommendations | Azure portal/CLI |

---

## 1. testssl.sh

testssl.sh is the open-source equivalent of Qualys SSL Labs — runs locally, no data leaves your environment, detailed cipher grading.

### Install

```bash
# Option A: Git clone (recommended — always current version)
git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl
chmod +x /opt/testssl/testssl.sh

# Option B: Add to PATH
echo 'export PATH="/opt/testssl:$PATH"' >> ~/.bashrc && source ~/.bashrc

# Option C: Package manager (may be older version)
# Ubuntu/Debian: apt-get install testssl.sh
# Arch: pacman -S testssl.sh
```

### Validate

```bash
testssl.sh --version
# Expected: testssl.sh 3.x.x from ...
# If "command not found": use /opt/testssl/testssl.sh

# Quick test (uses badssl.com — public test endpoint)
/opt/testssl/testssl.sh --fast https://tls-v1-0.badssl.com:1010/ 2>&1 | head -20
```

---

## 2. OpenSSL

OpenSSL is almost always pre-installed on Linux. Verify version — older versions may not support TLS 1.3.

### Check existing installation

```bash
openssl version
# Expected: OpenSSL 3.x.x or OpenSSL 1.1.1x
# TLS 1.3 requires OpenSSL 1.1.1+
```

### Install/upgrade if needed

```bash
# Ubuntu/Debian
sudo apt-get update && sudo apt-get install -y openssl

# RHEL/CentOS
sudo yum install openssl

# macOS
brew install openssl
```

### Validate

```bash
openssl version -a
# Expected: OpenSSL 1.1.1+ or 3.x.x

# Test TLS 1.3 support
echo | openssl s_client -connect google.com:443 -tls1_3 2>&1 | grep "Protocol"
# Expected: Protocol : TLSv1.3
```

---

## 3. cert-manager (Kubernetes)

cert-manager automates certificate issuance and renewal. Replaces Venafi for internal PKI.

### Install

```bash
# Latest stable release
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/latest/download/cert-manager.yaml

# Wait for cert-manager to be ready (takes ~60 seconds)
kubectl wait --for=condition=Available deployment/cert-manager -n cert-manager --timeout=120s
kubectl wait --for=condition=Available deployment/cert-manager-webhook -n cert-manager --timeout=120s
kubectl wait --for=condition=Available deployment/cert-manager-cainjector -n cert-manager --timeout=120s
```

### Install cert-manager kubectl plugin (optional but useful)

```bash
# Linux AMD64
curl -Lo kubectl-cert-manager.tar.gz \
  https://github.com/cert-manager/cert-manager/releases/latest/download/kubectl-cert_manager-linux-amd64.tar.gz
tar xzf kubectl-cert-manager.tar.gz
sudo mv kubectl-cert_manager /usr/local/bin/
```

### Validate

```bash
# Check pods running
kubectl get pods -n cert-manager
# Expected: cert-manager, cert-manager-cainjector, cert-manager-webhook — all Running

# Check CRDs installed
kubectl get crds | grep cert-manager
# Expected: certificates.cert-manager.io, clusterissuers.cert-manager.io, etc.

# Check ClusterIssuers (empty is OK at install time — add via templates)
kubectl get clusterissuer
# Expected: No resources found (until you deploy clusterissuer.yaml)

# Plugin test
kubectl cert-manager version
```

---

## 4. Microsoft Defender for Cloud — TLS Recommendations

Defender for Cloud is a SaaS service — no install required. Enable it and check TLS recommendations.

### Verify TLS recommendations are enabled

```bash
# Check Defender for Cloud pricing tier (Standard required for TLS recommendations)
az security pricing list --query "[?name=='AppServices' || name=='SqlServers' || name=='StorageAccounts'].{name:name, pricing:pricingTier}" -o table

# Expected: PricingTier = Standard for each resource type
# If Free: az security pricing create --name AppServices --tier Standard
```

### Review current TLS findings

```bash
# List all active TLS/SSL recommendations
az security assessment list \
  --query "[?contains(displayName,'TLS') || contains(displayName,'SSL') || contains(displayName,'secure transfer')].{recommendation:displayName, severity:metadata.severity, status:status.code}" \
  -o table
```

### Portal path

1. Azure Portal → Microsoft Defender for Cloud
2. Recommendations → filter by "TLS" or "SSL"
3. Review: "App Service apps should use the latest TLS version"
4. Review: "Secure transfer to storage accounts should be enabled"

---

## Quick Validation Checklist

```bash
# 1. testssl.sh
testssl.sh --version && echo "testssl.sh: OK"

# 2. OpenSSL (TLS 1.3 capable)
openssl version | grep -E "3\.|1\.1\." && echo "OpenSSL: OK"

# 3. cert-manager (if Kubernetes available)
kubectl get pods -n cert-manager --no-headers 2>/dev/null | grep -c "Running" | \
  xargs -I{} bash -c 'echo "cert-manager pods running: {}"'

# 4. Azure CLI (for Defender for Cloud)
az --version 2>/dev/null | head -1 && echo "az CLI: OK"
```

---

## Next Steps

1. Run `00-install-validate.md` (this file) — tools validated
2. Run `01-assess.md` — baseline TLS posture assessment
3. Run `01a-tls-audit.md` — deep TLS cipher analysis
4. Run `01b-cert-lifecycle-audit.md` — certificate inventory
5. Fix gaps using `02-fix-SC8-tls.md` and `02a-fix-IA5-certs.md`
6. Validate with `03-validate.md`
