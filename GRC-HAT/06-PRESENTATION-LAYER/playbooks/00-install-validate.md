# 00-install-validate.md — L6 Presentation Layer Tool Installation

| Field | Value |
|---|---|
| **NIST Controls** | SC-28 (protection of info at rest), SC-13 (cryptographic protection), SC-12 (key management) |
| **Tools** | HashiCorp Vault, Azure Key Vault (az CLI), SOPS + age, gitleaks, detect-secrets, OpenSSL, hashcat |
| **Enterprise Equiv** | Thales CipherTrust ($250K+) / CyberArk ($200K+) / Venafi ($150K+) |
| **Time** | 2 hours |
| **Rank** | D (scripted, no decisions required) |

---

## What You're Installing

| Tool | Purpose | Source |
|---|---|---|
| HashiCorp Vault | Transit encryption-as-a-service, secret lifecycle, key rotation | HashiCorp |
| Azure CLI (`az`) | Azure Key Vault management, disk encryption, key rotation | Microsoft |
| SOPS | Encrypt secrets in git repos (YAML/JSON/.env) | Mozilla |
| age | Modern encryption for SOPS (replaces PGP) | FiloSottile |
| gitleaks | Detect secrets in git history and working directory | gitleaks.io |
| detect-secrets | Detect secrets in files, pre-commit hook | Yelp |
| OpenSSL | TLS cipher testing, certificate operations, hash validation | OpenSSL |
| hashcat | Demonstrate hash cracking speed (why MD5 is broken) | hashcat.net |

---

## 1. HashiCorp Vault (Dev Mode for Lab)

### Docker (fastest for lab)

```bash
docker run -d \
    --name vault \
    --cap-add=IPC_LOCK \
    -p 8200:8200 \
    -e 'VAULT_DEV_ROOT_TOKEN_ID=root' \
    -e 'VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200' \
    hashicorp/vault:1.15.4

export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_TOKEN='root'

# Validate
vault status
# Expected: Initialized: true, Sealed: false, HA Enabled: false
```

### Enable transit secrets engine

```bash
# WHY: Transit engine = encryption-as-a-service
# Applications send plaintext to Vault, get ciphertext back. Key never leaves Vault.
vault secrets enable transit
vault write -f transit/keys/app-key type=aes256-gcm96
# WHY: aes256-gcm96 = AES-256 with GCM mode (authenticated encryption, prevents tampering)

# Test encrypt/decrypt
CIPHER=$(vault write -field=ciphertext transit/encrypt/app-key plaintext=$(echo -n "test-secret" | base64))
echo "Ciphertext: $CIPHER"

vault write -field=plaintext transit/decrypt/app-key ciphertext="$CIPHER" | base64 --decode
# Expected: test-secret
```

### Apply transit policy

```bash
vault policy write transit-app ../03-templates/hashicorp-vault/transit-policy.hcl
vault token create -policy=transit-app -ttl=1h
```

**Expected output:** Vault status shows `Initialized: true, Sealed: false`. Transit encrypt/decrypt returns correct plaintext.

---

## 2. Azure CLI (Azure Key Vault Access)

### Install

```bash
# Linux
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

# macOS
brew install azure-cli

# Verify
az version
```

### Authenticate and configure

```bash
az login
az account show --query tenantId -o tsv

# List Key Vaults
az keyvault list --query "[].{name:name, rg:resourceGroup}" -o table

# Set env var for auditor scripts
export AZURE_VAULT_NAME="<your-vault-name>"

# Test: list keys
az keyvault key list --vault-name "$AZURE_VAULT_NAME" -o table
```

**Expected output:** Key list or empty table. Error = permissions issue (need Key Vault Reader role at minimum).

---

## 3. SOPS + age

### Install SOPS

```bash
# Linux
SOPS_VERSION=$(curl -s https://api.github.com/repos/mozilla/sops/releases/latest \
    | python3 -c "import json,sys; print(json.load(sys.stdin)['tag_name'])")
curl -L "https://github.com/mozilla/sops/releases/download/${SOPS_VERSION}/sops-${SOPS_VERSION}.linux.amd64" \
    -o /usr/local/bin/sops
chmod +x /usr/local/bin/sops

# macOS
brew install sops

# Verify
sops --version
```

### Install age

```bash
# Linux
AGE_VERSION=$(curl -s https://api.github.com/repos/FiloSottile/age/releases/latest \
    | python3 -c "import json,sys; print(json.load(sys.stdin)['tag_name'])")
curl -L "https://github.com/FiloSottile/age/releases/download/${AGE_VERSION}/age-${AGE_VERSION}-linux-amd64.tar.gz" \
    | tar -xz -C /usr/local/bin --strip-components=1

# macOS
brew install age

# Generate key pair
age-keygen -o ~/.config/sops/age/keys.txt
cat ~/.config/sops/age/keys.txt
# Shows: public key (starts with age1...) and private key (starts with AGE-SECRET-KEY)

export SOPS_AGE_KEY_FILE=~/.config/sops/age/keys.txt
```

### Test SOPS encryption

```bash
# Create a test secret file
cat > /tmp/test-secret.yaml <<EOF
database:
  password: supersecret
  host: db.internal
EOF

# Configure .sops.yaml (update with your age public key from above)
# Then encrypt
sops --encrypt --age $(grep "public key:" ~/.config/sops/age/keys.txt | awk '{print $NF}') \
    --encrypted-regex "password" \
    /tmp/test-secret.yaml > /tmp/test-secret.enc.yaml

cat /tmp/test-secret.enc.yaml
# host: should be plaintext, password: should be ENC[...]

# Decrypt
sops --decrypt /tmp/test-secret.enc.yaml
# Should return original values
```

**Expected output:** `password` field shows `ENC[AES256_GCM,data=...]`. `host` stays plaintext. Decrypt returns original values.

---

## 4. gitleaks

### Install

```bash
# Linux
GITLEAKS_VERSION=$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest \
    | python3 -c "import json,sys; print(json.load(sys.stdin)['tag_name'])")
curl -L "https://github.com/gitleaks/gitleaks/releases/download/${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION#v}_linux_x64.tar.gz" \
    | tar -xz -C /usr/local/bin gitleaks

# macOS
brew install gitleaks

# Verify
gitleaks version
```

### Test

```bash
# Scan current directory
gitleaks detect --source . --verbose

# If you want to test it detects something:
echo "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" > /tmp/test-leak.txt
gitleaks detect --source /tmp --no-git --verbose
# Expected: 1 leak found (aws-access-token rule)
rm /tmp/test-leak.txt
```

**Expected output:** No leaks detected in a clean repo. 1 leak detected in test file.

---

## 5. detect-secrets

### Install

```bash
pip install detect-secrets==1.4.0
# Verify
detect-secrets --version
```

### Create baseline

```bash
# In your project root
detect-secrets scan > .secrets.baseline

# Add to pre-commit
cat >> .pre-commit-config.yaml <<'EOF'
  - repo: https://github.com/Yelp/detect-secrets
    rev: v1.4.0
    hooks:
      - id: detect-secrets
        args: ['--baseline', '.secrets.baseline']
EOF
```

**Expected output:** `.secrets.baseline` JSON file with 0 results in a clean repo.

---

## 6. OpenSSL (TLS and Hash Operations)

```bash
# Should already be installed. Verify:
openssl version
# Expected: OpenSSL 3.x.x or 1.1.x

# Test strong TLS config
OPENSSL_CONF=../03-templates/openssl/strong-defaults.cnf \
    openssl s_client -connect google.com:443 -brief 2>&1 | head -5
# Expected: TLSv1.3 or TLSv1.2

# Test weak cipher rejection
OPENSSL_CONF=../03-templates/openssl/strong-defaults.cnf \
    openssl s_client -connect google.com:443 -cipher RC4-SHA 2>&1 | grep -i "error\|no cipher"
# Expected: "no ciphers available" or handshake failure
```

---

## 7. hashcat (MD5 crack speed demo)

```bash
# Install (Ubuntu/Debian)
sudo apt-get install hashcat

# macOS
brew install hashcat

# Verify
hashcat --version

# Demo: how fast MD5 can be cracked (benchmark only — no real wordlist needed)
hashcat -b -m 0   # -m 0 = MD5
# Expected on modern CPU: ~1 billion H/s
# Expected on GPU (RTX 4090): ~160 billion H/s

# Compare: bcrypt benchmark
hashcat -b -m 3200  # -m 3200 = bcrypt
# Expected: ~40,000-100,000 H/s
# WHY: bcrypt is 1 MILLION times slower than MD5. That is the point.
```

---

## Validation Checklist

- [ ] `vault status` returns `Initialized: true, Sealed: false`
- [ ] `vault write transit/encrypt/app-key plaintext=...` returns ciphertext
- [ ] `az account show` returns tenant ID
- [ ] `sops --version` works, age keygen creates key pair
- [ ] `gitleaks detect --source .` runs without error
- [ ] `detect-secrets scan` creates baseline file
- [ ] `openssl s_client -connect host:443` negotiates TLS 1.2+
- [ ] `hashcat -b -m 0` shows MD5 speed >> `hashcat -b -m 3200` (bcrypt speed)
