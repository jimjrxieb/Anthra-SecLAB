# 00-install-validate.md — L5 Session Layer Tool Installation

| Field | Value |
|---|---|
| **NIST Controls** | AC-2, AC-6, AC-12, IA-2 |
| **Tools** | Entra ID (az CLI), Keycloak (Docker/Helm), kubectl RBAC tools (kubectl-who-can, rakkess), HashiCorp Vault |
| **Enterprise Equiv** | Okta ($150K+/yr) / CyberArk ($200K+/yr) / Duo ($80K+/yr) |
| **Time** | 2 hours |
| **Rank** | D (scripted, no decisions required) |

---

## What You're Installing

| Tool | Purpose | Source |
|---|---|---|
| Azure CLI (`az`) | Entra ID Conditional Access, user/group management | Microsoft |
| Keycloak | Open-source IdP — OIDC, SAML, TOTP, session policy | Red Hat / Quay.io |
| kubectl-who-can | "Who can do X in this namespace?" RBAC query | GitHub: aquasecurity |
| rakkess | Access matrix for all verbs across resource types | GitHub: corneliusweig |
| HashiCorp Vault | Secrets management, K8s auth, token TTL enforcement | HashiCorp |

---

## 1. Azure CLI (Entra ID Access)

### Install

```bash
# Linux (Debian/Ubuntu)
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

# macOS
brew install azure-cli

# Verify
az version
```

### Authenticate and configure

```bash
# Interactive login
az login

# If working with a specific tenant
az login --tenant <tenant-id>

# Verify access
az account show
az account show --query tenantId -o tsv

# Enable Microsoft Graph extension (for CA policies)
az extension add --name account 2>/dev/null || true
```

### Validate Entra ID access

```bash
# List users (requires User.Read.All)
az ad user list --query "[0].userPrincipalName" -o tsv

# List CA policies (requires Policy.Read.All)
az rest \
  --method GET \
  --url "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" \
  | python3 -c "import json,sys; d=json.load(sys.stdin); print(f'CA policies found: {len(d.get(\"value\", []))}')"
```

**Expected output:** Number of CA policies in your tenant. If you get a permissions error, you need Policy.Read.All granted to your user or the az CLI app.

---

## 2. Keycloak (Local Lab)

### Docker (fastest for lab use)

```bash
# Start Keycloak with admin credentials
docker run -d \
  --name keycloak \
  -p 8080:8080 \
  -e KEYCLOAK_ADMIN=admin \
  -e KEYCLOAK_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:latest \
  start-dev

# Wait for startup
sleep 15

# Verify
curl -s http://localhost:8080/health/ready | python3 -m json.tool
```

### Helm (K8s lab cluster)

```bash
helm repo add codecentric https://codecentric.github.io/helm-charts
helm repo update

helm install keycloak codecentric/keycloakx \
  --namespace keycloak \
  --create-namespace \
  --set auth.adminUser=admin \
  --set auth.adminPassword=admin \
  --set service.type=NodePort

# Wait for pod
kubectl rollout status deployment/keycloak -n keycloak
```

### Get admin token

```bash
KC_TOKEN=$(curl -s -X POST \
  http://localhost:8080/realms/master/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=admin&grant_type=password&client_id=admin-cli" \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['access_token'])")

echo "Token obtained: ${KC_TOKEN:0:20}..."

# Validate: list realms
curl -s http://localhost:8080/admin/realms \
  -H "Authorization: Bearer ${KC_TOKEN}" \
  | python3 -c "import json,sys; [print(r['realm']) for r in json.load(sys.stdin)]"
```

**Expected output:** `master` — the default realm name.

---

## 3. kubectl RBAC Tools

### kubectl-who-can (aquasecurity)

Answers "who can do X?" — e.g., who can `create deployments` in `production`?

```bash
# Install
kubectl krew install who-can

# Or binary install
KWHO_VERSION=$(curl -s https://api.github.com/repos/aquasecurity/kubectl-who-can/releases/latest \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['tag_name'])")
curl -L "https://github.com/aquasecurity/kubectl-who-can/releases/download/${KWHO_VERSION}/kubectl-who-can_linux_x86_64.tar.gz" \
  | tar -xz -C /usr/local/bin kubectl-who-can
chmod +x /usr/local/bin/kubectl-who-can

# Validate
kubectl who-can create deployments
kubectl who-can get secrets -n default
```

**Expected output:** List of users, groups, and service accounts that can perform the action.

### rakkess (access matrix)

Shows all verbs (get/list/create/delete) across all resources for a given identity.

```bash
# Install via krew
kubectl krew install access-matrix

# Or binary
RAKKESS_VERSION=$(curl -s https://api.github.com/repos/corneliusweig/rakkess/releases/latest \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['tag_name'])")
curl -L "https://github.com/corneliusweig/rakkess/releases/download/${RAKKESS_VERSION}/rakkess-amd64-linux.tar.gz" \
  | tar -xz -C /usr/local/bin rakkess
chmod +x /usr/local/bin/rakkess

# Validate
kubectl access-matrix --namespace default
kubectl access-matrix --as system:serviceaccount:default:default
```

**Expected output:** Grid of resources × verbs with allowed/denied indicators.

---

## 4. HashiCorp Vault (Optional, for SA-scoped secrets)

### Docker

```bash
docker run -d \
  --name vault \
  --cap-add=IPC_LOCK \
  -p 8200:8200 \
  -e 'VAULT_DEV_ROOT_TOKEN_ID=root' \
  -e 'VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200' \
  hashicorp/vault:latest

export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_TOKEN='root'

# Validate
vault status
vault kv put secret/test value=hello
vault kv get secret/test
```

### Enable K8s auth method

```bash
# Enable
vault auth enable kubernetes

# Configure (from inside cluster)
vault write auth/kubernetes/config \
  kubernetes_host="https://kubernetes.default.svc" \
  kubernetes_ca_cert=@/var/run/secrets/kubernetes.io/serviceaccount/ca.crt

vault auth list
```

**Expected output:** Vault status shows initialized, unsealed, and active.

---

## Validation Checklist

- [ ] `az account show` returns your tenant ID — Entra ID access confirmed
- [ ] `az rest --url .../conditionalAccess/policies` returns policy list
- [ ] `curl http://localhost:8080/health/ready` returns `{"status":"UP"}` — Keycloak running
- [ ] `kubectl who-can create deployments` returns subject list — RBAC tool working
- [ ] `kubectl access-matrix --namespace default` renders resource matrix
- [ ] `vault status` shows `Initialized: true, Sealed: false` (if Vault installed)
