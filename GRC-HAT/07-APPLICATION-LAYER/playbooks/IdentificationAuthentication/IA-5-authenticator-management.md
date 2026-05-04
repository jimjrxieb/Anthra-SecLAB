# IA-5: Authenticator Management
**Family:** Identification and Authentication  
**NIST 800-53 Rev 5**  
**Layer:** Application (L7)

## Control Statement
Manage information system authenticators by verifying the identity of individuals or devices before distributing authenticators, establishing initial authenticator content, ensuring authenticators meet minimum strength requirements, and implementing administrative procedures for lost or compromised authenticators.

## Why It Matters at L7
Credentials are the most commonly stolen and abused artifact in application security incidents. Hardcoded API keys discovered in public repositories, default credentials left on framework admin panels, and API keys that have never been rotated are consistently among the top findings in penetration tests and breach investigations. At L7, authenticator hygiene means every secret has a home (a secrets manager), a lifecycle (rotation policy), and a detection mechanism (secret scanning in CI/CD). Kubernetes secrets encryption at rest closes the gap where etcd access would otherwise expose credentials directly. Certificate expiry monitoring prevents authentication failures from taking down services.

---

## GRC Analyst Perspective
> **No code access.** Tools: interviews, documentation review, SIEM dashboards, audit reports, evidence packages.

### Audit Questions
- Does the organization use a centralized secrets management solution (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault) for all application credentials? Which applications use local secret storage instead, and what is the justification?
- Is there a documented secret rotation policy specifying rotation frequency by credential type (API keys, database passwords, certificates, service account credentials)? When was this policy last reviewed?
- What controls prevent developers from hardcoding secrets in source code? Is secret scanning (Gitleaks, GitHub Advanced Security, Semgrep) running in CI/CD pipelines and pre-commit hooks?
- How does the organization manage the lifecycle of API keys — provisioning, rotation, and revocation? Is there an inventory of active API keys per application and per user?
- Are Kubernetes Secrets encrypted at rest in etcd? What is the encryption provider configuration, and has it been validated?
- What is the process for responding to a discovered hardcoded credential — including notification, revocation, rotation, and retrospective analysis?
- Are TLS certificates monitored for expiry? What is the alerting threshold, and who is responsible for certificate renewal?
- How are default credentials (framework admin accounts, database default users) managed on initial deployment? Is there an automated check that prevents deployment with known default credentials?

### Evidence to Request
| Evidence Item | Source | Acceptable Format |
|---|---|---|
| Secret rotation policy document (current version) | Security or Platform Engineering team | Policy document with rotation intervals by credential type |
| Secrets manager usage inventory (which apps use vault vs local secrets) | Platform Engineering or DevOps | Architecture diagram, application inventory, or configuration audit |
| CI/CD secret scanning configuration and last scan results | DevSecOps or Application Security | Pipeline config, scan report, or SAST/secret scan output |
| Kubernetes Secrets encryption at rest configuration | Platform Engineering or Cluster Admin | Encryption config YAML or cloud provider KMS configuration |
| Certificate inventory with expiry dates | Platform Engineering or PKI team | Certificate inventory spreadsheet, cert-manager report, or monitoring dashboard export |
| Evidence of last API key rotation per application (90-day window) | Application team or secrets manager audit log | Rotation logs, audit trail from secrets manager, or ticket records |

### Gap Documentation Template
**Control:** IA-5  
**Finding:** A Gitleaks scan of the application repository identified three hardcoded API keys and one database password committed to source code history. The credentials appear in commits dating back 14 months and have not been rotated since discovery.  
**Risk:** Hardcoded credentials in version control are accessible to any developer with repository read access, and if the repository is public or becomes public, to any external party. Unrotated credentials that have been committed remain valid attack artifacts indefinitely until explicitly revoked. The specific credentials identified grant access to a production third-party payment processing API.  
**Recommendation:** Immediately revoke and rotate all identified credentials. Remove credentials from git history using git-filter-repo or BFG Repo Cleaner. Implement Gitleaks as a pre-commit hook and CI/CD gate to prevent future commits. Migrate all secrets to a secrets manager with automated rotation enabled. Conduct a retrospective to determine if credentials were accessed externally.  
**Owner:** Development team (rotation and history cleanup), Platform Engineering (secrets manager migration), Application Security (scanning controls)  

### CISO Communication
> Our application security scan identified hardcoded credentials in multiple code repositories — including at least one that controls access to a production payment processing system. These credentials have been in version control long enough that we cannot be certain they have not been accessed by unauthorized parties. We are treating this as an active incident: credentials are being revoked and rotated immediately, and we are conducting a retrospective review of access logs for the affected systems. Longer-term, we are implementing automated scanning in our development pipeline to prevent this class of finding from reaching version control again, and we are migrating credentials to a managed vault with automatic rotation. The technical risk here is significant, and the business exposure — particularly around the payment system credential — warrants board-level awareness.

---

## Cybersecurity Engineer Perspective
> **Code access available.** Tools: kubectl, curl, cloud CLI, SIEM, scanning tools, direct remediation.

### Assessment Commands
```bash
# Run Gitleaks against the application repository to find hardcoded secrets
gitleaks detect --source . --report-format json --report-path /tmp/gitleaks-report.json
cat /tmp/gitleaks-report.json | jq '.[] | {file: .File, line: .StartLine, rule: .RuleID, secret: "REDACTED"}'

# Scan with Semgrep for secret patterns in application code
semgrep --config "p/secrets" --json . | jq '.results[] | {path: .path, line: .start.line, message: .extra.message}'

# Check Kubernetes Secrets encryption at rest
kubectl get secret -n <app-namespace> -o json | jq '.items[] | {name: .metadata.name, type: .type, keys: (.data // {} | keys)}'

# Check if etcd encryption is enabled (requires cluster admin)
kubectl get apiserver -o json 2>/dev/null | jq '.spec.encryption' || \
  echo "Check encryption-config on control plane directly"

# Check for default framework credentials still active
# Django admin default
curl -s -X POST https://<app-url>/admin/login/ \
  -d "username=admin&password=admin" | grep -i "login\|error\|welcome"

# Spring Boot default actuator (no auth)
curl -s -o /dev/null -w "%{http_code}" https://<app-url>/actuator/env

# Check certificate expiry for app TLS cert
echo | openssl s_client -connect <app-url>:443 -servername <app-url> 2>/dev/null | \
  openssl x509 -noout -dates
# macOS: same command works

# Check cert-manager certificate resources in cluster
kubectl get certificates -n <app-namespace> 2>/dev/null || echo "cert-manager not detected"
kubectl get certificaterequests -n <app-namespace> 2>/dev/null

# Check AWS Secrets Manager rotation status (if cloud-native)
# CUTOFF=$(date -d "90 days ago" +%Y-%m-%d)
# macOS: CUTOFF=$(date -v-90d +%Y-%m-%d)
aws secretsmanager list-secrets --query \
  "SecretList[?LastRotatedDate<='${CUTOFF}'] | [*].{Name:Name, LastRotated:LastRotatedDate}" \
  --output table 2>/dev/null || echo "AWS CLI not configured or insufficient permissions"
```

### Detection / Testing
```bash
# Scan entire git history for secrets (not just current state)
gitleaks detect --source . --log-opts="--all" \
  --report-format json --report-path /tmp/gitleaks-history.json
cat /tmp/gitleaks-history.json | jq 'length'
# Dangerous if: count > 0 — indicates historical secret exposure

# Check for secrets in environment variables passed to containers
kubectl get pods -n <app-namespace> -o json | \
  jq -r '.items[].spec.containers[].env // [] | .[] | select(.value != null) | "\(.name)=\(.value)"' | \
  grep -iE "(password|secret|token|key|api_key|credential|pass)" | \
  sed 's/=.*/=REDACTED/'
# Flag any literal values — these should be secretKeyRef or secretsmanager references

# Check for Kubernetes Secrets in plaintext (not opaque/encrypted)
kubectl get secrets -n <app-namespace> -o json | \
  jq -r '.items[] | select(.type != "kubernetes.io/service-account-token") | "\(.metadata.name): \(.type)"'

# Test if a known rotated secret (old value) still works
# Replace OLD_KEY with a previously rotated credential value for testing
OLD_KEY="<previously-rotated-api-key>"
curl -s -o /dev/null -w "%{http_code}" https://<app-url>/api/v1/profile \
  -H "X-API-Key: ${OLD_KEY}"
# Should return 401 — if 200, rotation did not revoke the old credential

# Check certificate expiry proactively
CERT_EXPIRY=$(echo | openssl s_client -connect <app-url>:443 -servername <app-url> 2>/dev/null | \
  openssl x509 -noout -enddate | cut -d= -f2)
EXPIRY_EPOCH=$(date -d "${CERT_EXPIRY}" +%s)
NOW_EPOCH=$(date +%s)
DAYS_LEFT=$(( (EXPIRY_EPOCH - NOW_EPOCH) / 86400 ))
echo "Certificate expires: ${CERT_EXPIRY} (${DAYS_LEFT} days remaining)"
[ "${DAYS_LEFT}" -lt 30 ] && echo "WARNING: Certificate expires in less than 30 days" || echo "OK"
```

### Remediation
```bash
# --- Revoke and rotate a hardcoded credential ---
# Step 1: Identify the credential type and revoke via provider (example: GitHub PAT)
# GitHub: Settings > Developer settings > Personal access tokens > Revoke
# AWS: aws iam delete-access-key --access-key-id <old-key>
# Generic API: use provider's key management console

# Step 2: Generate new credential and store in secrets manager
aws secretsmanager create-secret \
  --name "/app/<app-namespace>/api-key" \
  --description "API key for <app-name> production" \
  --secret-string '{"api_key":"<new-key-value>"}'

# Step 3: Update Kubernetes Secret to reference secrets manager (External Secrets Operator)
cat <<'EOF'
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: app-api-key
  namespace: <app-namespace>
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: aws-secretsmanager
    kind: ClusterSecretStore
  target:
    name: app-api-key
    creationPolicy: Owner
  data:
  - secretKey: api_key
    remoteRef:
      key: /app/<app-namespace>/api-key
      property: api_key
EOF

# Step 4: Remove hardcoded secret from git history
# Install: pip install git-filter-repo
git filter-repo --path <file-with-secret> --invert-paths
# Then force-push to remote (coordinate with team — rewrites history)

# --- Enable Kubernetes secrets encryption at rest ---
# Create encryption config (apply on control plane node)
cat <<'EOF'
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
      - secrets
    providers:
      - aescbc:
          keys:
            - name: key1
              secret: <base64-encoded-32-byte-key>
      - identity: {}
EOF

# Enable automatic rotation in AWS Secrets Manager
aws secretsmanager rotate-secret \
  --secret-id "/app/<app-namespace>/api-key" \
  --rotation-rules AutomaticallyAfterDays=90
```

### Validation
```bash
# Confirm Gitleaks finds no new secrets after remediation
gitleaks detect --source . --report-format json --report-path /tmp/gitleaks-post-remediation.json
FINDING_COUNT=$(cat /tmp/gitleaks-post-remediation.json | jq 'length')
echo "Gitleaks findings: ${FINDING_COUNT} — $([ "${FINDING_COUNT}" = "0" ] && echo PASS || echo FAIL)"
# Expected: 0 findings

# Confirm old (rotated) credentials no longer work
OLD_KEY="<previously-rotated-api-key>"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" https://<app-url>/api/v1/profile \
  -H "X-API-Key: ${OLD_KEY}")
echo "Old credential test: ${STATUS} — $([ "${STATUS}" = "401" ] && echo PASS || echo FAIL)"
# Expected: 401 Unauthorized — old key revoked

# Confirm no literal secrets in pod environment variables
LITERAL_SECRETS=$(kubectl get pods -n <app-namespace> -o json | \
  jq -r '.items[].spec.containers[].env // [] | .[] | select(.value != null) | .name' | \
  grep -icE "(password|secret|token|api_key)" || true)
echo "Literal secret env vars: ${LITERAL_SECRETS} — $([ "${LITERAL_SECRETS}" = "0" ] && echo PASS || echo REVIEW)"
# Expected: 0 literal secret values — all should use valueFrom.secretKeyRef

# Confirm certificate has more than 30 days until expiry
CERT_EXPIRY=$(echo | openssl s_client -connect <app-url>:443 -servername <app-url> 2>/dev/null | \
  openssl x509 -noout -enddate | cut -d= -f2)
EXPIRY_EPOCH=$(date -d "${CERT_EXPIRY}" +%s)
NOW_EPOCH=$(date +%s)
DAYS_LEFT=$(( (EXPIRY_EPOCH - NOW_EPOCH) / 86400 ))
echo "Certificate: ${DAYS_LEFT} days remaining — $([ "${DAYS_LEFT}" -gt 30 ] && echo PASS || echo WARNING)"
# Expected: > 30 days remaining
```

### Evidence Capture
```bash
EVIDENCE_DIR="/tmp/jsa-evidence/IA-5"
mkdir -p "${EVIDENCE_DIR}"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)

# Capture Gitleaks scan results (current state)
gitleaks detect --source . \
  --report-format json \
  --report-path "${EVIDENCE_DIR}/gitleaks-current-${TIMESTAMP}.json" 2>/dev/null
# Redact actual secret values before sharing with auditors
cat "${EVIDENCE_DIR}/gitleaks-current-${TIMESTAMP}.json" | \
  jq '[.[] | {file: .File, line: .StartLine, rule: .RuleID, commit: .Commit}]' \
  > "${EVIDENCE_DIR}/gitleaks-redacted-${TIMESTAMP}.json"
echo "Captured: ${EVIDENCE_DIR}/gitleaks-redacted-${TIMESTAMP}.json"

# Capture Kubernetes Secret inventory (keys only, no values)
kubectl get secrets -n <app-namespace> -o json | \
  jq -r '.items[] | {name: .metadata.name, type: .type, keys: (.data // {} | keys)}' \
  > "${EVIDENCE_DIR}/k8s-secrets-inventory-${TIMESTAMP}.json"
echo "Captured: ${EVIDENCE_DIR}/k8s-secrets-inventory-${TIMESTAMP}.json"

# Capture certificate expiry information
{
  echo "=== Certificate Expiry Check - ${TIMESTAMP} ==="
  echo | openssl s_client -connect <app-url>:443 -servername <app-url> 2>/dev/null | \
    openssl x509 -noout -subject -dates -issuer
} > "${EVIDENCE_DIR}/cert-expiry-${TIMESTAMP}.txt"
echo "Captured: ${EVIDENCE_DIR}/cert-expiry-${TIMESTAMP}.txt"

# Capture AWS Secrets Manager rotation status (if applicable)
# CUTOFF=$(date -d "90 days ago" +%Y-%m-%d)
# macOS: CUTOFF=$(date -v-90d +%Y-%m-%d)
CUTOFF=$(date -d "90 days ago" +%Y-%m-%d 2>/dev/null || date -v-90d +%Y-%m-%d 2>/dev/null || echo "date-command-unsupported")
aws secretsmanager list-secrets \
  --query "SecretList[*].{Name:Name, LastRotated:LastRotatedDate, RotationEnabled:RotationEnabled}" \
  --output json \
  > "${EVIDENCE_DIR}/secrets-manager-rotation-${TIMESTAMP}.json" 2>/dev/null || \
  echo "AWS CLI not available or insufficient permissions" > "${EVIDENCE_DIR}/secrets-manager-rotation-${TIMESTAMP}.json"
echo "Captured: ${EVIDENCE_DIR}/secrets-manager-rotation-${TIMESTAMP}.json"

echo "Evidence bundle complete: ${EVIDENCE_DIR}/"
ls -lh "${EVIDENCE_DIR}/"
```
