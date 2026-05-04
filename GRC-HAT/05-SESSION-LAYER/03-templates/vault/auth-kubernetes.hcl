# auth-kubernetes.hcl — HashiCorp Vault Kubernetes Auth Configuration
# NIST: AC-2 (Account Management), AC-6 (Least Privilege), IA-2 (Authentication)
# Usage: Apply via Vault CLI or Terraform vault provider

# WHY: Vault's Kubernetes auth method allows pods to authenticate to Vault using
# their K8s service account tokens — no static credentials stored in pods.
# This replaces long-lived API keys with short-lived Vault tokens scoped to
# specific policies. Eliminates the #1 cause of secret sprawl in K8s environments.

# ─── Enable Kubernetes Auth Method ────────────────────────────────────────
# Run once: vault auth enable kubernetes
# Already enabled? vault auth list | grep kubernetes

# ─── Configure the Auth Method ────────────────────────────────────────────
# vault write auth/kubernetes/config \
#   kubernetes_host="https://kubernetes.default.svc" \
#   kubernetes_ca_cert=@/var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
#   token_reviewer_jwt=@/var/run/secrets/kubernetes.io/serviceaccount/token
#
# WHY: Vault validates SA tokens against the K8s API server using the TokenReview API.
# The kubernetes_host points to the cluster API. The CA cert validates the K8s API TLS cert.
# The token_reviewer_jwt is the SA token of Vault's own K8s SA (requires system:auth-delegator).

# ─── Vault Policy: app-readonly ───────────────────────────────────────────
# Save as: vault policy write app-readonly - <<EOF
path "secret/data/app/*" {
  # WHY: Application gets read access to its own secret path only.
  # AC-6 least privilege — application cannot read other apps' secrets.
  # The wildcard covers versioned secrets at secret/data/app/<app-name>/*
  capabilities = ["read", "list"]
}

path "secret/metadata/app/*" {
  # WHY: Metadata access required for listing available secret versions.
  # Read-only — application cannot delete or update metadata.
  capabilities = ["read", "list"]
}

# WHY: Deny access to all other paths explicitly. In Vault, absence of a rule = deny.
# These explicit denials document intent and protect against future policy inheritance.
path "secret/data/other-app/*" {
  capabilities = ["deny"]
}

path "auth/*" {
  # WHY: Applications must not be able to modify auth methods or create new tokens.
  # Token creation is privileged — application workloads use token_renew only.
  capabilities = ["deny"]
}

path "sys/*" {
  # WHY: System paths (sys/seal, sys/policy, etc.) are administrative.
  # No workload should ever have sys access.
  capabilities = ["deny"]
}
# EOF

# ─── Vault Policy: app-readwrite ──────────────────────────────────────────
# For applications that write secrets (e.g., rotating their own credentials)
# Save as: vault policy write app-readwrite - <<EOF
path "secret/data/app/MY-APP-NAME/*" {
  # WHY: Write-scoped policy is further restricted to a specific app path.
  # Not a wildcard across all apps — each app gets its own named path.
  # create/update/patch allow writing new secrets and updating existing ones.
  capabilities = ["create", "read", "update", "patch", "list"]
}

path "secret/metadata/app/MY-APP-NAME/*" {
  capabilities = ["read", "list", "delete"]
}

path "secret/delete/app/MY-APP-NAME/*" {
  # WHY: Soft delete allowed — hard delete is not (destroy is not listed).
  # Preserves audit trail. Only admins can destroy versions permanently.
  capabilities = ["update"]
}
# EOF

# ─── Kubernetes Auth Role ─────────────────────────────────────────────────
# vault write auth/kubernetes/role/my-app \
#   bound_service_account_names="my-app-sa" \
#   bound_service_account_namespaces="my-app-namespace" \
#   policies="app-readonly" \
#   ttl="1h" \
#   max_ttl="4h"

# WHY: The role binds a specific SA (my-app-sa) in a specific namespace to a Vault policy.
# Only pods using exactly that SA in exactly that namespace can assume this role.
# Cross-namespace escalation is prevented by the bound_service_account_namespaces constraint.

# TTL enforcement:
# ttl=1h — Vault token expires after 1 hour. Application must re-authenticate.
# WHY: Short TTL limits the window of exposure if a Vault token is stolen.
# NIST AC-12: session/token termination after defined period.
# max_ttl=4h — Even with renewal, token cannot live beyond 4 hours.
# WHY: Prevents indefinite token renewal. Forces full re-authentication cycle.

# ─── Multiple Application Roles ───────────────────────────────────────────
# Repeat vault write auth/kubernetes/role/* for each application:
#
# vault write auth/kubernetes/role/api-service \
#   bound_service_account_names="api-sa" \
#   bound_service_account_namespaces="api-namespace" \
#   policies="app-readonly" \
#   ttl="1h" \
#   max_ttl="4h"
#
# vault write auth/kubernetes/role/worker-service \
#   bound_service_account_names="worker-sa" \
#   bound_service_account_namespaces="worker-namespace" \
#   policies="app-readwrite" \
#   ttl="1h" \
#   max_ttl="4h"
#
# WHY: One role per application. Not one role for all workloads.
# Shared roles = shared blast radius if any workload is compromised.
# Separate roles = compromise of one workload does not grant access to others.

# ─── Vault Agent Sidecar Configuration (K8s annotation) ─────────────────
# Add to pod spec to have Vault Agent inject secrets as files:
#
# annotations:
#   vault.hashicorp.com/agent-inject: "true"
#   vault.hashicorp.com/role: "my-app"
#   vault.hashicorp.com/agent-inject-secret-config: "secret/data/app/my-app/config"
#   vault.hashicorp.com/agent-inject-template-config: |
#     {{- with secret "secret/data/app/my-app/config" -}}
#     DATABASE_URL={{ .Data.data.database_url }}
#     API_KEY={{ .Data.data.api_key }}
#     {{- end -}}
#
# WHY: Vault Agent injects secrets as environment files, not environment variables.
# Environment variables are visible in /proc, Docker inspect, and crash dumps.
# File injection + read-once-on-start is safer than persistent env var exposure.

# ─── Audit Logging ────────────────────────────────────────────────────────
# vault audit enable file file_path=/vault/logs/audit.log
#
# WHY: NIST AU-2/AU-12 require audit logging for all authentication events.
# Vault audit log captures every request: who authenticated, what path was read,
# what policy allowed it, and the response code. Essential for incident response.

# ─── Token Renewal ────────────────────────────────────────────────────────
# vault write auth/token/renew-self
# vault token renew -increment=1h <token>
#
# WHY: Applications using Vault Agent handle renewal automatically.
# Manual token management must implement renewal before TTL expiry.
# Token expiry without renewal = application loses secret access = outage.
# Monitor: vault token lookup <token> — check expire_time field.
