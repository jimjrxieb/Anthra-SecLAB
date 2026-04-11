# vault-config.hcl — Hardened HashiCorp Vault Server Configuration
# NIST: SC-12 (key management), SC-13 (cryptographic protection), AU-2 (audit events)
# Usage: vault server -config=vault-config.hcl
# WHY: Default Vault configuration is not hardened. This template enforces
#      TLS, audit logging, and sane lease TTLs for production use.

# ── Storage Backend ────────────────────────────────────────────────────────
storage "raft" {
  # WHY: Raft is the recommended production storage backend as of Vault 1.4+.
  # It replaces Consul-based HA and provides integrated HA without an external
  # dependency. All data is encrypted at rest using AES-256-GCM.
  path    = "/opt/vault/data"
  node_id = "vault-node-1"

  # WHY: Retry join allows nodes to find each other even if cluster is forming.
  # Required for Kubernetes deployments or cloud instances with dynamic IPs.
  retry_join {
    leader_api_addr = "https://vault-node-1:8200"
  }
}

# ── Listeners ─────────────────────────────────────────────────────────────
listener "tcp" {
  # WHY: Never run Vault on plaintext HTTP in production.
  # SC-13 requires cryptographic protection of data in transit.
  # All API traffic, CLI connections, and UI access must be TLS-encrypted.
  address       = "0.0.0.0:8200"
  tls_cert_file = "/opt/vault/tls/vault.crt"
  tls_key_file  = "/opt/vault/tls/vault.key"

  # WHY: TLS 1.2 is the minimum. TLS 1.3 is preferred.
  # NIST SP 800-52 Rev 2 requires TLS 1.2+ for federal systems.
  tls_min_version = "tls12"

  # WHY: Disable TLS 1.0 and 1.1 explicitly. Both are broken.
  # BEAST, POODLE, and other attacks affect TLS 1.0/1.1.
  # tls_disable_client_certs defaults to false — mutual TLS for high-security deployments.
  tls_disable_client_certs = false

  # WHY: Only allow strong cipher suites. Removes RC4, DES, 3DES, EXPORT.
  # SC-13: Only FIPS 140-validated algorithms permitted.
  tls_cipher_suites = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_GCM_SHA384"

  # WHY: Cluster port is separate from API port for HA coordination.
  # Never expose cluster port to external networks — internal only.
  cluster_address = "0.0.0.0:8201"
}

# WHY: Metrics endpoint on localhost only. Prometheus scraping from within cluster.
# Never expose metrics externally — they reveal key names, mount paths, error rates.
listener "tcp" {
  address         = "127.0.0.1:8202"
  tls_disable     = true
  telemetry {
    unauthenticated_metrics_access = false
  }
}

# ── Audit Logging ──────────────────────────────────────────────────────────
audit {
  # WHY: AU-2 requires logging of all authentication events, secret access,
  # policy changes, and administrative actions. Vault's audit log captures
  # EVERY request and response. Any access to a secret is logged with:
  # - timestamp, path, operation, token_id, remote_address
  # The response includes HMAC-hashed secret values (not plaintext).
  type = "file"
  path = "file/"
  options = {
    file_path   = "/opt/vault/logs/vault-audit.log"
    log_raw     = "false"   # WHY: false = HMAC-hash secrets in logs (don't log plaintext)
    format      = "json"    # WHY: JSON for SIEM ingestion (Splunk, Elastic)
    mode        = "0600"    # WHY: Root-only read on audit log (AU-9 protection)
    rotate_duration = "24h" # WHY: Daily rotation for log management
    rotate_max_files = "30" # WHY: 30-day retention (adjust per compliance requirement)
  }
}

# WHY: Enable syslog as secondary audit device.
# If file audit device fails, Vault BLOCKS all requests until audit succeeds.
# Syslog as secondary ensures audit never fully fails.
audit "syslog" {
  type = "syslog"
  path = "syslog/"
  options = {
    facility = "AUTH"
    tag      = "vault"
    log_raw  = "false"
  }
}

# ── Seal Configuration ─────────────────────────────────────────────────────
# WHY: Auto-unseal with Azure Key Vault or AWS KMS means Vault doesn't require
# manual unseal on restart. Without this, a crash requires human intervention.
# SC-12: The unseal key is managed by the cloud HSM — FIPS 140-3 protection.

# Azure Key Vault auto-unseal (uncomment for Azure deployments):
# seal "azurekeyvault" {
#   tenant_id      = "<azure-tenant-id>"
#   client_id      = "<app-client-id>"
#   client_secret  = "<app-client-secret>"   # WHY: Use managed identity instead in production
#   vault_name     = "<key-vault-name>"
#   key_name       = "vault-unseal-key"
# }

# AWS KMS auto-unseal (uncomment for AWS deployments):
# seal "awskms" {
#   region     = "us-east-1"
#   kms_key_id = "<kms-key-id>"
#   # WHY: Use IAM role (not access keys) for EC2/EKS deployments
# }

# ── Lease TTL ─────────────────────────────────────────────────────────────
default_lease_ttl = "768h"   # 32 days
max_lease_ttl     = "768h"   # 32 days
# WHY: 768h is the HashiCorp recommended default for production.
# Shorter TTLs reduce the blast radius if a token is compromised.
# SC-12: Lease TTL acts as an automatic key expiry — tokens expire
# and must be renewed, creating audit events.
# For high-security environments: reduce to 24h-72h and require renewal.

# ── API Address ────────────────────────────────────────────────────────────
api_addr = "https://vault.example.internal:8200"
cluster_addr = "https://vault.example.internal:8201"
# WHY: Must be set correctly for redirect responses in HA clusters.
# Clients are redirected to the leader node — wrong addr = broken HA.

# ── UI ─────────────────────────────────────────────────────────────────────
ui = false
# WHY: Disable the web UI in production. SC-7 (boundary protection).
# The UI is an attack surface. CLI and API access only.
# Enable only for internal admin use behind VPN with MFA.

# ── Telemetry ─────────────────────────────────────────────────────────────
telemetry {
  # WHY: Metrics for operational monitoring. CA-7 (continuous monitoring).
  # Expose to Prometheus/Grafana via internal listener only.
  prometheus_retention_time = "30s"
  disable_hostname          = false

  # Forwarding to StatsD/DogStatsd for Datadog integration:
  # statsd_address = "localhost:8125"
}

# ── Raw Storage ────────────────────────────────────────────────────────────
raw_storage_endpoint = false
# WHY: Disable the raw storage endpoint. This endpoint bypasses all
# Vault policies and exposes raw backend data. Production: always false.

# ── Intrusion Detection ────────────────────────────────────────────────────
# WHY: Enable plugin directory for custom auth/secrets plugins.
# Set permissions to 755 root — Vault verifies SHA256 checksum of plugins.
plugin_directory = "/opt/vault/plugins"
