# transit-policy.hcl — HashiCorp Vault Transit Secrets Engine Policy
# NIST: SC-12 (key management), SC-13 (cryptographic protection), AC-6 (least privilege)
# Usage: vault policy write transit-app transit-policy.hcl
# WHY: The transit secrets engine is "encryption as a service."
#      Applications send plaintext → Vault returns ciphertext.
#      The key NEVER leaves Vault. This policy defines what an application
#      can do with the key. It follows AC-6 (least privilege).

# ── Allow: Encrypt ────────────────────────────────────────────────────────
# WHY: Applications must be able to encrypt data before storing it.
# SC-28: Encryption at rest requires the application to encrypt before write.
# Limit: only encrypt — cannot read or export the raw key material.
path "transit/encrypt/app-key" {
  capabilities = ["update"]
  # WHY: "update" (POST) is required for encrypt endpoint.
  # The key name "app-key" scopes this to one specific key — not all transit keys.
}

# ── Allow: Decrypt ────────────────────────────────────────────────────────
# WHY: Applications must be able to decrypt data they previously encrypted.
# SC-28: Decryption is required for authorized reads.
# Limit: only decrypt — cannot sign, export, or rotate.
path "transit/decrypt/app-key" {
  capabilities = ["update"]
  # WHY: If this identity is compromised, the attacker can decrypt data
  # but cannot destroy the key (no delete), export key material (no export),
  # or rotate the key to lock out others (no manage).
}

# ── Allow: Rewrap ─────────────────────────────────────────────────────────
# WHY: After key rotation, existing ciphertexts are still encrypted with the
# old key version. Rewrap re-encrypts them with the new key version without
# exposing plaintext. SC-12: required for key rotation without data migration.
path "transit/rewrap/app-key" {
  capabilities = ["update"]
}

# ── Allow: Read key metadata (not material) ────────────────────────────────
# WHY: Applications may need to check the current key version to determine
# if cached ciphertexts need rewrapping. Metadata only — no key material.
path "transit/keys/app-key" {
  capabilities = ["read"]
  # WHY: "read" returns key metadata (versions, type, creation time) but NOT
  # the actual key bytes. Key material export is controlled by a separate policy.
}

# ── Deny: Export ─────────────────────────────────────────────────────────
# WHY: Explicitly deny export. If a key is exportable, the "encryption as a
# service" model breaks — the key can be extracted and used offline, bypassing
# audit logging. SC-12: key material should never leave the HSM boundary.
# "deny" overrides any broader path that might grant access.
path "transit/export/+/app-key" {
  capabilities = ["deny"]
}
path "transit/export/+/app-key/+" {
  capabilities = ["deny"]
}

# ── Deny: Sign ────────────────────────────────────────────────────────────
# WHY: Application encryption keys should not be used for signing.
# Separate keys for separate purposes (key separation principle — SC-12).
# A key that can sign can create forged documents/JWTs.
# If the application doesn't need signing, deny it.
path "transit/sign/app-key" {
  capabilities = ["deny"]
}
path "transit/verify/app-key" {
  capabilities = ["deny"]
}

# ── Deny: Key management operations ───────────────────────────────────────
# WHY: Applications must not be able to rotate, delete, or configure their
# own keys. Key lifecycle is a security team operation, not an app operation.
# AC-6: Applications are NOT privileged users.
path "transit/keys/app-key/config" {
  capabilities = ["deny"]
}
path "transit/keys/app-key/rotate" {
  capabilities = ["deny"]
}
path "transit/keys/app-key/trim" {
  capabilities = ["deny"]
}

# ── Deny: List all keys ────────────────────────────────────────────────────
# WHY: Applications should only know about their own key. Listing all keys
# reveals the naming conventions and scope of encryption — unnecessary exposure.
# AC-6: Least privilege — see only what you need.
path "transit/keys" {
  capabilities = ["deny"]
}

# ── Allow: Generate data key (for envelope encryption) ────────────────────
# WHY: For encrypting large data efficiently, applications use envelope encryption:
# 1. Vault generates a random data encryption key (DEK)
# 2. Application uses DEK to encrypt data locally (fast)
# 3. Vault wraps (encrypts) the DEK with the transit key (key encryption key)
# This avoids sending all data through Vault's API for large payloads.
# SC-13: Envelope encryption is a NIST-recommended pattern.
path "transit/datakey/plaintext/app-key" {
  capabilities = ["update"]
  # WHY: "plaintext" returns both encrypted and plaintext DEK.
  # Use "wrapped" instead if application only needs encrypted DEK (higher security).
}

# ── Separation of duties: rotation policy ─────────────────────────────────
# This policy is for APPLICATION identities only.
# Security team rotation policy is in a separate "transit-admin" policy.
# WHY: If the application could rotate its own key, a compromised application
# could lock out legitimate users by rotating before they can detect the breach.
