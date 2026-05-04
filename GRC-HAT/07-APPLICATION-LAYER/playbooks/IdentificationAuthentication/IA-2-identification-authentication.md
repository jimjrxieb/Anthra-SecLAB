# IA-2: Identification and Authentication (Organizational Users)
**Family:** Identification and Authentication  
**NIST 800-53 Rev 5**  
**Layer:** Application (L7)

## Control Statement
Uniquely identify and authenticate organizational users and associate that identification with processes acting on behalf of those users.

## Why It Matters at L7
Application-layer authentication is where identity claims are made and trusted. Weak or misconfigured authentication at L7 — such as JWT tokens signed with `alg:none`, shared service accounts, or applications that bypass SSO for certain endpoints — creates a gap that network and infrastructure controls cannot compensate for. Service-to-service authentication within a Kubernetes cluster is equally critical: workloads that communicate without mutual TLS or OIDC-based identity can be impersonated by any compromised pod in the network. Every authentication decision made at L7 determines the blast radius of a credential compromise.

---

## GRC Analyst Perspective
> **No code access.** Tools: interviews, documentation review, SIEM dashboards, audit reports, evidence packages.

### Audit Questions
- Is multi-factor authentication enforced for all user accounts with access to production systems? Are admin and privileged accounts subject to stricter MFA requirements than standard users?
- Has the organization implemented a centralized identity provider (SSO) for application authentication? Which applications authenticate directly against a local user store rather than SSO, and what is the justification?
- What is the documented policy for session token security, including token lifetime, refresh token rotation, and invalidation on logout?
- How does the organization ensure JWT tokens are signed with strong algorithms (RS256, ES256)? Is there a code review or automated scanning process that would catch a `alg:none` or `HS256` with a weak secret vulnerability?
- How is service-to-service authentication handled within the Kubernetes cluster? Is mutual TLS (mTLS) enforced via a service mesh, or are services accessed over unauthenticated internal channels?
- What is the MFA enrollment rate across user accounts? How are non-enrolled accounts identified and escalated?
- Is there a process for detecting and alerting on authentication bypass attempts — such as tokens with manipulated claims, repeated failed authentications, or access from unexpected geographic locations?

### Evidence to Request
| Evidence Item | Source | Acceptable Format |
|---|---|---|
| MFA enforcement policy and enrollment report | Identity team or IdP admin (Okta, Azure AD) | Policy document + IdP-generated enrollment report |
| SSO integration inventory (which apps use SSO vs local auth) | Architecture or Platform Engineering | Application inventory spreadsheet or architecture diagram |
| JWT signing algorithm configuration per application | Application Security or Development team | Code snippet, configuration file, or security review record |
| Service mesh mTLS configuration (Istio/Linkerd) or equivalent | Platform Engineering | Service mesh config, certificate authority documentation |
| Authentication architecture review (current quarter) | Security Architecture | Architecture review document or ADR |
| SIEM alert rules for authentication anomalies (failed logins, bypass attempts) | SOC or Security Engineering | SIEM rule export, alert configuration screenshot |

### Gap Documentation Template
**Control:** IA-2  
**Finding:** The application accepts JWT tokens signed with the `alg:none` algorithm, allowing an attacker to forge authentication tokens by removing the signature entirely and setting the algorithm header to "none." This was confirmed through manual testing by submitting a token with a stripped signature and `"alg":"none"` header.  
**Risk:** Any authenticated session in the application can be hijacked without knowledge of the signing key. An attacker can impersonate any user, including administrative accounts, by constructing a forged token. This constitutes a critical authentication bypass with potential for full application compromise.  
**Recommendation:** Explicitly validate and enforce accepted signing algorithms in the JWT verification library configuration. Never accept `alg:none`. Prefer RS256 or ES256 (asymmetric algorithms) over HS256. Implement automated scanning in CI/CD using Semgrep rules targeting JWT misconfiguration patterns.  
**Owner:** Application Development team (remediation), Application Security (validation and CI/CD control)  

### CISO Communication
> Our authentication review identified a critical vulnerability class in how several applications validate login tokens: the token signing algorithm is not explicitly enforced, allowing attackers to submit forged tokens that impersonate any user without knowing the application's secret key. This is a known and well-documented vulnerability category that has led to significant breaches at other organizations. In parallel, our MFA enrollment rate is below target for non-admin users, and several internal services communicate without any authentication between them inside the cluster. We are prioritizing fixes in this order: JWT algorithm enforcement (immediate), MFA gap remediation (30 days), and service-to-service authentication hardening (60 days). Each item has a clear owner and a measurable success criterion.

---

## Cybersecurity Engineer Perspective
> **Code access available.** Tools: kubectl, curl, cloud CLI, SIEM, scanning tools, direct remediation.

### Assessment Commands
```bash
# Decode a JWT token from the application (without verification) to inspect claims and header
# Capture a token first, then decode
TOKEN=$(curl -s -X POST https://<app-url>/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"testpass"}' | jq -r '.token // .access_token')

# Decode header (part before first dot)
echo "${TOKEN}" | cut -d. -f1 | base64 -d 2>/dev/null | jq .
# Look for: "alg" field — should be RS256 or ES256, never "none" or "HS256" with short secret

# Decode claims (part between dots)
echo "${TOKEN}" | cut -d. -f2 | base64 -d 2>/dev/null | jq .
# Look for: exp (expiry), iat (issued at), sub (subject), appropriate scope

# Check session token entropy (should be >= 128 bits)
curl -sI https://<app-url>/login | grep -i "set-cookie" | grep -oP "session=[^;]+" | head -1

# Check MFA enforcement — does the application have MFA-related headers or flows?
curl -s -X POST https://<app-url>/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"testpass"}' | jq .

# Check Kubernetes service accounts (look for default SA with automounted tokens)
kubectl get pods -n <app-namespace> -o json | \
  jq -r '.items[] | "\(.metadata.name): automountServiceAccountToken=\(.spec.automountServiceAccountToken // "not-set (defaults to true)")"'

# Check if service mesh (Istio) mTLS is enforced
kubectl get peerauthentication -n <app-namespace> 2>/dev/null || echo "No PeerAuthentication — mTLS may not be enforced"
kubectl get destinationrule -n <app-namespace> 2>/dev/null
```

### Detection / Testing
```bash
# Test JWT alg:none vulnerability
# Step 1: Get a valid token
VALID_TOKEN=$(curl -s -X POST https://<app-url>/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"testpass"}' | jq -r '.token // .access_token')

# Step 2: Decode the claims and re-encode without signature
CLAIMS=$(echo "${VALID_TOKEN}" | cut -d. -f2 | base64 -d 2>/dev/null)

# Step 3: Build a forged token with alg:none
ALG_NONE_HEADER=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 | tr '+/' '-_' | tr -d '=')
CLAIMS_B64=$(echo -n "${CLAIMS}" | base64 -w 0 | tr '+/' '-_' | tr -d '=')
# Note: -w 0 suppresses line wrapping (Linux/GNU base64); macOS base64 does not wrap by default
FORGED_TOKEN="${ALG_NONE_HEADER}.${CLAIMS_B64}."

# Step 4: Test if the forged token is accepted
curl -s https://<app-url>/api/v1/profile \
  -H "Authorization: Bearer ${FORGED_TOKEN}" | jq .
# Vulnerable if: returns valid user data instead of 401

# Test HS256 with weak secret (requires knowing the algorithm first)
# If alg=HS256, attempt to crack with common secrets:
# hashcat -a 0 -m 16500 "${VALID_TOKEN}" /usr/share/wordlists/rockyou.txt

# Test authentication bypass via parameter manipulation
curl -s https://<app-url>/api/v1/admin \
  -H "Authorization: Bearer ${VALID_TOKEN}" \
  -H "X-Forwarded-For: 127.0.0.1" | jq .

# Test for endpoints that skip authentication
for ENDPOINT in /api/v1/users /api/v1/admin /api/internal /api/v1/export; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://<app-url>${ENDPOINT}")
  echo "${STATUS} ${ENDPOINT}"
done

# Check for OIDC/OAuth2 misconfiguration (open redirect in callback)
curl -s -o /dev/null -w "%{http_code}" \
  "https://<app-url>/oauth/callback?code=test&redirect_uri=https://attacker.example.com"
```

### Remediation
```bash
# --- Enforce JWT algorithm in Node.js (jsonwebtoken) ---
cat <<'EOF'
// BAD: allows any algorithm
jwt.verify(token, secret);

// GOOD: explicitly enforce algorithm
jwt.verify(token, publicKey, { algorithms: ['RS256'] });
EOF

# --- Enforce JWT algorithm in Python (PyJWT) ---
cat <<'EOF'
import jwt

# BAD: algorithm not enforced
decoded = jwt.decode(token, secret, options={"verify_signature": False})

# GOOD: explicitly enforce algorithm, never allow 'none'
decoded = jwt.decode(
    token,
    public_key,
    algorithms=["RS256"],  # Never include 'none' or 'HS256' with symmetric secret in prod
    options={"require": ["exp", "iat", "sub"]}
)
EOF

# --- Kubernetes: disable service account token automounting ---
# Patch deployment to disable automounted SA tokens if not needed
kubectl patch deployment <deployment-name> -n <app-namespace> \
  --type=json \
  -p='[{"op":"add","path":"/spec/template/spec/automountServiceAccountToken","value":false}]'

# --- Istio: enforce STRICT mTLS for namespace ---
cat <<'EOF'
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
  namespace: <app-namespace>
spec:
  mtls:
    mode: STRICT
EOF

kubectl apply -f /tmp/peer-authentication-strict.yaml
```

### Validation
```bash
# Confirm alg:none is rejected
ALG_NONE_HEADER=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 | tr '+/' '-_' | tr -d '=')
DUMMY_CLAIMS=$(echo -n '{"sub":"testuser","exp":9999999999}' | base64 | tr '+/' '-_' | tr -d '=')
FORGED="${ALG_NONE_HEADER}.${DUMMY_CLAIMS}."

STATUS=$(curl -s -o /dev/null -w "%{http_code}" https://<app-url>/api/v1/profile \
  -H "Authorization: Bearer ${FORGED}")
echo "alg:none test: ${STATUS} — $([ "${STATUS}" = "401" ] && echo PASS || echo FAIL)"
# Expected: 401 Unauthorized

# Confirm mTLS is enforced (attempt plain HTTP connection between pods)
kubectl run mtls-test-pod --image=curlimages/curl:latest --rm -it --restart=Never \
  -n <app-namespace> -- \
  curl -s http://<service-name>.<app-namespace>.svc.cluster.local/api/health 2>&1 | \
  grep -iE "(connection refused|ssl|tls|handshake)"
# Expected: TLS handshake required or connection refused without client cert

# Confirm SA token automounting is disabled
kubectl get pod -n <app-namespace> -o json | \
  jq -r '.items[] | select(.spec.automountServiceAccountToken == false) | .metadata.name'
# Expected: pod names listed — confirms automounting disabled

# Confirm unauthenticated access to protected endpoints is denied
STATUS=$(curl -s -o /dev/null -w "%{http_code}" https://<app-url>/api/v1/users)
echo "Unauthenticated /api/v1/users: ${STATUS} — $([ "${STATUS}" = "401" ] && echo PASS || echo REVIEW)"
# Expected: 401 Unauthorized
```

### Evidence Capture
```bash
EVIDENCE_DIR="/tmp/jsa-evidence/IA-2"
mkdir -p "${EVIDENCE_DIR}"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)

# Capture JWT header analysis (algorithm and claims structure — redact sensitive values)
TOKEN=$(curl -s -X POST https://<app-url>/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"testpass"}' | jq -r '.token // .access_token')

{
  echo "=== JWT Header ==="
  echo "${TOKEN}" | cut -d. -f1 | base64 -d 2>/dev/null | jq .
  echo "=== JWT Claims (sensitive values redacted in review) ==="
  echo "${TOKEN}" | cut -d. -f2 | base64 -d 2>/dev/null | jq 'del(.sub) | .'
} > "${EVIDENCE_DIR}/jwt-analysis-${TIMESTAMP}.txt"
echo "Captured: ${EVIDENCE_DIR}/jwt-analysis-${TIMESTAMP}.txt"

# Capture alg:none test result
ALG_NONE_HEADER=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 | tr '+/' '-_' | tr -d '=')
DUMMY_CLAIMS=$(echo -n '{"sub":"audit-test","exp":9999999999}' | base64 | tr '+/' '-_' | tr -d '=')
FORGED="${ALG_NONE_HEADER}.${DUMMY_CLAIMS}."
{
  echo "=== alg:none Bypass Test - ${TIMESTAMP} ==="
  curl -s -o /dev/null -w "HTTP Status: %{http_code}\n" \
    https://<app-url>/api/v1/profile \
    -H "Authorization: Bearer ${FORGED}"
} > "${EVIDENCE_DIR}/jwt-algnone-test-${TIMESTAMP}.txt"
echo "Captured: ${EVIDENCE_DIR}/jwt-algnone-test-${TIMESTAMP}.txt"

# Capture service account automount status
kubectl get pods -n <app-namespace> -o json | \
  jq -r '.items[] | "\(.metadata.name): automountServiceAccountToken=\(.spec.automountServiceAccountToken // "not-set")"' \
  > "${EVIDENCE_DIR}/sa-automount-status-${TIMESTAMP}.txt"
echo "Captured: ${EVIDENCE_DIR}/sa-automount-status-${TIMESTAMP}.txt"

# Capture mTLS policy status
kubectl get peerauthentication -n <app-namespace> -o yaml \
  > "${EVIDENCE_DIR}/mtls-peerauthentication-${TIMESTAMP}.yaml" 2>/dev/null || \
  echo "No PeerAuthentication resources found" > "${EVIDENCE_DIR}/mtls-peerauthentication-${TIMESTAMP}.yaml"
echo "Captured: ${EVIDENCE_DIR}/mtls-peerauthentication-${TIMESTAMP}.yaml"

echo "Evidence bundle complete: ${EVIDENCE_DIR}/"
ls -lh "${EVIDENCE_DIR}/"
```
