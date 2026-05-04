# CM-6: Configuration Settings
**Family:** Configuration Management  
**NIST 800-53 Rev 5**  
**Layer:** Application (L7)

## Control Statement
Establish and document configuration settings for information technology products employed within the information system that reflect the most restrictive mode consistent with operational requirements.

## Why It Matters at L7
Application configuration is the first line of defense against a broad class of web attacks — misconfigured HTTP headers leave browsers unable to enforce content policies, weak TLS settings expose sessions to downgrade attacks, and insecure cookie flags allow credential theft through XSS or network interception. At L7, a single missing header or incorrectly set cipher suite can negate months of application security investment. Production configurations must be hardened, version-controlled, and auditable.

---

## GRC Analyst Perspective
> **No code access.** Tools: interviews, documentation review, SIEM dashboards, audit reports, evidence packages.

### Audit Questions
- Does the organization maintain a documented baseline configuration standard for web application deployments, including required HTTP security headers?
- How are configuration changes reviewed and approved before reaching production? Is there a change management process that includes security review?
- Is there a mapping from the organization's configuration standard to CIS Benchmark controls or OWASP Secure Headers recommendations?
- How does the organization ensure that development or debug configurations (e.g., DEBUG=true, verbose logging) are not present in production deployments?
- Are TLS configuration standards documented, specifying minimum protocol version, acceptable cipher suites, and certificate requirements?
- How are Kubernetes ConfigMaps and Secrets managed? Is there a policy preventing sensitive values from being stored in ConfigMaps?
- What is the process for detecting and remediating configuration drift — when a live system no longer matches its approved baseline?
- Is CORS policy documented for each application, with justification for any cross-origin permissions granted?

### Evidence to Request
| Evidence Item | Source | Acceptable Format |
|---|---|---|
| HTTP security headers policy and standards document | Security or Platform Engineering team | Policy document, wiki page, or CIS benchmark mapping |
| TLS configuration baseline (minimum version, cipher allow-list) | Infrastructure or Platform team | Document, Terraform config excerpt, or TLS policy spec |
| ConfigMap vs Secret separation policy | DevOps or Platform Engineering | Policy document or ADR (Architecture Decision Record) |
| Configuration change management records (last 90 days) | Change Management or ITSM system | Change tickets, approval logs, or change advisory board minutes |
| Production vs development configuration comparison | DevOps or application team | Side-by-side diff, environment variable inventory, or deployment manifest review |
| Mozilla Observatory or equivalent header scan results | Security team or automated scan output | Scan report with grades and findings |

### Gap Documentation Template
**Control:** CM-6  
**Finding:** HTTP security headers (HSTS, CSP, X-Frame-Options) are absent or misconfigured on the production application, as evidenced by curl header inspection and Mozilla Observatory scan results.  
**Risk:** Without HSTS, users are vulnerable to SSL stripping attacks. Without CSP, XSS payloads can execute without browser-level restriction. Without X-Frame-Options, the application is susceptible to clickjacking.  
**Recommendation:** Implement a hardened header set via reverse proxy (nginx/Envoy/ALB) so that headers are enforced consistently regardless of application framework. Test against OWASP Secure Headers Project criteria. Target a Mozilla Observatory score of B or above.  
**Owner:** Platform Engineering (implementation), Application Security (validation)  

### CISO Communication
> Our web applications are currently missing several browser-enforced security controls that cost nothing to implement and protect users from well-documented attack patterns including session hijacking, clickjacking, and cross-site scripting. These controls — called HTTP security headers — are industry-standard requirements under CIS and OWASP benchmarks, and their absence would be flagged immediately in any third-party penetration test or compliance audit. We recommend a one-time configuration sprint to bring all production applications into compliance with our header policy, followed by automated scanning in the CI/CD pipeline to prevent regression. This is a low-effort, high-impact remediation that directly reduces our attack surface and demonstrates security hygiene to auditors and customers.

---

## Cybersecurity Engineer Perspective
> **Code access available.** Tools: kubectl, curl, cloud CLI, SIEM, scanning tools, direct remediation.

### Assessment Commands
```bash
# Check HTTP security headers on application
curl -sI https://<app-url> | grep -iE "(strict-transport|content-security|x-frame|x-content-type|referrer-policy|permissions-policy|set-cookie)"

# Full header dump for manual review
curl -sI https://<app-url>

# Check TLS configuration and cipher suites
nmap --script ssl-enum-ciphers -p 443 <app-url>

# Check minimum TLS version (expect TLSv1.2 or TLSv1.3 only)
openssl s_client -connect <app-url>:443 -tls1_1 2>&1 | grep -E "(handshake|Protocol)"
openssl s_client -connect <app-url>:443 -tls1_2 2>&1 | grep -E "(handshake|Protocol)"
openssl s_client -connect <app-url>:443 -tls1_3 2>&1 | grep -E "(handshake|Protocol)"

# Check HSTS max-age (should be >= 31536000)
curl -sI https://<app-url> | grep -i strict-transport

# Check CORS policy — should not return wildcard for credentialed requests
curl -sI -H "Origin: https://evil.example.com" -H "Access-Control-Request-Method: GET" https://<app-url>/api/ | grep -i "access-control"

# Check cookie flags on auth cookies
curl -sI -c /tmp/cookies.txt https://<app-url>/login | grep -i set-cookie
```

### Detection / Testing
```bash
# Test for TLS 1.0/1.1 acceptance (these should FAIL)
openssl s_client -connect <app-url>:443 -tls1 2>&1 | grep -E "(handshake|alert)"
openssl s_client -connect <app-url>:443 -tls1_1 2>&1 | grep -E "(handshake|alert)"

# Test CORS wildcard (misconfigured if Access-Control-Allow-Origin: * returned with credentials)
curl -sI \
  -H "Origin: https://attacker.example.com" \
  -H "Cookie: session=test" \
  https://<app-url>/api/v1/users | grep -i "access-control-allow-origin"

# Check for weak ciphers (RC4, DES, 3DES, EXPORT)
nmap --script ssl-enum-ciphers -p 443 <app-url> | grep -iE "(weak|rc4|des|export|null)"

# Check Kubernetes ConfigMaps for embedded secrets (base64 encoded or plaintext)
kubectl get configmaps -n <app-namespace> -o json | \
  jq -r '.items[] | .metadata.name as $name | .data // {} | to_entries[] | "\($name): \(.key)=\(.value)"' | \
  grep -iE "(password|secret|token|key|credential|api_key|db_pass)"

# Check if debug mode is enabled in application config
kubectl get configmap -n <app-namespace> -o json | \
  jq -r '.items[].data // {} | to_entries[] | select(.value | test("debug.*true|true.*debug"; "i")) | "\(.key)=\(.value)"'

# Check for secrets stored in environment variables (should reference Secret, not literal value)
kubectl get pods -n <app-namespace> -o json | \
  jq -r '.items[].spec.containers[].env // [] | .[] | select(.value != null) | "\(.name)=\(.value)"' | \
  grep -iE "(password|secret|token|key|api_key)"
```

### Remediation
```bash
# --- Nginx: add security headers ---
# Add to nginx.conf server block or via ConfigMap
cat <<'EOF'
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none';" always;
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
EOF

# --- Nginx: restrict TLS to 1.2 and 1.3 with strong ciphers ---
cat <<'EOF'
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305';
ssl_prefer_server_ciphers on;
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 1d;
ssl_session_tickets off;
EOF

# --- Move a ConfigMap value to a Secret ---
# Extract current plaintext value
CURRENT_VAL=$(kubectl get configmap <configmap-name> -n <app-namespace> -o jsonpath='{.data.<key-name>}')

# Create a proper Secret
kubectl create secret generic <secret-name> \
  --from-literal=<key-name>="${CURRENT_VAL}" \
  -n <app-namespace>

# Update the Deployment to reference the Secret instead of ConfigMap
# Edit the env section in the deployment manifest:
# env:
# - name: DB_PASSWORD
#   valueFrom:
#     secretKeyRef:
#       name: <secret-name>
#       key: <key-name>

# Remove the sensitive key from the ConfigMap
kubectl patch configmap <configmap-name> -n <app-namespace> \
  --type=json \
  -p='[{"op":"remove","path":"/data/<key-name>"}]'
```

### Validation
```bash
# Verify security headers are present and correct
curl -sI https://<app-url> | grep -iE "(strict-transport|content-security|x-frame|x-content-type|referrer)"
# Expected: All five headers present; HSTS max-age >= 31536000

# Confirm TLS 1.0 and 1.1 are rejected
openssl s_client -connect <app-url>:443 -tls1_1 2>&1 | grep "handshake failure"
# Expected: "handshake failure" or "no protocols available" — connection should be refused

# Confirm TLS 1.2 still works
openssl s_client -connect <app-url>:443 -tls1_2 2>&1 | grep "Cipher"
# Expected: A strong cipher (ECDHE, AES-GCM, CHACHA20) — no RC4, DES, EXPORT

# Confirm no secrets in ConfigMaps
kubectl get configmaps -n <app-namespace> -o json | \
  jq -r '.items[] | .data // {} | to_entries[] | .key' | \
  grep -icE "(password|secret|token|api_key)" || echo "PASS: no secret keys found in ConfigMaps"
# Expected: 0 matches or "PASS" message

# Confirm cookie flags
curl -sI https://<app-url>/login | grep -i set-cookie
# Expected: Set-Cookie header includes Secure; HttpOnly; SameSite=Strict (or Lax)
```

### Evidence Capture
```bash
EVIDENCE_DIR="/tmp/jsa-evidence/CM-6"
mkdir -p "${EVIDENCE_DIR}"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)

# Capture header scan
curl -sI https://<app-url> > "${EVIDENCE_DIR}/headers-${TIMESTAMP}.txt"
echo "Captured: ${EVIDENCE_DIR}/headers-${TIMESTAMP}.txt"

# Capture TLS cipher enumeration
nmap --script ssl-enum-ciphers -p 443 <app-url> > "${EVIDENCE_DIR}/tls-ciphers-${TIMESTAMP}.txt"
echo "Captured: ${EVIDENCE_DIR}/tls-ciphers-${TIMESTAMP}.txt"

# Capture ConfigMap key inventory (no values — avoid capturing secrets)
kubectl get configmaps -n <app-namespace> -o json | \
  jq -r '.items[] | .metadata.name as $name | .data // {} | keys[] | "\($name): \(.)"' \
  > "${EVIDENCE_DIR}/configmap-keys-${TIMESTAMP}.txt"
echo "Captured: ${EVIDENCE_DIR}/configmap-keys-${TIMESTAMP}.txt"

# Capture CORS test result
curl -sI \
  -H "Origin: https://test-cors-probe.example.com" \
  https://<app-url>/api/ \
  > "${EVIDENCE_DIR}/cors-test-${TIMESTAMP}.txt"
echo "Captured: ${EVIDENCE_DIR}/cors-test-${TIMESTAMP}.txt"

# Capture TLS protocol acceptance test
for PROTO in tls1 tls1_1 tls1_2 tls1_3; do
  echo "=== ${PROTO} ===" >> "${EVIDENCE_DIR}/tls-protocol-test-${TIMESTAMP}.txt"
  openssl s_client -connect <app-url>:443 -${PROTO} 2>&1 | grep -E "(Cipher|handshake|alert|Protocol)" \
    >> "${EVIDENCE_DIR}/tls-protocol-test-${TIMESTAMP}.txt"
done
echo "Captured: ${EVIDENCE_DIR}/tls-protocol-test-${TIMESTAMP}.txt"

echo "Evidence bundle complete: ${EVIDENCE_DIR}/"
ls -lh "${EVIDENCE_DIR}/"
```
