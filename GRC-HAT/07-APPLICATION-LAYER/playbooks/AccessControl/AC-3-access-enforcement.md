# AC-3: Access Enforcement
**Family:** Access Control  
**NIST 800-53 Rev 5**  
**Layer:** Application (L7)

## Control Statement
The information system enforces approved authorizations for logical access to information and system resources in accordance with applicable access control policies.

## Why It Matters at L7
OWASP consistently ranks Broken Access Control as the #1 web application vulnerability. At L7, access enforcement must happen server-side on every request — it cannot rely on the UI hiding buttons or client-side JavaScript disabling fields. IDOR (Insecure Direct Object Reference) flaws, missing authorization decorators on API endpoints, and role checks that exist in the UI but not the API are the most common failure modes, and all are invisible to network-layer controls.

---

## GRC Analyst Perspective
> **No code access.** Tools: interviews, documentation review, SIEM dashboards, audit reports, evidence packages.

### Audit Questions
- Does the application enforce authorization server-side on every API endpoint, or does any authorization logic exist only in the front-end client?
- Is there documented evidence that each application role maps to a specific set of permitted actions, and is this mapping enforced in code or configuration?
- Has the application been assessed for IDOR vulnerabilities — specifically whether one authenticated user can access another user's data by manipulating resource identifiers in URLs or request bodies?
- What access control model does the application use (RBAC, ABAC, ACL)? Is it implemented consistently across all endpoints, or are there endpoints that bypass the model?
- Has a penetration test or DAST scan been conducted that specifically tested authorization bypass scenarios? When was the last test?
- Are authorization failures (403 responses, rejected access attempts) logged in the SIEM with sufficient detail to detect enumeration or privilege escalation attempts?
- Is there a process for reviewing authorization policy changes before they are deployed to production?

### Evidence to Request
| Evidence Item | Source | Acceptable Format |
|---|---|---|
| DAST scan report showing authorization test results | ZAP, Burp Suite, or equivalent tool | PDF report with finding details, dated within 90 days |
| RBAC/ABAC role-permission matrix | Application documentation or IAM configuration | Spreadsheet or PDF mapping roles to permitted actions |
| Penetration test report with Broken Access Control findings | Third-party pentest firm or internal red team | Full report with remediation status |
| Code review evidence showing server-side auth checks on API endpoints | Pull request reviews, SAST scan | PR link or SAST report excerpt |
| SIEM alert configuration for repeated 403 responses (potential enumeration) | SIEM platform | Alert rule export or screenshot |
| Deployment approval records showing auth policy review | Change management / ticketing system | Dated approval records |

### Gap Documentation Template
**Control:** AC-3  
**Finding:** [API endpoints under /api/v1/admin/ enforce role-based access checks in the front-end React application but have no server-side authorization middleware; any authenticated user who crafts a direct HTTP request bypasses all role restrictions]  
**Risk:** [Any authenticated user — including low-privilege external customers — can access administrative functions, exfiltrate sensitive data, or modify other users' records without detection, constituting a critical Broken Access Control vulnerability per OWASP Top 10]  
**Recommendation:** [Implement server-side authorization middleware applied uniformly to all API routes; conduct a full DAST scan focused on authentication bypass and IDOR testing; establish CI pipeline gate that fails builds with missing auth decorators detected by SAST]  
**Owner:** Application Development Lead / Security Engineering  

### CISO Communication
> Our application currently relies on the user interface to restrict access to sensitive functions — but the underlying API has no equivalent protection. This means any user who knows the API endpoint address can bypass role restrictions entirely, without any special technical skill. This is the most commonly exploited web application vulnerability in the industry, and it has resulted in major data breaches across healthcare, finance, and government sectors. Remediating this requires the development team to add authorization checks directly to the server-side API code, not just the interface. We also need a dynamic scan of the application that actively attempts to bypass access controls before every major release, so we catch regressions before they reach production.

---

## Cybersecurity Engineer Perspective
> **Code access available.** Tools: kubectl, cloud CLI, SIEM queries, direct remediation.

### Assessment Commands
```bash
# List all ingress resources and their annotations (look for auth annotations)
kubectl get ingress -n <app-namespace> -o json \
  | jq -r '.items[] | "\(.metadata.name) | annotations: \(.metadata.annotations)"'

# Check for OAuth2 proxy or auth middleware annotations on ingress
kubectl get ingress -n <app-namespace> -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.metadata.annotations.nginx\.ingress\.kubernetes\.io/auth-url}{"\n"}{end}'

# Check NetworkPolicy — does the namespace restrict ingress to known sources?
kubectl get networkpolicy -n <app-namespace> -o yaml

# Run Semgrep to detect missing authorization decorators in Python Flask/FastAPI
# Write custom rule to temp file (semgrep requires file path, not inline YAML)
cat > /tmp/missing-auth-check.yaml <<'EOF'
rules:
  - id: missing-auth-decorator
    patterns:
      - pattern: |
          @app.route(...)
          def $FUNC(...):
              ...
      - pattern-not: |
          @app.route(...)
          @login_required
          def $FUNC(...):
              ...
      - pattern-not: |
          @app.route(...)
          @require_permissions(...)
          def $FUNC(...):
              ...
    message: "Route handler $FUNC missing authentication decorator"
    languages: [python]
    severity: ERROR
EOF
semgrep --config /tmp/missing-auth-check.yaml /path/to/app/source/

# Semgrep check for IDOR-prone patterns (direct object ID from request without ownership check)
semgrep --config "p/owasp-top-ten" /path/to/app/source/ --json > /tmp/semgrep-ac3-results.json
```

### Detection / Testing
```bash
# Manual IDOR test: authenticate as User A, then try to access User B's resource
# Step 1: Get User A's auth token
TOKEN_A=$(curl -s -X POST https://<app-name>/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"user_a","password":"<password_a"}' \
  | jq -r '.token')

# Step 2: Get User A's own resource ID
USER_A_RESOURCE=$(curl -s https://<app-name>/api/users/me \
  -H "Authorization: Bearer ${TOKEN_A}" | jq -r '.id')

# Step 3: Try to access User B's resource using User A's token (IDOR test)
# Replace <user_b_id> with a known different user ID
curl -v -X GET "https://<app-name>/api/users/<user_b_id>/data" \
  -H "Authorization: Bearer ${TOKEN_A}"
# Expected: 403 Forbidden — FAIL if 200 OK returned

# KQL — Sentinel: Detect repeated 403 responses from a single user (enumeration)
AppRequests
| where TimeGenerated > ago(1h)
| where ResultCode == 403
| summarize FailedAttempts=count(), DistinctPaths=dcount(Url) by UserId, ClientIP
| where FailedAttempts > 20 and DistinctPaths > 5
| order by FailedAttempts desc

# SPL — Splunk: Detect privilege escalation — low-role user accessing admin endpoints
index=app_access sourcetype=nginx_access
| regex uri="/api/v1/admin"
| lookup user_roles username AS user OUTPUT role
| where role!="admin" AND role!="superuser"
| stats count BY user, uri, src_ip
| sort -count
```

### Remediation
```bash
# Apply a Kubernetes NetworkPolicy that restricts who can reach the application pods
cat <<EOF | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: <app-name>-ingress-restrict
  namespace: <app-namespace>
spec:
  podSelector:
    matchLabels:
      app: <app-name>
  policyTypes:
  - Ingress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: ingress-nginx
    ports:
    - protocol: TCP
      port: 8080
EOF

# Add OAuth2-proxy auth annotation to ingress (nginx ingress controller)
kubectl annotate ingress <app-name>-ingress -n <app-namespace> \
  nginx.ingress.kubernetes.io/auth-url="https://oauth2proxy.<domain>/oauth2/auth" \
  nginx.ingress.kubernetes.io/auth-signin="https://oauth2proxy.<domain>/oauth2/start" \
  --overwrite

# Annotate the ingress with the auth-response-headers to pass identity to the backend
kubectl annotate ingress <app-name>-ingress -n <app-namespace> \
  nginx.ingress.kubernetes.io/auth-response-headers="X-Auth-Request-User,X-Auth-Request-Email,X-Auth-Request-Groups" \
  --overwrite
```

### Validation
```bash
# Confirm NetworkPolicy is applied
kubectl get networkpolicy <app-name>-ingress-restrict -n <app-namespace> -o yaml
# Expected: policy present with correct podSelector and ingress rules

# Re-run IDOR test with User A's token against User B's resource
curl -o /dev/null -s -w "%{http_code}" \
  "https://<app-name>/api/users/<user_b_id>/data" \
  -H "Authorization: Bearer ${TOKEN_A}"
# Expected: 403

# Confirm unauthenticated request returns 401 (not 200 or redirect to data)
curl -o /dev/null -s -w "%{http_code}" \
  "https://<app-name>/api/users/me"
# Expected: 401

# Confirm auth annotation is set on ingress
kubectl get ingress <app-name>-ingress -n <app-namespace> \
  -o jsonpath='{.metadata.annotations.nginx\.ingress\.kubernetes\.io/auth-url}'
# Expected: https://oauth2proxy.<domain>/oauth2/auth
```

### Evidence Capture
```bash
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
EVIDENCE_DIR="/tmp/ac3-evidence-${TIMESTAMP}"
mkdir -p "${EVIDENCE_DIR}"

# Ingress configuration with auth annotations
kubectl get ingress -n <app-namespace> -o json \
  > "${EVIDENCE_DIR}/ingress-config.json"

# NetworkPolicy snapshot
kubectl get networkpolicy -n <app-namespace> -o yaml \
  > "${EVIDENCE_DIR}/networkpolicies.yaml"

# Semgrep SAST results
semgrep --config "p/owasp-top-ten" /path/to/app/source/ --json \
  > "${EVIDENCE_DIR}/semgrep-owasp-scan.json"

# IDOR test result (curl response code and headers)
curl -v "https://<app-name>/api/users/<user_b_id>/data" \
  -H "Authorization: Bearer ${TOKEN_A}" 2>&1 \
  > "${EVIDENCE_DIR}/idor-test-result.txt"

echo "Evidence written to ${EVIDENCE_DIR}"
ls -lh "${EVIDENCE_DIR}"
```
