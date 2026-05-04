# CM-7: Least Functionality
**Family:** Configuration Management  
**NIST 800-53 Rev 5**  
**Layer:** Application (L7)

## Control Statement
Configure the information system to provide only essential capabilities, prohibiting or restricting the use of functions, ports, protocols, and services not required by the mission or business function.

## Why It Matters at L7
Web applications and frameworks ship with features enabled by default that are only appropriate for development environments — debug consoles, admin dashboards, health check endpoints, and verbose error pages. In production, these features become direct attack vectors: a Spring Boot `/actuator/heapdump` endpoint leaks credentials from heap memory, a Django `DEBUG=True` setting exposes stack traces with environment variables, and an exposed `/metrics` endpoint without authentication reveals internal service topology to reconnaissance tools. Least functionality at L7 means every enabled feature has a documented reason to exist in production.

---

## GRC Analyst Perspective
> **No code access.** Tools: interviews, documentation review, SIEM dashboards, audit reports, evidence packages.

### Audit Questions
- Does the organization maintain an inventory of endpoints and features that are explicitly disabled in production? How is this list reviewed and updated?
- What is the approval process for enabling non-default features or admin endpoints in a production application? Is there an exception management workflow?
- How does the organization ensure that framework debug modes (Spring Boot dev tools, Django DEBUG=True, Rails development mode) cannot be deployed to production — either through pipeline controls or configuration management?
- Are admin and management interfaces (e.g., database admin tools, application admin panels) exposed on separate network segments or require additional authentication beyond the application login?
- What HTTP methods does each application accept, and is there documented justification for methods beyond GET and POST where they are in use?
- How frequently are exposed endpoints reviewed against the approved endpoint inventory? Who owns that review?
- Are container images hardened to remove unnecessary shells, package managers, and debugging utilities before production deployment?

### Evidence to Request
| Evidence Item | Source | Acceptable Format |
|---|---|---|
| Inventory of disabled endpoints and features per application | Application team or Platform Engineering | Document, runbook, or deployment checklist |
| Debug mode configuration controls (pipeline enforcement) | CI/CD or DevOps team | Pipeline config, deployment policy, or environment variable documentation |
| Exception log for any non-default features enabled in production | Change Management or Security team | Change tickets, risk acceptance records, or exception register |
| Container image hardening checklist or Dockerfile review | DevOps or Application Security | Dockerfile, image scan report (Trivy/Grype), or hardening checklist |
| HTTP method policy per application or API | Architecture or Application team | API specification, WAF rule set, or documented policy |
| Periodic endpoint review records | Application Security or Compliance | Review minutes, scan reports, or audit findings |

### Gap Documentation Template
**Control:** CM-7  
**Finding:** Spring Boot Actuator endpoints including `/actuator/env` and `/actuator/heapdump` are accessible without authentication in the production environment, exposing environment variables, configuration properties, and heap memory contents.  
**Risk:** An unauthenticated attacker with network access to the application can retrieve database credentials, API keys, and application secrets from the `/actuator/env` and `/actuator/heapdump` endpoints. This constitutes a critical credential exposure risk that could lead to full environment compromise.  
**Recommendation:** Restrict Actuator endpoint exposure to only `/actuator/health` and `/actuator/info` in production. Secure remaining endpoints behind Spring Security with role-based access control. If Actuator endpoints are required for observability, expose them on a separate management port accessible only from the cluster internal network.  
**Owner:** Application Development team (remediation), Platform Engineering (network restriction), Application Security (validation)  

### CISO Communication
> Several of our production applications have development-mode features and administrative interfaces left enabled that were never intended for external exposure. These include health-check and diagnostics endpoints that can reveal internal configuration details, API keys, and database credentials to anyone who knows the URL — no login required. This class of vulnerability is among the most commonly exploited in web application attacks because it requires no technical skill: the attacker simply navigates to a known URL. We are initiating a sweep of all production applications to identify and disable non-essential features, followed by a CI/CD pipeline control that prevents debug configurations from ever reaching production again. The risk here is significant and the fix is straightforward.

---

## Cybersecurity Engineer Perspective
> **Code access available.** Tools: kubectl, curl, cloud CLI, SIEM, scanning tools, direct remediation.

### Assessment Commands
```bash
# Probe common debug and admin endpoints
for ENDPOINT in \
  /actuator /actuator/env /actuator/heapdump /actuator/mappings /actuator/beans \
  /debug /admin /metrics /health /info /status \
  /__debug__ /_debug /django-admin /phpmyadmin \
  /api/debug /api/internal /swagger-ui /swagger-ui.html /api-docs /v2/api-docs /v3/api-docs; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://<app-url>${ENDPOINT}")
  echo "${STATUS} https://<app-url>${ENDPOINT}"
done

# Check for TRACE method (should be disabled — enables XST attacks)
curl -s -o /dev/null -w "%{http_code}" -X TRACE https://<app-url>/

# Check which HTTP methods are accepted (OPTIONS reveals allowed methods)
curl -s -I -X OPTIONS https://<app-url>/ | grep -i "allow"

# Check open ports on application host/pod
nmap -sV -p 1-65535 <app-url>

# Check container for available shells and package managers
kubectl exec -n <app-namespace> <pod-name> -- which sh bash ash zsh 2>/dev/null
kubectl exec -n <app-namespace> <pod-name> -- which curl wget apt apt-get yum dnf pip python 2>/dev/null
```

### Detection / Testing
```bash
# Test Spring Boot Actuator exposure
curl -s https://<app-url>/actuator | jq '._links | keys'
# Dangerous if: heapdump, env, beans, mappings, logfile, shutdown are listed

# Test if /actuator/env leaks secrets (CRITICAL — check carefully)
curl -s https://<app-url>/actuator/env | jq '.propertySources[].properties | to_entries[] | select(.key | test("password|secret|key|token"; "i")) | {key: .key, value: "REDACTED"}'

# Test Django DEBUG mode (look for detailed stack trace or settings dump)
curl -s "https://<app-url>/trigger-404-test-path-xyz" | grep -iE "(debug|traceback|settings|django)"

# Test for exposed phpMyAdmin or database admin interface
curl -s -o /dev/null -w "%{http_code}" https://<app-url>/phpmyadmin
curl -s -o /dev/null -w "%{http_code}" https://<app-url>/pma
curl -s -o /dev/null -w "%{http_code}" https://<app-url>/dbadmin

# Check if /metrics is unauthenticated (Prometheus scrape endpoint)
curl -s https://<app-url>/metrics | head -20

# Test TRACE method for XST
curl -s -X TRACE https://<app-url>/ -H "X-Custom-Header: test-xst-probe" | grep "X-Custom-Header"
# Dangerous if: the response body reflects the X-Custom-Header back

# Check for verbose error pages (should return generic 500, not stack traces)
curl -s "https://<app-url>/api/v1/users?id='" | grep -iE "(exception|traceback|at com\.|at org\.|line [0-9])"

# Check for unnecessary binaries in containers
kubectl get pods -n <app-namespace> -o jsonpath='{.items[*].metadata.name}' | tr ' ' '\n' | while read POD; do
  echo "=== ${POD} ==="
  kubectl exec -n <app-namespace> "${POD}" -- sh -c "which curl wget nc netcat nmap 2>/dev/null" 2>/dev/null || echo "exec failed or no shell"
done
```

### Remediation
```bash
# --- Spring Boot: restrict Actuator endpoints in application.properties ---
cat <<'EOF'
# Expose only health and info in production
management.endpoints.web.exposure.include=health,info
management.endpoint.health.show-details=never
management.server.port=8081

# Disable dev tools
spring.devtools.restart.enabled=false
spring.devtools.livereload.enabled=false
EOF

# --- Django: ensure DEBUG=False in production settings ---
# In settings/production.py:
cat <<'EOF'
DEBUG = False
ALLOWED_HOSTS = ['<app-url>']
# Do not expose /admin/ unless explicitly needed
# If needed, move to a non-default URL:
# from django.urls import path
# urlpatterns = [path('secure-admin-<random>/', admin.site.urls)]
EOF

# --- Nginx: block debug and admin endpoints at reverse proxy ---
cat <<'EOF'
# Add to nginx.conf server block
location ~* ^/(actuator|debug|admin|phpmyadmin|pma|dbadmin|__debug__|_debug|api-docs|swagger-ui) {
    return 403;
}

# Block dangerous HTTP methods using limit_except (safer than `if` directive)
# The `if` directive in Nginx has undefined behavior in proxy contexts — use limit_except instead
# See: https://www.nginx.com/resources/wiki/start/topics/depth/ifisevil/ ("if is evil")
location / {
    limit_except GET POST HEAD OPTIONS {
        deny all;
    }
}
EOF

# --- Kubernetes: restrict /metrics to cluster-internal only via NetworkPolicy ---
cat <<'EOF'
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: restrict-metrics-endpoint
  namespace: <app-namespace>
spec:
  podSelector:
    matchLabels:
      app: <app-label>
  ingress:
  - ports:
    - port: 9090
      protocol: TCP
    from:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: monitoring
EOF

# Apply the NetworkPolicy
kubectl apply -f /tmp/restrict-metrics-networkpolicy.yaml
```

### Validation
```bash
# Confirm debug endpoints return 403 or 404 (not 200)
for ENDPOINT in /actuator/env /actuator/heapdump /debug /admin/__debug__; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://<app-url>${ENDPOINT}")
  echo "${STATUS} ${ENDPOINT} — $([ "${STATUS}" = "403" ] || [ "${STATUS}" = "404" ] && echo PASS || echo FAIL)"
done
# Expected: 403 or 404 for all debug/admin endpoints

# Confirm TRACE method is rejected
TRACE_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X TRACE https://<app-url>/)
echo "TRACE: ${TRACE_STATUS} — $([ "${TRACE_STATUS}" = "405" ] && echo PASS || echo FAIL)"
# Expected: 405 Method Not Allowed

# Confirm no shells accessible in containers
kubectl exec -n <app-namespace> <pod-name> -- which bash 2>&1 | grep -q "no bash" && echo "PASS: bash not found" || echo "REVIEW: bash present in container"
# Expected: "PASS" or exec failure — no interactive shell available

# Confirm /metrics requires authentication or is network-restricted
METRICS_STATUS=$(curl -s -o /dev/null -w "%{http_code}" https://<app-url>/metrics)
echo "Metrics endpoint: ${METRICS_STATUS} — $([ "${METRICS_STATUS}" = "401" ] || [ "${METRICS_STATUS}" = "403" ] || [ "${METRICS_STATUS}" = "404" ] && echo PASS || echo REVIEW)"
# Expected: 401, 403, or 404 — not 200
```

### Evidence Capture
```bash
EVIDENCE_DIR="/tmp/jsa-evidence/CM-7"
mkdir -p "${EVIDENCE_DIR}"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)

# Capture endpoint probe results
{
  echo "=== CM-7 Endpoint Probe - ${TIMESTAMP} ==="
  for ENDPOINT in \
    /actuator /actuator/env /actuator/heapdump /debug /admin /metrics \
    /__debug__ /_debug /swagger-ui /api-docs /v2/api-docs /phpmyadmin; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://<app-url>${ENDPOINT}")
    echo "${STATUS} https://<app-url>${ENDPOINT}"
  done
} > "${EVIDENCE_DIR}/endpoint-probe-${TIMESTAMP}.txt"
echo "Captured: ${EVIDENCE_DIR}/endpoint-probe-${TIMESTAMP}.txt"

# Capture HTTP method test
{
  echo "=== HTTP Methods Test - ${TIMESTAMP} ==="
  for METHOD in GET POST PUT DELETE PATCH TRACE OPTIONS HEAD; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X "${METHOD}" "https://<app-url>/")
    echo "${METHOD}: ${STATUS}"
  done
} > "${EVIDENCE_DIR}/http-methods-${TIMESTAMP}.txt"
echo "Captured: ${EVIDENCE_DIR}/http-methods-${TIMESTAMP}.txt"

# Capture container binary inventory
kubectl get pods -n <app-namespace> -o jsonpath='{.items[*].metadata.name}' | tr ' ' '\n' | while read POD; do
  echo "=== ${POD} ===" >> "${EVIDENCE_DIR}/container-binaries-${TIMESTAMP}.txt"
  kubectl exec -n <app-namespace> "${POD}" -- sh -c \
    "which sh bash ash zsh curl wget nc nmap python pip apt apt-get yum 2>/dev/null || echo none-found" \
    >> "${EVIDENCE_DIR}/container-binaries-${TIMESTAMP}.txt" 2>/dev/null
done
echo "Captured: ${EVIDENCE_DIR}/container-binaries-${TIMESTAMP}.txt"

echo "Evidence bundle complete: ${EVIDENCE_DIR}/"
ls -lh "${EVIDENCE_DIR}/"
```
