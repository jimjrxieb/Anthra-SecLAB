# L7-02 PR.PS-01 — Detect: Missing Security Headers

**Role:** L1 Security Analyst
**CSF:** PROTECT / PR.PS-01
**CIS v8:** 16.12
**NIST 800-53:** SI-10, SC-8

You have received a ticket or tip that the Portfolio UI may be missing HTTP
security headers. Possibly from a periodic config audit, a developer noticing
something changed, or an automated scanner alert. Your job is to confirm the
finding and gather evidence before proceeding to investigate.md.

---

## Step 1 — Port-Forward and Check Response Headers

The UI service is ClusterIP — not directly accessible from your machine. Use
kubectl port-forward to create a tunnel, then curl the response headers.

```bash
# Start port-forward in the background
kubectl port-forward -n anthra svc/portfolio-anthra-portfolio-app-ui 8080:80 &
PF_PID=$!

# Wait a moment for the tunnel to open
sleep 2

# Capture all response headers
curl -sI http://localhost:8080/

# Stop the port-forward when done
kill ${PF_PID} 2>/dev/null || true
```

**What a hardened response looks like:**

```
HTTP/1.1 200 OK
Server: nginx/1.27.x
Content-Type: text/html
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' ...
X-Frame-Options: SAMEORIGIN
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), microphone=(), camera=()
Strict-Transport-Security: max-age=31536000; includeSubDomains
```

**What a stripped (vulnerable) response looks like:**

```
HTTP/1.1 200 OK
Server: nginx/1.27.x
Content-Type: text/html
Content-Length: 1234
```

If you see the stripped version, the vulnerability is confirmed. The page loads
but the browser receives no security policy.

---

## Step 2 — Check Each Header Individually

Check all seven headers in one command to see exactly which are missing:

```bash
kubectl port-forward -n anthra svc/portfolio-anthra-portfolio-app-ui 8080:80 &
PF_PID=$!
sleep 2

for HEADER in \
  "content-security-policy" \
  "x-frame-options" \
  "x-content-type-options" \
  "x-xss-protection" \
  "referrer-policy" \
  "permissions-policy" \
  "strict-transport-security"; do
  VALUE=$(curl -sI http://localhost:8080/ 2>/dev/null | grep -i "^${HEADER}:" | tr -d '\r' || true)
  if [[ -n "${VALUE}" ]]; then
    printf "  PRESENT  %s\n" "${VALUE}"
  else
    printf "  MISSING  %s\n" "${HEADER}"
  fi
done

kill ${PF_PID} 2>/dev/null || true
```

Any line showing MISSING is a confirmed gap. Document each one.

---

## Step 3 — Check from Inside the Pod (Bypass Any Edge Proxy)

If your cluster sits behind Cloudflare, a WAF, or an ingress controller that
injects headers, you may see headers from the edge — not from nginx itself.
Test from inside the pod to confirm the origin server behavior:

```bash
UI_POD=$(kubectl get pods -n anthra -l app.kubernetes.io/component=ui \
  -o jsonpath='{.items[0].metadata.name}')

kubectl exec -n anthra "${UI_POD}" -- \
  curl -sI http://localhost:8080/ \
  | grep -iE "(content-security|x-frame|x-content-type|x-xss|strict-transport|referrer-policy|permissions-policy)"
```

**IMPORTANT — Edge vs Origin:**

If Cloudflare or another CDN is in front of this service, it may add some
headers (e.g., Strict-Transport-Security) at the edge. This does not mean the
origin server is configured correctly. An auditor testing CIS 16.12 expects
headers to be set by the application, not injected by infrastructure you do
not control. Always test at the origin pod.

For this scenario, there is no ingress — testing from inside the pod is
authoritative.

---

## Step 4 — Check Grafana for Header-Related Metrics

Security headers are a configuration property, not a runtime event. Grafana
dashboards will not alert you directly to their absence.

```bash
kubectl port-forward -n monitoring svc/prometheus-grafana 3000:80 &
# Open: http://localhost:3000
```

What Grafana CAN tell you:
- Whether the UI is serving requests at all (nginx request rate)
- Whether error rates have changed (a config reload failure could cause 500s)
- Whether the pod has restarted recently (possible indicator of a forced config change)

What Grafana CANNOT tell you:
- Whether specific response headers are present or absent
- Whether the nginx config was overwritten

**Detection gap to document:** "Response header configuration is not monitored
by Prometheus or Grafana. Missing security headers require manual config audit
or external scanner verification."

---

## Step 5 — What Each Missing Header Enables

Understanding the attack surface is part of your analysis. Document this in
your finding.

| Missing Header              | Attack Enabled                                                        |
|-----------------------------|-----------------------------------------------------------------------|
| Content-Security-Policy     | Cross-site scripting (XSS) — attacker can inject and run scripts     |
| X-Frame-Options             | Clickjacking — attacker embeds the page in an iframe on their site   |
| X-Content-Type-Options      | MIME sniffing — browser may execute a file as a different type       |
| X-XSS-Protection            | Legacy XSS filter bypass in older browsers (defense in depth)        |
| Referrer-Policy             | Data leakage — full URL including tokens sent in Referer header      |
| Permissions-Policy          | Feature abuse — unauthorized camera, mic, geolocation from the page |
| Strict-Transport-Security   | HTTP downgrade — attacker on local network strips TLS                |

For this scenario, the most impactful missing headers are:
1. **Content-Security-Policy** — XSS is the highest-frequency web attack
2. **X-Frame-Options** — Clickjacking targets login pages and form submissions
3. **Strict-Transport-Security** — Without HSTS, HTTPS can be silently downgraded

---

## Step 6 — Check the Actual nginx Config

Confirm what is in the config file right now:

```bash
UI_POD=$(kubectl get pods -n anthra -l app.kubernetes.io/component=ui \
  -o jsonpath='{.items[0].metadata.name}')

kubectl exec -n anthra "${UI_POD}" -- cat /etc/nginx/conf.d/default.conf
```

A hardened config will have an `add_header` block with all seven headers.
A stripped config will have only the `listen`, `root`, and `location` blocks.

---

## Evidence to Capture

```bash
EVIDENCE_DIR="/tmp/L7-02-evidence-$(date +%Y%m%d-%H%M%S)"
mkdir -p "${EVIDENCE_DIR}"

UI_POD=$(kubectl get pods -n anthra -l app.kubernetes.io/component=ui \
  -o jsonpath='{.items[0].metadata.name}')

# Full response headers (origin)
kubectl exec -n anthra "${UI_POD}" -- curl -sI http://localhost:8080/ \
  > "${EVIDENCE_DIR}/response-headers.txt" 2>&1

# nginx config (what is actually configured)
kubectl exec -n anthra "${UI_POD}" -- cat /etc/nginx/conf.d/default.conf \
  > "${EVIDENCE_DIR}/nginx-default.conf" 2>&1

# Deployment spec (for change history and security context)
kubectl get deployment portfolio-anthra-portfolio-app-ui -n anthra -o yaml \
  > "${EVIDENCE_DIR}/deployment.yaml" 2>/dev/null || true

# Pod events (recent changes)
kubectl describe pod "${UI_POD}" -n anthra \
  > "${EVIDENCE_DIR}/pod-describe.txt" 2>/dev/null || true

echo "Evidence saved to: ${EVIDENCE_DIR}"
ls -la "${EVIDENCE_DIR}"
```

---

## Decision Point

| Condition                                      | Action                                       |
|------------------------------------------------|----------------------------------------------|
| All 7 headers missing                          | D-rank — proceed to investigate.md, fix with fix.sh |
| Some headers missing, some present             | D-rank — same path, note partial state       |
| Headers present from edge, missing at origin   | D-rank — fix origin config, document edge gap |
| Headers fully present                          | Already remediated — document and close      |
| UI returning 500/502                           | Separate issue — check pod status first      |

**NEXT STEP:** Open `investigate.md`
