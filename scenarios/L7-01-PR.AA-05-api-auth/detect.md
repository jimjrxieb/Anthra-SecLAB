# L7-01 PR.AA-05 — Detect: API Documentation Endpoint Exposure

**Role:** L1 Security Analyst
**CSF:** PROTECT / PR.AA-05
**CIS v8:** 3.3
**NIST 800-53:** AC-3

You have received an alert or tip that the Portfolio API may be exposing its
documentation endpoints without authentication. Follow these steps to confirm
the finding and gather evidence before escalating or remediating.

---

## Step 1 — Check Grafana for Unusual Endpoint Traffic

If the cluster has Prometheus and Grafana running, check for HTTP request counts
against documentation paths.

```bash
# Port-forward to Grafana
kubectl port-forward -n monitoring svc/prometheus-grafana 3000:80 &

# Open: http://localhost:3000
# Default credentials (if unchanged): admin / prom-operator
```

In Grafana, look for the "FastAPI / HTTP Requests" dashboard or run this PromQL
query directly in Explore:

```promql
sum by (handler) (
  increase(http_requests_total{namespace="anthra"}[1h])
)
```

**What you are looking for:** Request counts on `/docs`, `/redoc`, or `/openapi.json`.
Any traffic to these endpoints is suspicious — they serve no business function in
production. Even a single hit from an unexpected source should be treated as a
finding.

**If Grafana has no data:** The app may not have metrics instrumented. Move to Step 3.

---

## Step 2 — Check Falco Alerts

```bash
# Check Falco logs directly
kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=200 | grep -i "anthra\|api\|docs"

# Or check via the Falco sidekick UI if deployed
kubectl port-forward -n falco svc/falco-falcosidekick-ui 2802:2802 &
# Open: http://localhost:2802
```

**IMPORTANT — Known Detection Gap:**

Falco watches system calls. It fires when a process opens a file, spawns a shell,
or makes a suspicious network call at the kernel level. It does not watch HTTP
routes at the application layer.

An unauthenticated request to `/docs` is just a normal HTTP GET. The API process
handles it, the syscalls look identical to any other request. Falco will not fire.

This is not a Falco failure — it is a tool boundary. Falco is the right tool for
container runtime anomalies (file writes, privilege escalation, reverse shells).
Application-layer access control gaps require application-layer controls: code
changes, WAF rules, or API gateway policies.

**Document this gap** in your finding: "Runtime detection (Falco) does not cover
application-layer access control defaults. Detection depends on access log review
or manual configuration audit."

---

## Step 3 — Check the Endpoint Directly

Port-forward the API service and test each documentation endpoint.

```bash
# Start port-forward (runs in background)
kubectl port-forward -n anthra svc/portfolio-anthra-portfolio-app-api 8000:8000 &
PF_PID=$!

# Wait for the tunnel to open
sleep 2

# Test each documentation endpoint
for ENDPOINT in /docs /redoc /openapi.json /health; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:8000${ENDPOINT}")
  printf "%-20s  %s\n" "${ENDPOINT}" "${STATUS}"
done

# Stop the port-forward when done
kill ${PF_PID} 2>/dev/null || true
```

**Expected output (vulnerable state):**

```
/docs                 200
/redoc                200
/openapi.json         200
/health               200
```

**Expected output (remediated state):**

```
/docs                 404
/redoc                404
/openapi.json         404
/health               200
```

If `/docs` returns 200, the vulnerability is confirmed. Save the output.

You can also download the full schema to see what is exposed:

```bash
curl -s http://localhost:8000/openapi.json | python3 -m json.tool > /tmp/openapi-evidence.json
wc -l /tmp/openapi-evidence.json
head -80 /tmp/openapi-evidence.json
```

This file contains every API route, method, parameter, and response type.
It is the attacker's reconnaissance gift.

---

## Step 4 — Check FastAPI Source for Hardening

If you have access to the application source, check whether docs were explicitly
disabled in the FastAPI constructor.

```bash
# Find the main FastAPI app file
kubectl exec -n anthra \
  $(kubectl get pods -n anthra -l app.kubernetes.io/component=api \
    -o jsonpath='{.items[0].metadata.name}') \
  -- find / -name "main.py" -path "*/app/*" 2>/dev/null | head -5

# Read the app constructor
kubectl exec -n anthra \
  $(kubectl get pods -n anthra -l app.kubernetes.io/component=api \
    -o jsonpath='{.items[0].metadata.name}') \
  -- sh -c 'grep -n "FastAPI\|docs_url\|redoc_url\|openapi_url\|DISABLE_DOCS" /app/main.py 2>/dev/null || echo "Could not read main.py"'
```

**Hardened (correct):**
```python
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
```

**Vulnerable (default):**
```python
app = FastAPI()
# or
app = FastAPI(title="Portfolio API")
# No docs_url=None means /docs is live
```

---

## Evidence to Capture

Before moving to investigate.md, save the following:

```bash
EVIDENCE_DIR="/tmp/L7-01-evidence-$(date +%Y%m%d-%H%M%S)"
mkdir -p "${EVIDENCE_DIR}"

# HTTP status codes
for EP in /docs /redoc /openapi.json /health; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:8000${EP}" 2>/dev/null || echo "ERR")
  echo "${EP}: ${STATUS}" >> "${EVIDENCE_DIR}/endpoint-status.txt"
done

# OpenAPI schema (full exposure evidence)
curl -s http://localhost:8000/openapi.json > "${EVIDENCE_DIR}/openapi.json" 2>/dev/null || true

# Pod and deployment info
kubectl get deployment portfolio-anthra-portfolio-app-api -n anthra -o yaml \
  > "${EVIDENCE_DIR}/deployment.yaml" 2>/dev/null || true

echo "Evidence saved to: ${EVIDENCE_DIR}"
ls -la "${EVIDENCE_DIR}"
```

---

## Decision Point

| Condition                                      | Action                        |
|------------------------------------------------|-------------------------------|
| `/docs` returns 200, ClusterIP only            | D-rank — proceed to investigate.md, fix with fix.sh |
| `/docs` returns 200, exposed via ingress       | Escalate to senior engineer before proceeding |
| `/docs` returns 404                            | Already remediated — document and close |
| Cannot reach API at all                        | Separate issue — check pod status first |

**NEXT STEP:** Open `investigate.md`
