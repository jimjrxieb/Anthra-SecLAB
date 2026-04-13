# L7-01 PR.AA-05 — Investigate: API Documentation Endpoint Exposure

**Role:** L1 Security Analyst
**CSF:** PROTECT / PR.AA-05
**CIS v8:** 3.3
**NIST 800-53:** AC-3

You have confirmed `/docs` returns HTTP 200 without authentication. Now determine
the actual exposure scope, classify the finding, and decide whether to proceed
with the deterministic fix or escalate.

---

## Step 1 — Determine Exposure Scope

The risk level of this finding depends entirely on who can reach port 8000.

```bash
NAMESPACE="anthra"
SVC="portfolio-anthra-portfolio-app-api"

# Check service type (ClusterIP = internal only, NodePort/LoadBalancer = wider exposure)
kubectl get svc "${SVC}" -n "${NAMESPACE}" \
  -o jsonpath='Type: {.spec.type}{"\n"}Port: {.spec.ports[0].port}{"\n"}ClusterIP: {.spec.clusterIP}{"\n"}'

# Check if any ingress routes to the API
kubectl get ingress -n "${NAMESPACE}" -o wide 2>/dev/null || echo "No ingress resources found"

# Check if any Kyverno or network policies restrict access to port 8000
kubectl get networkpolicy -n "${NAMESPACE}" -o wide 2>/dev/null || echo "No NetworkPolicies found"
```

**Interpret the results:**

| Service Type  | Exposure                                                          |
|---------------|-------------------------------------------------------------------|
| ClusterIP     | Reachable only from within the cluster — lower risk              |
| NodePort      | Reachable from the node network — medium risk                    |
| LoadBalancer  | Potentially internet-facing — HIGH risk, escalate immediately    |

If the service is ClusterIP with no ingress routing to port 8000, the exposure is
limited to workloads already running inside the cluster. This is still a finding —
a compromised adjacent pod can reach it — but it does not require emergency response.

**If internet-facing:** Stop. Do not run fix.sh yourself. Escalate to a senior
engineer immediately with your evidence package. This becomes a B-rank finding.

---

## Step 2 — Examine What Is Exposed

Download the OpenAPI schema and inventory the routes.

```bash
# Start port-forward if not already running
kubectl port-forward -n anthra svc/portfolio-anthra-portfolio-app-api 8000:8000 &
PF_PID=$!
sleep 2

# Download the schema
curl -s http://localhost:8000/openapi.json -o /tmp/openapi.json

# Count total routes
echo "Total routes in schema:"
python3 -c "
import json
with open('/tmp/openapi.json') as f:
    schema = json.load(f)
paths = schema.get('paths', {})
print(f'  {len(paths)} paths')
for path, methods in paths.items():
    for method in methods:
        if method in ['get','post','put','delete','patch']:
            print(f'  {method.upper():8} {path}')
"

# Check for any sensitive-looking routes
echo ""
echo "Potentially sensitive routes:"
python3 -c "
import json
with open('/tmp/openapi.json') as f:
    schema = json.load(f)
sensitive = ['admin','auth','token','secret','key','password','internal','debug']
for path in schema.get('paths', {}):
    for term in sensitive:
        if term in path.lower():
            print(f'  REVIEW: {path}')
            break
" || echo "  No obviously sensitive routes found"

kill ${PF_PID} 2>/dev/null || true
```

Record the total route count and any sensitive endpoints in your evidence file.

---

## Step 3 — Check Whether Anyone Has Already Hit /docs

Look at access logs for prior requests to documentation endpoints.

```bash
API_POD=$(kubectl get pods -n anthra \
  -l app.kubernetes.io/component=api \
  --field-selector=status.phase=Running \
  -o jsonpath='{.items[0].metadata.name}')

# Check container logs for documentation endpoint hits
echo "--- Access log entries for /docs, /redoc, /openapi.json ---"
kubectl logs -n anthra "${API_POD}" --tail=500 2>/dev/null | \
  grep -E '/(docs|redoc|openapi)' || echo "No documentation endpoint hits in recent logs"

# Check Fluent Bit if shipping logs to a central store
# If using Loki:
# logcli query '{namespace="anthra"} |= "/docs"' --limit=20 2>/dev/null || true
```

**Why this matters:** If another workload or an external probe has already
hit `/docs` or downloaded `/openapi.json`, the schema has already been exposed.
Document this in your report. It does not change the remediation, but it affects
the incident timeline and may require additional review of what was accessed.

---

## Step 4 — Classify the Finding

Fill in this classification block for your report:

```
Finding: Unauthenticated API documentation endpoint exposure
Asset: portfolio-anthra-portfolio-app-api (namespace: anthra)
Endpoints affected: /docs, /redoc, /openapi.json
HTTP status (before fix): 200 (all three)
Authentication required: No
CSF: PR.AA-05 — Access permissions managed
CIS v8: 3.3 — Configure Data Access Control Lists
NIST 800-53: AC-3 — Access Enforcement
Severity: Medium
Rank: D (deterministic fix, auto-remediate with logging)
Exposure scope: ClusterIP — internal cluster only [verify this]
Prior exploitation evidence: [Yes/No — check Step 3]
```

**Rank determination:**

- D-rank applies when: fix is deterministic (one kubectl set env command), no
  data loss risk, no service disruption, reversible, and the service is not
  internet-facing.
- If internet-facing or evidence of prior exploitation: bump to C-rank.
  Log the finding, propose the fix, wait for approval before running fix.sh.

---

## Step 5 — Decide

| Condition                              | Rank   | Action                                       |
|----------------------------------------|--------|----------------------------------------------|
| ClusterIP, no prior hits               | D      | Proceed to fix.sh                            |
| ClusterIP, prior hits in logs          | D/C    | Document hits, proceed to fix.sh, notify team |
| NodePort or LoadBalancer               | C      | Escalate before fixing                       |
| Internet-facing (ingress to port 8000) | B      | Stop, escalate immediately                   |

For this lab scenario (ClusterIP, no prior exploitation): proceed.

---

## Pre-Fix Checklist

Before running fix.sh, confirm:

- [ ] Baseline captured (baseline.sh ran and output saved)
- [ ] Exposure scope determined (ClusterIP confirmed)
- [ ] Prior hits checked (logs reviewed)
- [ ] Finding classified (rank, severity, CSF/CIS/NIST documented)
- [ ] Evidence package saved to /tmp/L7-01-evidence-*/

**NEXT STEP:** Run `fix.sh`
