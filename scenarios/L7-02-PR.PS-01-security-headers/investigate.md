# L7-02 PR.PS-01 — Investigate: Missing Security Headers

**Role:** L1 Security Analyst
**CSF:** PROTECT / PR.PS-01
**CIS v8:** 16.12
**NIST 800-53:** SI-10, SC-8

You have confirmed the headers are missing. Now you need to understand scope,
determine when it happened, decide who is responsible for the fix, and assign
a rank. Do this before touching anything.

---

## Step 1 — Which Headers Are Missing?

Document each header's status individually. This determines severity and informs
the remediation priority. Run this checklist and write down the result.

```bash
UI_POD=$(kubectl get pods -n anthra -l app.kubernetes.io/component=ui \
  -o jsonpath='{.items[0].metadata.name}')

RESPONSE=$(kubectl exec -n anthra "${UI_POD}" -- curl -sI http://localhost:8080/ 2>/dev/null)

declare -A HEADERS
HEADERS["Content-Security-Policy"]="content-security-policy"
HEADERS["X-Frame-Options"]="x-frame-options"
HEADERS["X-Content-Type-Options"]="x-content-type-options"
HEADERS["X-XSS-Protection"]="x-xss-protection"
HEADERS["Referrer-Policy"]="referrer-policy"
HEADERS["Permissions-Policy"]="permissions-policy"
HEADERS["Strict-Transport-Security"]="strict-transport-security"

for NAME in "${!HEADERS[@]}"; do
  PATTERN="${HEADERS[$NAME]}"
  VALUE=$(echo "${RESPONSE}" | grep -i "^${PATTERN}:" | tr -d '\r' || true)
  if [[ -n "${VALUE}" ]]; then
    echo "  PRESENT  ${NAME}: ${VALUE}"
  else
    echo "  MISSING  ${NAME}"
  fi
done
```

**Risk by missing header (for your notes):**

- Content-Security-Policy MISSING → HIGH — XSS attacks can execute
- X-Frame-Options MISSING → MEDIUM — clickjacking on login flows
- Strict-Transport-Security MISSING → MEDIUM — TLS downgrade possible on LAN
- X-Content-Type-Options MISSING → LOW-MEDIUM — MIME sniffing on file downloads
- Referrer-Policy MISSING → LOW — data leakage in URL parameters
- Permissions-Policy MISSING → LOW — feature access policy absent
- X-XSS-Protection MISSING → LOW — legacy browsers only, defense in depth

---

## Step 2 — Is This Internet-Facing?

The exposure level determines urgency. A missing header behind a VPN is a
finding. The same missing header on a public login page is an incident.

```bash
# Check for any ingress or gateway pointing to the UI service
kubectl get ingress -n anthra 2>/dev/null || echo "No ingress resources in anthra"
kubectl get httproute,virtualservice,gateway -n anthra 2>/dev/null \
  || echo "No gateway API resources in anthra"

# Check if the service has an external IP (LoadBalancer type would mean public)
kubectl get svc portfolio-anthra-portfolio-app-ui -n anthra \
  -o jsonpath='Type: {.spec.type}{"\n"}ClusterIP: {.spec.clusterIP}{"\n"}'
```

**Expected output for this scenario:**

```
Type: ClusterIP
ClusterIP: 10.x.x.x
```

ClusterIP means the UI is not directly routable from the internet. To access it,
an attacker would need to already be inside the cluster. That reduces the
immediate blast radius but does not eliminate the finding — this is a security
control gap, not just a risk-conditional gap.

**If Cloudflare or a CDN is in front:**

Some headers (notably HSTS and X-Frame-Options) may be added by Cloudflare at
the edge. Do not let this close the finding. The origin server must set these
headers independently. Relying on edge injection means:
- Local-network requests bypass the CDN and get unprotected responses
- CDN misconfiguration or bypass removes all protection at once
- The control is not owned at the layer it was designed for

Document the edge behavior but keep the origin fix as required.

---

## Step 3 — When Did the Headers Disappear?

Determine whether this is a fresh change or a long-standing gap.

```bash
# Check pod restart time (if pod was recently replaced, something changed)
kubectl get pod -n anthra \
  -l app.kubernetes.io/component=ui \
  -o jsonpath='{range .items[*]}{.metadata.name}  started={.status.startTime}{"\n"}{end}'

# Check deployment rollout history (shows revisions)
kubectl rollout history deployment/portfolio-anthra-portfolio-app-ui -n anthra

# Show the most recent rollout event
kubectl describe deployment portfolio-anthra-portfolio-app-ui -n anthra \
  | grep -A 5 "Events:"

# Check when the current replicaset was created
kubectl get replicaset -n anthra \
  -l app.kubernetes.io/component=ui \
  --sort-by=.metadata.creationTimestamp \
  -o jsonpath='{range .items[*]}{.metadata.name}  created={.metadata.creationTimestamp}{"\n"}{end}'
```

**What the timeline tells you:**

- Pod started recently, rollout history shows recent revision → config was
  changed as part of a deployment, possibly intentional, possibly not
- Pod has been running for days and rollout history is old → the stripped config
  was either baked into the image from the start, or was injected mid-runtime
  (which is more concerning — suggests unauthorized exec access to the pod)

---

## Step 4 — Confirm the Config Was Overwritten (Not a Build Gap)

The original Dockerfile bakes in all seven headers. If the config in the running
pod does not match what the Dockerfile produces, something changed it after
deployment.

```bash
UI_POD=$(kubectl get pods -n anthra -l app.kubernetes.io/component=ui \
  -o jsonpath='{.items[0].metadata.name}')

# Show the current config
echo "--- Current /etc/nginx/conf.d/default.conf ---"
kubectl exec -n anthra "${UI_POD}" -- cat /etc/nginx/conf.d/default.conf

# Count the add_header lines (hardened config has 7, stripped has 0)
HEADER_COUNT=$(kubectl exec -n anthra "${UI_POD}" -- \
  grep -c "add_header" /etc/nginx/conf.d/default.conf 2>/dev/null || echo 0)
echo ""
echo "add_header lines in current config: ${HEADER_COUNT}"
echo "Expected (hardened): 7"
echo "Expected (stripped): 0"
```

If `HEADER_COUNT` is 0 but the image was built from the Dockerfile (which adds 7
headers), the config was overwritten after the container started. This is either
from a previous training break scenario (expected) or an unauthorized exec
(requires investigation).

---

## Step 5 — Classification and Rank Decision

Fill in this table before proceeding to fix.sh.

| Field            | Your Assessment                                                       |
|------------------|-----------------------------------------------------------------------|
| CSF Control      | PR.PS-01 — Configuration management                                  |
| CIS Control      | 16.12 — Code-level security checks                                   |
| NIST Control     | SI-10, SC-8                                                           |
| Headers Missing  | [fill in: which of the 7 are missing]                                |
| Internet-Facing? | [Yes / No / Behind Cloudflare]                                       |
| Root Cause       | [Config overwrite / Image build gap / Edge-only headers]             |
| Severity         | Medium                                                                |
| Rank             | D — Deterministic. The fix is known, reversible, and scripted.       |
| Confidence       | High — the correct headers are defined in the Dockerfile source.     |

**Why D-rank:**

The fix is deterministic. The correct config is in the Dockerfile. There is no
ambiguity about what the correct state looks like. There is no blast radius for
the fix — restoring an nginx config does not change application behavior, only
response headers. An E-rank finding is auto-fixed with no logging. A D-rank
finding is auto-fixed with logging and a human-reviewable record. This is D-rank:
the pattern is clear, the fix is scripted, a human should see it happened.

**When to escalate:**

Escalate to a senior engineer (B-rank) if:
- Evidence suggests the config was overwritten by unauthorized pod exec
- The stripped config is present in the container image itself (build pipeline
  integrity issue, not a runtime issue)
- The UI is directly internet-facing with an active user base

---

## Step 6 — Proceed

You have confirmed the finding, scoped the exposure, checked the timeline, and
assigned D-rank. You are authorized to proceed with the fix.

```
D-rank authority: Fix it. Log it. A human reviews the log.
No approval required for D-rank.
```

**NEXT STEP:** Run `fix.sh` to restore the hardened nginx config, then run
`verify.sh` to confirm, then fill in `report-template.md`.
