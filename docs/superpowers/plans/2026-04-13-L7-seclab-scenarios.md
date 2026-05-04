# Layer 7 SecLAB Scenario Framework — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build 10 Layer 7 (Application) break/detect/fix scenarios for a Day 1 cybersecurity analyst training lab, backed by CSF 2.0, with Splunk/Grafana detection and guided L1 investigation procedures.

**Architecture:** Each scenario follows a 7-step lifecycle: Baseline → Break → Detect (SIEM) → Investigate (L1 steps) → Remediate (CSF/CIS-guided) → Verify → Report. A shared `00-DAY1-BASELINE` establishes the "normal" state before any scenario runs. All scenarios target the Portfolio app in the `anthra` namespace on the `k3d-seclab` cluster.

**Tech Stack:** k3d (k3s v1.31), Falco + Falcosidekick, Kyverno, Fluent Bit → Loki, Prometheus + Grafana, kubescape, kube-bench, trivy, semgrep, gitleaks. Portfolio: FastAPI (api), React/Vite (ui), ChromaDB (chroma).

---

## Environment State (verified 2026-04-13)

| Component | Status | Location |
|-----------|--------|----------|
| k3d-seclab cluster | 3 nodes running | k3d-seclab-server-0, agent-0, agent-1 |
| Portfolio app | 3/3 pods Running | `anthra` namespace (api, ui, chroma) |
| Falco | 3 DaemonSet pods + 2 Sidekick | `falco` namespace |
| Kyverno | 3 controllers | `kyverno` namespace |
| Fluent Bit | 3 DaemonSet pods | `logging` namespace |
| Prometheus + Grafana | Full stack | `monitoring` namespace |
| kubescape | installed | /home/jimmie/bin/kubescape |
| trivy | installed | /home/jimmie/bin/trivy |
| kube-bench | installed | /usr/local/bin/kube-bench |

## File Structure

```
scenarios/
├── 00-DAY1-BASELINE/
│   ├── README.md                    ← "Your first day" — what to do, what to check
│   ├── checklist.md                 ← Guided checklist (L1 analyst perspective)
│   ├── run-baseline.sh              ← Automated baseline capture (cluster + app state)
│   └── baseline-report-template.md  ← Fill-in template for baseline findings
│
├── L7-01-PR.AA-05-api-auth/        ← Scenario 1: Admin endpoint exposed
│   ├── README.md                    ← Scenario overview (CSF, rationale, what breaks)
│   ├── baseline.sh                  ← Capture pre-break state
│   ├── break.sh                     ← Inject the vulnerability
│   ├── detect.md                    ← L1: what fires in Grafana/Falco? what to look for
│   ├── investigate.md               ← L1: step-by-step investigation procedure
│   ├── fix.sh                       ← CSF/CIS-guided remediation script
│   ├── remediate.md                 ← L1: why this fix, which benchmark says so
│   ├── verify.sh                    ← Prove the fix worked
│   └── report-template.md           ← POA&M entry + evidence + manager summary
│
├── L7-02-PR.PS-01-security-headers/ ← Scenario 2: Missing security headers
│   └── (same 9-file structure)
│
├── L7-03-PR.PS-01-cis-benchmark/    ← Scenario 3: CIS failures unremediated
│   └── (same 9-file structure)
│
├── L7-04-DE.CM-03-edr-disabled/     ← Scenario 4: Falco/EDR agent down
│   └── (same 9-file structure)
│
├── L7-05-DE.AE-02-alert-fatigue/    ← Scenario 5: No custom alert rules
│   └── (same 9-file structure)
│
├── L7-06-DE.AE-06-log-retention/    ← Scenario 6: Logs expiring too fast
│   └── (same 9-file structure)
│
├── L7-07-DE.AE-07-missing-logs/     ← Scenario 7: Log source stopped
│   └── (same 9-file structure)
│
├── L7-08-ID.RA-01-unpatched-cve/    ← Scenario 8: Vulnerable container image
│   └── (same 9-file structure)
│
├── L7-09-RS.MI-01-no-response/      ← Scenario 9: Detection without response
│   └── (same 9-file structure)
│
└── L7-10-RS.MI-02-fim-disabled/     ← Scenario 10: FIM not covering critical paths
    └── (same 9-file structure)
```

**Existing scenarios to relocate** (AC-6, CM-7, SC-7) will be refactored to the new structure in a future task. This plan covers only L7 + Day 1 baseline.

---

## Task 0: Day 1 Baseline

**Files:**
- Create: `scenarios/00-DAY1-BASELINE/README.md`
- Create: `scenarios/00-DAY1-BASELINE/checklist.md`
- Create: `scenarios/00-DAY1-BASELINE/run-baseline.sh`
- Create: `scenarios/00-DAY1-BASELINE/baseline-report-template.md`

### README.md

- [ ] **Step 1: Write the Day 1 README**

This is the first thing a new analyst reads. It sets the persona, the environment, and the mindset.

```markdown
# Day 1 — Your First Day as a Security Analyst

You just started at Anthra Corp. You're a Level 1 cybersecurity analyst (SOC/GRC/SRE).

## Your Environment

- **Cluster:** k3d-seclab (3-node k3s Kubernetes cluster)
- **Application:** Portfolio — AI/ML RAG chatbot (FastAPI + React + ChromaDB)
- **Namespace:** `anthra`
- **Security Stack:** Falco (runtime detection), Kyverno (admission control), Fluent Bit (logging), Prometheus + Grafana (monitoring)

## What You Do Today

Before anything breaks, you need to know what "normal" looks like. A senior engineer
cannot tell you what's wrong if you don't know what's right.

### Step 1: Run the baseline
```bash
bash scenarios/00-DAY1-BASELINE/run-baseline.sh
```

### Step 2: Walk the checklist
Open `checklist.md` and go through it item by item. For each check:
- Run the command
- Record what you see
- Note anything that looks wrong

### Step 3: Fill in your baseline report
Open `baseline-report-template.md` and fill in your findings.
This is your "before" snapshot. Every scenario that follows will break
something — you'll compare against this to detect the change.

## Framework Reference

This lab uses NIST Cybersecurity Framework 2.0:
- **IDENTIFY** — Know what you have (asset inventory, vulnerability scans)
- **PROTECT** — Harden it (access control, encryption, configs)
- **DETECT** — Watch for attacks (SIEM, IDS, monitoring)
- **RESPOND** — Contain and investigate (incident response)
- **RECOVER** — Restore and improve (evidence, lessons learned)

Every scenario maps to a CSF subcategory. The fix always references a CIS Controls v8
safeguard. You'll learn both frameworks by doing, not by reading.
```

- [ ] **Step 2: Commit**

```bash
git add scenarios/00-DAY1-BASELINE/README.md
git commit -m "feat(seclab): add Day 1 analyst onboarding README"
```

### checklist.md

- [ ] **Step 3: Write the Day 1 checklist**

This is the analyst's guided walkthrough. Every item has: what to run, what to expect, what's wrong if it doesn't match.

```markdown
# Day 1 Baseline Checklist

Run each check. Record the result. Flag anything unexpected.

## 1. Cluster Health (ID.AM-01)

### 1.1 Nodes
```bash
kubectl get nodes -o wide
```
**Expected:** 3 nodes, all `Ready`. If any node is `NotReady`, escalate.

### 1.2 Namespaces
```bash
kubectl get ns
```
**Expected:** `anthra`, `falco`, `kyverno`, `logging`, `monitoring`, plus system namespaces.
**Flag if:** Unknown namespaces exist (could be unauthorized workloads).

### 1.3 Pods in target namespace
```bash
kubectl get pods -n anthra
```
**Expected:** 3 pods (api, ui, chroma), all `Running`, all `1/1`.
**Flag if:** Pods in `CrashLoopBackOff`, `ImagePullBackOff`, or `0/1` ready.

---

## 2. Security Stack (DE.CM-03)

### 2.1 Falco running
```bash
kubectl get pods -n falco
```
**Expected:** DaemonSet pods on every node (3 pods), all `Running`.
**Flag if:** Any pod not running — runtime detection is blind on that node.

### 2.2 Kyverno running
```bash
kubectl get pods -n kyverno
```
**Expected:** 3 controller pods, all `Running`.
**Flag if:** Admission controller down — policy enforcement is disabled.

### 2.3 Kyverno policies enforcing
```bash
kubectl get clusterpolicies -o jsonpath='{range .items[*]}{.metadata.name}: {.spec.validationFailureAction}{"\n"}{end}'
```
**Expected:** All policies show `Enforce` or `Audit`. Note which are which.
**Flag if:** No policies exist — cluster has no admission guardrails.

### 2.4 Fluent Bit running
```bash
kubectl get pods -n logging
```
**Expected:** DaemonSet on every node (3 pods).
**Flag if:** Missing pods — logs from that node are not being collected.

### 2.5 Prometheus + Grafana running
```bash
kubectl get pods -n monitoring
```
**Expected:** Prometheus, Grafana, Alertmanager, node-exporters all running.
**Flag if:** Alertmanager down — alerts won't fire.

---

## 3. Application Security (PR.PS-01)

### 3.1 Security context on Portfolio pods
```bash
kubectl get pods -n anthra -o jsonpath='{range .items[*]}{.metadata.name}: runAsNonRoot={.spec.securityContext.runAsNonRoot}, readOnlyRootFS={.spec.containers[0].securityContext.readOnlyRootFilesystem}{"\n"}{end}'
```
**Expected:** `runAsNonRoot=true`, `readOnlyRootFilesystem=true` on all pods.
**Flag if:** Any pod running as root or with writable filesystem.

### 3.2 NetworkPolicies in anthra
```bash
kubectl get networkpolicy -n anthra
```
**Expected:** At least 1 NetworkPolicy (default-deny or app-specific).
**Flag if:** Zero policies — all pod-to-pod traffic is unrestricted.

### 3.3 Service types
```bash
kubectl get svc -n anthra -o jsonpath='{range .items[*]}{.metadata.name}: {.spec.type}{"\n"}{end}'
```
**Expected:** All `ClusterIP`. No `NodePort` or `LoadBalancer`.
**Flag if:** NodePort exposed — direct external access without ingress.

### 3.4 Service account tokens
```bash
kubectl get pods -n anthra -o jsonpath='{range .items[*]}{.metadata.name}: automount={.spec.automountServiceAccountToken}{"\n"}{end}'
```
**Expected:** `automount=false` on all app pods.
**Flag if:** `true` — pods have unnecessary K8s API access.

---

## 4. Vulnerability Posture (ID.RA-01)

### 4.1 Container image scan
```bash
trivy image portfolio-prod-api:latest --severity HIGH,CRITICAL --quiet 2>/dev/null | tail -5
trivy image portfolio-prod-ui:latest --severity HIGH,CRITICAL --quiet 2>/dev/null | tail -5
```
**Expected:** Note the count of HIGH/CRITICAL CVEs. This is your baseline.

### 4.2 CIS Kubernetes benchmark
```bash
kube-bench run --targets node 2>/dev/null | grep -E "^(\[PASS\]|\[FAIL\]|\[WARN\])" | sort | uniq -c | sort -rn
```
**Expected:** Mostly PASS. Record FAIL count — this is your CIS baseline.

### 4.3 Kubescape posture
```bash
kubescape scan --format pretty 2>/dev/null | tail -20
```
**Expected:** Note the compliance score. This is your Kubescape baseline.

---

## 5. RBAC (PR.AA-05)

### 5.1 ClusterRoleBindings to cluster-admin
```bash
kubectl get clusterrolebindings -o json | python3 -c "
import sys, json
data = json.load(sys.stdin)
for item in data.get('items', []):
    if item['roleRef']['name'] == 'cluster-admin':
        subjects = [f\"{s.get('namespace','')}/{s['name']}\" for s in item.get('subjects',[])]
        print(f\"  {item['metadata']['name']}: {', '.join(subjects)}\")
"
```
**Expected:** Only system bindings (kube-system SAs). No user or app SAs.
**Flag if:** Any non-system SA bound to cluster-admin.

### 5.2 Wildcard RBAC
```bash
kubectl get clusterroles -o json | python3 -c "
import sys, json
data = json.load(sys.stdin)
for item in data.get('items', []):
    for rule in item.get('rules', []):
        if '*' in rule.get('verbs', []) or '*' in rule.get('resources', []):
            print(f\"  {item['metadata']['name']}: verbs={rule['verbs']} resources={rule['resources']}\")
" 2>/dev/null | head -20
```
**Expected:** Only system roles (system:controller:*, admin, edit, cluster-admin).
**Flag if:** Custom roles with wildcards.

---

## Summary

After completing this checklist, you should know:
1. How many nodes, pods, and services are running
2. Whether Falco, Kyverno, Fluent Bit, and Prometheus are healthy
3. The security posture of the Portfolio pods (securityContext, NetworkPolicy, RBAC)
4. The vulnerability baseline (CVE count, CIS score, Kubescape score)
5. Any pre-existing issues that need attention before scenarios start

Fill in the baseline report template with your findings.
```

- [ ] **Step 4: Commit**

```bash
git add scenarios/00-DAY1-BASELINE/checklist.md
git commit -m "feat(seclab): add Day 1 analyst baseline checklist"
```

### run-baseline.sh

- [ ] **Step 5: Write the automated baseline capture script**

```bash
#!/usr/bin/env bash
# Day 1 Baseline — Automated State Capture
# Run this before any scenario to establish "normal"
#
# CSF 2.0: ID.AM-01 (Inventories maintained)
# CIS v8: 1.1 (Establish Enterprise Asset Inventory)
# NIST: CM-2 (Baseline Configuration)
#

set -euo pipefail

NAMESPACE="anthra"
EVIDENCE_DIR="${EVIDENCE_DIR:-/home/jimmie/linkops-industries/GP-copilot/GP-PROJECTS/01-instance/slot-3/Anthra-SecLAB/evidence/$(date +%Y-%m-%d)}"
TIMESTAMP="$(date -u +%Y-%m-%dT%H%M%SZ)"
BASELINE_DIR="${EVIDENCE_DIR}/baseline-${TIMESTAMP}"

mkdir -p "${BASELINE_DIR}"

echo "=== Day 1 Baseline Capture ==="
echo "  Namespace: ${NAMESPACE}"
echo "  Output:    ${BASELINE_DIR}"
echo ""

# 1. Cluster state
echo "[1/7] Cluster state..."
kubectl get nodes -o wide > "${BASELINE_DIR}/nodes.txt" 2>&1
kubectl get ns > "${BASELINE_DIR}/namespaces.txt" 2>&1
kubectl get pods -A -o wide > "${BASELINE_DIR}/all-pods.txt" 2>&1

# 2. Target namespace
echo "[2/7] Target namespace (${NAMESPACE})..."
kubectl get pods,svc,networkpolicy,sa -n "${NAMESPACE}" -o wide > "${BASELINE_DIR}/anthra-resources.txt" 2>&1
kubectl get pods -n "${NAMESPACE}" -o json > "${BASELINE_DIR}/anthra-pods.json" 2>&1

# 3. Security stack health
echo "[3/7] Security stack..."
kubectl get pods -n falco --no-headers > "${BASELINE_DIR}/falco-status.txt" 2>&1 || echo "falco namespace not found" > "${BASELINE_DIR}/falco-status.txt"
kubectl get pods -n kyverno --no-headers > "${BASELINE_DIR}/kyverno-status.txt" 2>&1 || echo "kyverno namespace not found" > "${BASELINE_DIR}/kyverno-status.txt"
kubectl get pods -n logging --no-headers > "${BASELINE_DIR}/logging-status.txt" 2>&1 || echo "logging namespace not found" > "${BASELINE_DIR}/logging-status.txt"
kubectl get pods -n monitoring --no-headers > "${BASELINE_DIR}/monitoring-status.txt" 2>&1 || echo "monitoring namespace not found" > "${BASELINE_DIR}/monitoring-status.txt"

# 4. Kyverno policies
echo "[4/7] Kyverno policies..."
kubectl get clusterpolicies -o jsonpath='{range .items[*]}{.metadata.name}: {.spec.validationFailureAction}{"\n"}{end}' > "${BASELINE_DIR}/kyverno-policies.txt" 2>&1 || echo "no policies" > "${BASELINE_DIR}/kyverno-policies.txt"

# 5. RBAC snapshot
echo "[5/7] RBAC snapshot..."
kubectl get clusterrolebindings -o json > "${BASELINE_DIR}/crb-snapshot.json" 2>&1
kubectl get rolebindings -n "${NAMESPACE}" -o json > "${BASELINE_DIR}/rb-snapshot.json" 2>&1

# 6. NetworkPolicy snapshot
echo "[6/7] NetworkPolicy snapshot..."
kubectl get networkpolicy -n "${NAMESPACE}" -o json > "${BASELINE_DIR}/netpol-snapshot.json" 2>&1

# 7. Image versions
echo "[7/7] Image versions..."
kubectl get pods -n "${NAMESPACE}" -o jsonpath='{range .items[*]}{.metadata.name}: {.spec.containers[0].image}{"\n"}{end}' > "${BASELINE_DIR}/images.txt" 2>&1

echo ""
echo "=== Baseline capture complete ==="
echo "Files saved to: ${BASELINE_DIR}"
ls -la "${BASELINE_DIR}"
echo ""
echo "Next: Walk through checklist.md and fill in baseline-report-template.md"
```

- [ ] **Step 6: Make executable and commit**

```bash
chmod +x scenarios/00-DAY1-BASELINE/run-baseline.sh
git add scenarios/00-DAY1-BASELINE/run-baseline.sh
git commit -m "feat(seclab): add automated baseline capture script"
```

### baseline-report-template.md

- [ ] **Step 7: Write the baseline report template**

```markdown
# Baseline Report — Anthra Corp SecLAB

**Analyst:** _______________
**Date:** _______________
**Cluster:** k3d-seclab
**Namespace:** anthra

---

## Cluster Health

| Check | Result | Notes |
|-------|--------|-------|
| Nodes (expect 3 Ready) | | |
| Pods in anthra (expect 3 Running) | | |
| Falco running (expect 3 pods) | | |
| Kyverno running (expect 3 pods) | | |
| Fluent Bit running (expect 3 pods) | | |
| Grafana accessible | | |

## Security Posture

| Check | Result | Notes |
|-------|--------|-------|
| All pods runAsNonRoot | | |
| All pods readOnlyRootFilesystem | | |
| NetworkPolicies present | | |
| All services ClusterIP | | |
| SA tokens disabled | | |

## Vulnerability Baseline

| Scanner | Score/Count | Notes |
|---------|------------|-------|
| Trivy HIGH/CRITICAL (api) | | |
| Trivy HIGH/CRITICAL (ui) | | |
| kube-bench FAIL count | | |
| Kubescape compliance % | | |

## RBAC

| Check | Result | Notes |
|-------|--------|-------|
| Non-system cluster-admin bindings | | |
| Custom wildcard roles | | |

## Pre-Existing Issues

List anything that looks wrong before scenarios start:

1.
2.
3.

---

**Signature:** _______________
**Reviewed by:** _______________
```

- [ ] **Step 8: Commit**

```bash
git add scenarios/00-DAY1-BASELINE/baseline-report-template.md
git commit -m "feat(seclab): add baseline report template for analysts"
```

---

## Task 1: L7-01-PR.AA-05 — Admin API Endpoint Exposed

**CSF 2.0:** PR.AA-05 (Access permissions, entitlements, and authorizations are managed)
**CIS v8:** 3.3 (Configure Data Access Control Lists)
**What breaks:** The Portfolio API's `/docs` (Swagger) and `/redoc` endpoints are accessible — they expose every route, parameter, and data model to anyone who finds them.

**Files:**
- Create: `scenarios/L7-01-PR.AA-05-api-auth/README.md`
- Create: `scenarios/L7-01-PR.AA-05-api-auth/baseline.sh`
- Create: `scenarios/L7-01-PR.AA-05-api-auth/break.sh`
- Create: `scenarios/L7-01-PR.AA-05-api-auth/detect.md`
- Create: `scenarios/L7-01-PR.AA-05-api-auth/investigate.md`
- Create: `scenarios/L7-01-PR.AA-05-api-auth/fix.sh`
- Create: `scenarios/L7-01-PR.AA-05-api-auth/remediate.md`
- Create: `scenarios/L7-01-PR.AA-05-api-auth/verify.sh`
- Create: `scenarios/L7-01-PR.AA-05-api-auth/report-template.md`

- [ ] **Step 1: Write README.md**

The scenario overview — what, why, CSF mapping, difficulty.

```markdown
# L7-01: Admin API Endpoint Exposed (PR.AA-05)

## Scenario

The Portfolio API's interactive documentation endpoints (`/docs`, `/redoc`, `/openapi.json`)
are accessible without authentication. An attacker who discovers these endpoints gets a
complete map of every API route, expected parameters, and data models — the equivalent
of handing them the application's blueprint.

## CSF 2.0 Mapping

| Field | Value |
|-------|-------|
| **Function** | PROTECT |
| **Category** | PR.AA — Identity Management, Authentication, and Access Control |
| **Subcategory** | PR.AA-05 — Access permissions, entitlements, and authorizations are managed |
| **CIS v8** | 3.3 — Configure Data Access Control Lists |
| **NIST 800-53** | AC-3 (Access Enforcement) |

## Difficulty

**Level 1** — Guided detection, no ambiguity in the fix.

## Lifecycle

1. `baseline.sh` — Capture current API endpoint accessibility
2. `break.sh` — Expose /docs and /redoc (if not already exposed)
3. `detect.md` — What to look for in Grafana / Falco / kubectl
4. `investigate.md` — L1 analyst step-by-step
5. `fix.sh` — Disable docs endpoints in production
6. `verify.sh` — Confirm endpoints return 404
7. `report-template.md` — Fill in your findings
```

- [ ] **Step 2: Write baseline.sh**

```bash
#!/usr/bin/env bash
# L7-01 PR.AA-05 — Baseline: Capture API endpoint state before break
#
# CSF 2.0: PR.AA-05 (Access permissions managed)
# CIS v8: 3.3 (Configure Data Access Control Lists)
# NIST: AC-3 (Access Enforcement)
#

set -euo pipefail

NAMESPACE="anthra"
API_POD=$(kubectl get pods -n "${NAMESPACE}" -l app.kubernetes.io/component=api -o jsonpath='{.items[0].metadata.name}')

echo "=== L7-01 Baseline: API endpoint accessibility ==="
echo "  API Pod: ${API_POD}"
echo ""

# Check /docs, /redoc, /openapi.json, /health
for ENDPOINT in /docs /redoc /openapi.json /health; do
    STATUS=$(kubectl exec -n "${NAMESPACE}" "${API_POD}" -- \
        curl -s -o /dev/null -w "%{http_code}" "http://localhost:8000${ENDPOINT}" 2>/dev/null || echo "ERR")
    echo "  ${ENDPOINT} -> HTTP ${STATUS}"
done

echo ""
echo "=== Baseline captured. If /docs or /redoc return 200, they are exposed. ==="
```

- [ ] **Step 3: Write break.sh**

```bash
#!/usr/bin/env bash
# L7-01 PR.AA-05 — Break: Expose API documentation endpoints
#
# CSF 2.0: PR.AA-05 (Access permissions managed)
# CIS v8: 3.3 (Configure Data Access Control Lists)
# NIST: AC-3 (Access Enforcement)
#
# FastAPI enables /docs and /redoc by default. If the app was hardened to
# disable them, this script re-enables them by patching the deployment env.
# If they're already exposed (default), this is a no-op — the vulnerability
# was there from the start. That's the point.

set -euo pipefail

NAMESPACE="anthra"

echo "=== L7-01 Break: Ensuring API docs are exposed ==="

# Check if /docs is already accessible
API_POD=$(kubectl get pods -n "${NAMESPACE}" -l app.kubernetes.io/component=api -o jsonpath='{.items[0].metadata.name}')
STATUS=$(kubectl exec -n "${NAMESPACE}" "${API_POD}" -- \
    curl -s -o /dev/null -w "%{http_code}" "http://localhost:8000/docs" 2>/dev/null || echo "ERR")

if [ "${STATUS}" = "200" ]; then
    echo "  /docs already returns 200 — vulnerability pre-exists (this is realistic)"
    echo "  In production, this is the most common case: nobody disabled the defaults"
else
    echo "  /docs returns ${STATUS} — patching deployment to re-enable"
    kubectl set env deployment/portfolio-anthra-portfolio-app-api \
        -n "${NAMESPACE}" DOCS_ENABLED=true
    kubectl rollout status deployment/portfolio-anthra-portfolio-app-api \
        -n "${NAMESPACE}" --timeout=60s
fi

echo ""
echo "=== L7-01 Break complete ==="
echo ""
echo "The API documentation is now accessible to anyone who can reach the service."
echo "Run: kubectl port-forward -n anthra svc/portfolio-anthra-portfolio-app-api 8000:8000"
echo "Then open: http://localhost:8000/docs"
```

- [ ] **Step 4: Write detect.md**

```markdown
# L7-01: Detection — What to Look For

You're a Day 1 analyst. Something might be wrong with the Portfolio API.
Here's how to find it.

## What You're Looking For

An API documentation endpoint (`/docs`, `/redoc`) that should NOT be accessible
in production is responding to requests. This gives anyone a complete map of
every API route.

## Step 1: Check Grafana (if dashboards exist)

```bash
# Port-forward Grafana
kubectl port-forward -n monitoring svc/prometheus-grafana 3000:80 &
# Open http://localhost:3000 (admin/prom-operator)
```

Look at:
- **HTTP request rate** — are there requests to `/docs` or `/openapi.json`?
- **Unusual endpoints** — any path getting traffic that isn't `/health` or `/api/*`?

## Step 2: Check Falco alerts

```bash
# Recent Falco alerts
kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=50 | grep -i "anthra"
```

Falco may not fire for this — it's not a syscall violation, it's a configuration
issue. That's important to note: **not all vulnerabilities trigger runtime alerts**.

## Step 3: Check the endpoint directly

```bash
# Port-forward the API
kubectl port-forward -n anthra svc/portfolio-anthra-portfolio-app-api 8000:8000 &

# Test documentation endpoints
curl -s -o /dev/null -w "HTTP %{http_code}" http://localhost:8000/docs
curl -s -o /dev/null -w "HTTP %{http_code}" http://localhost:8000/redoc
curl -s -o /dev/null -w "HTTP %{http_code}" http://localhost:8000/openapi.json
```

**If any return HTTP 200, the vulnerability is confirmed.**

## Step 4: Check the API source code

```bash
# Look at how the FastAPI app is initialized
kubectl exec -n anthra deployment/portfolio-anthra-portfolio-app-api -- \
    grep -n "FastAPI" /app/main.py | head -5
```

Look for: `docs_url=None, redoc_url=None`. If those kwargs are missing,
documentation is enabled by default.

## What to Record

- Which endpoints returned 200
- Whether Falco/Grafana caught it (and if not, why not)
- The FastAPI initialization line in main.py
```

- [ ] **Step 5: Write investigate.md**

```markdown
# L7-01: Investigation — L1 Analyst Procedure

## Context

You found that `/docs` and/or `/redoc` return HTTP 200 on the Portfolio API.
Now you need to understand the risk, scope, and urgency.

## Step 1: Determine exposure scope

**Question:** Can anyone outside the cluster reach these endpoints?

```bash
# Check if there's an ingress or gateway route to the API
kubectl get ingress,httproute -n anthra 2>/dev/null
kubectl get svc -n anthra -o jsonpath='{range .items[*]}{.metadata.name}: {.spec.type}{"\n"}{end}'
```

- If the service is `ClusterIP` only → exposure is cluster-internal (lower risk)
- If there's an ingress/gateway → exposure is internet-facing (HIGH risk)

## Step 2: Check what's exposed

```bash
# Download the OpenAPI spec — this is what an attacker gets
curl -s http://localhost:8000/openapi.json | python3 -m json.tool | head -50
```

Look for:
- **Sensitive routes** — `/api/admin/*`, `/api/settings/*`, `/api/keys/*`
- **Internal routes** — health checks, debug endpoints, metrics
- **Data models** — request/response schemas that reveal database structure

## Step 3: Check access logs

```bash
# Has anyone already accessed /docs?
kubectl logs -n anthra deployment/portfolio-anthra-portfolio-app-api --tail=100 | \
    grep -E "(docs|redoc|openapi)" || echo "No access to docs endpoints found in recent logs"
```

## Step 4: Classify the finding

| Field | Value |
|-------|-------|
| **CSF Subcategory** | PR.AA-05 |
| **CIS v8 Safeguard** | 3.3 (Configure Data Access Control Lists) |
| **Severity** | MEDIUM (ClusterIP only) or HIGH (internet-facing) |
| **Rank** | D (deterministic fix — disable docs in prod) |
| **Affected Asset** | portfolio-anthra-portfolio-app-api |
| **Evidence** | HTTP 200 on /docs, /redoc, or /openapi.json |

## Step 5: Decision

This is a **D-rank finding** — the fix is deterministic (disable docs_url and redoc_url
in FastAPI). No architectural decision needed. Proceed to remediation.

If the service is internet-facing, escalate to your manager before fixing —
an attacker may have already used the endpoint to map the API.
```

- [ ] **Step 6: Write fix.sh**

```bash
#!/usr/bin/env bash
# L7-01 PR.AA-05 — Fix: Disable API documentation endpoints in production
#
# CSF 2.0: PR.AA-05 (Access permissions managed)
# CIS v8: 3.3 (Configure Data Access Control Lists)
# NIST: AC-3 (Access Enforcement)
#
# Patches the FastAPI app to disable /docs, /redoc, and /openapi.json.
# In a real engagement, this would be a code change committed to git.
# In this lab, we patch the running container to demonstrate the fix.

set -euo pipefail

NAMESPACE="anthra"
API_DEPLOY="portfolio-anthra-portfolio-app-api"

echo "=== L7-01 Fix: Disabling API documentation endpoints ==="

# Patch: set environment variable that the app reads to disable docs
kubectl set env deployment/"${API_DEPLOY}" -n "${NAMESPACE}" \
    DISABLE_DOCS=true

echo "Waiting for rollout..."
kubectl rollout status deployment/"${API_DEPLOY}" -n "${NAMESPACE}" --timeout=60s

echo ""
echo "=== L7-01 Fix applied ==="
echo ""
echo "NOTE: This env var approach works if the app checks DISABLE_DOCS."
echo "If it doesn't, the real fix is a code change:"
echo ""
echo '  # In main.py, change:'
echo '  app = FastAPI()'
echo '  # To:'
echo '  app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)'
echo ""
echo "Run verify.sh to confirm the fix."
```

- [ ] **Step 7: Write remediate.md**

```markdown
# L7-01: Remediation — Why This Fix

## The Benchmark Says

**CIS Controls v8 — Safeguard 3.3:** Configure Data Access Control Lists

> Configure data access control lists based on a user's need to know.
> Apply data access control lists, also known as access permissions, to
> local and remote file systems, databases, and applications.

API documentation endpoints are data — they reveal the application's entire
interface. In production, only authorized developers should access them.

**CSF 2.0 — PR.AA-05:** Access permissions, entitlements, and authorizations
are defined in a policy, managed, enforced, and reviewed.

The default FastAPI behavior (docs enabled) violates this — there's no
access control on the documentation endpoints.

## The Fix

FastAPI's `docs_url`, `redoc_url`, and `openapi_url` parameters control
documentation endpoint availability:

```python
# BEFORE (vulnerable — default)
app = FastAPI()

# AFTER (hardened)
import os
docs_url = "/docs" if os.getenv("ENVIRONMENT") == "development" else None
app = FastAPI(
    docs_url=docs_url,
    redoc_url=None,       # Always disable redoc in prod
    openapi_url=None,     # Always disable openapi.json in prod
)
```

## Why Not Just Use Authentication?

Adding auth to /docs is an option, but the simpler fix is disabling it entirely:
- Developers use local environments where docs are enabled
- Production doesn't need interactive API documentation
- Fewer endpoints = smaller attack surface (CIS 4.8: Uninstall Unneeded Services)
```

- [ ] **Step 8: Write verify.sh**

```bash
#!/usr/bin/env bash
# L7-01 PR.AA-05 — Verify: Confirm documentation endpoints are disabled
#
# CSF 2.0: PR.AA-05 (Access permissions managed)
# CIS v8: 3.3 (Configure Data Access Control Lists)
# NIST: AC-3 (Access Enforcement)
#

set -euo pipefail

NAMESPACE="anthra"
API_POD=$(kubectl get pods -n "${NAMESPACE}" -l app.kubernetes.io/component=api -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)

echo "=== L7-01 Verify: API documentation endpoints ==="
echo ""

PASS=0
FAIL=0

for ENDPOINT in /docs /redoc /openapi.json; do
    STATUS=$(kubectl exec -n "${NAMESPACE}" "${API_POD}" -- \
        curl -s -o /dev/null -w "%{http_code}" "http://localhost:8000${ENDPOINT}" 2>/dev/null || echo "ERR")
    if [ "${STATUS}" = "200" ]; then
        echo "  FAIL: ${ENDPOINT} -> HTTP ${STATUS} (still accessible)"
        FAIL=$((FAIL + 1))
    else
        echo "  PASS: ${ENDPOINT} -> HTTP ${STATUS} (not accessible)"
        PASS=$((PASS + 1))
    fi
done

# Health should still work
STATUS=$(kubectl exec -n "${NAMESPACE}" "${API_POD}" -- \
    curl -s -o /dev/null -w "%{http_code}" "http://localhost:8000/health" 2>/dev/null || echo "ERR")
if [ "${STATUS}" = "200" ]; then
    echo "  PASS: /health -> HTTP ${STATUS} (still works)"
    PASS=$((PASS + 1))
else
    echo "  FAIL: /health -> HTTP ${STATUS} (broken!)"
    FAIL=$((FAIL + 1))
fi

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "${FAIL}" -eq 0 ]; then
    echo "=== VERIFICATION PASSED ==="
else
    echo "=== VERIFICATION FAILED — docs endpoints still accessible ==="
fi
```

- [ ] **Step 9: Write report-template.md**

```markdown
# Incident Report — L7-01: API Documentation Exposed

**Analyst:** _______________
**Date:** _______________
**Severity:** MEDIUM / HIGH (circle one)
**CSF Subcategory:** PR.AA-05
**CIS v8 Safeguard:** 3.3

---

## Finding

| Field | Value |
|-------|-------|
| Asset | portfolio-anthra-portfolio-app-api |
| Namespace | anthra |
| Endpoint(s) | /docs, /redoc, /openapi.json |
| HTTP Status (before fix) | |
| HTTP Status (after fix) | |
| Exposure | ClusterIP / Internet-facing (circle one) |

## Timeline

| Time | Action |
|------|--------|
| | Baseline captured (run-baseline.sh) |
| | Vulnerability detected (how?) |
| | Investigation completed |
| | Fix applied (fix.sh) |
| | Fix verified (verify.sh) |

## Root Cause

FastAPI enables interactive documentation by default. The deployment did not
explicitly disable `docs_url`, `redoc_url`, or `openapi_url` for production.

## Remediation Applied

- [ ] Environment variable `DISABLE_DOCS=true` set on deployment
- [ ] (Permanent fix) Code change: `FastAPI(docs_url=None, redoc_url=None, openapi_url=None)`
- [ ] Verified /docs returns non-200 after fix
- [ ] Verified /health still returns 200

## POA&M Entry

| ID | Control | Status | Priority | Target Date | Owner |
|----|---------|--------|----------|-------------|-------|
| L7-01 | PR.AA-05 / CIS 3.3 | REMEDIATED | MEDIUM | | |

## Lessons Learned

What would you recommend to prevent this in the future?

1.
2.
```

- [ ] **Step 10: Make scripts executable and commit all files**

```bash
chmod +x scenarios/L7-01-PR.AA-05-api-auth/baseline.sh
chmod +x scenarios/L7-01-PR.AA-05-api-auth/break.sh
chmod +x scenarios/L7-01-PR.AA-05-api-auth/fix.sh
chmod +x scenarios/L7-01-PR.AA-05-api-auth/verify.sh
git add scenarios/L7-01-PR.AA-05-api-auth/
git commit -m "feat(seclab): add L7-01 PR.AA-05 API auth scenario (full lifecycle)"
```

---

## Task 2: L7-02-PR.PS-01 — Missing Security Headers

**CSF 2.0:** PR.PS-01 (Configuration management practices are established and applied)
**CIS v8:** 16.12 (Implement Code-Level Security Checks)
**What breaks:** Security headers (CSP, X-Frame-Options, HSTS) are stripped from the UI nginx, leaving the frontend vulnerable to clickjacking, XSS, and downgrade attacks.

**Files:** Same 9-file structure as Task 1.

- [ ] **Step 1: Write all 9 files for L7-02**

`break.sh` overwrites the nginx config to remove all security headers. `detect.md` teaches the analyst to use `curl -I` and check response headers. `investigate.md` walks through which headers are missing and what attack each prevents. `fix.sh` restores the hardened nginx config. `verify.sh` checks all 6 headers are present. `remediate.md` references CIS 16.12 and OWASP Secure Headers Project.

Key content for `break.sh`:
```bash
# Patch nginx config to remove security headers
kubectl exec -n anthra deployment/portfolio-anthra-portfolio-app-ui -- \
    sh -c "echo 'server { listen 8080; root /usr/share/nginx/html; location / { try_files \$uri \$uri/ /index.html; } }' > /etc/nginx/conf.d/default.conf && nginx -s reload"
```

Key content for `detect.md`:
```bash
# Check response headers
curl -sI http://localhost:3000 | grep -iE "(content-security|x-frame|x-content-type|strict-transport|referrer-policy|permissions-policy)"
# If empty — headers are missing
```

- [ ] **Step 2: Commit**

```bash
git add scenarios/L7-02-PR.PS-01-security-headers/
git commit -m "feat(seclab): add L7-02 PR.PS-01 security headers scenario"
```

---

## Task 3: L7-03-PR.PS-01 — CIS Benchmark Failures

**CSF 2.0:** PR.PS-01 (Configuration management practices applied)
**CIS v8:** 4.1 (Establish and Maintain a Secure Configuration Process)
**What breaks:** kube-bench and kubescape report FAIL findings that haven't been remediated — the cluster was deployed without CIS hardening.

**Files:** Same 9-file structure. `break.sh` is a no-op — the failures already exist. `detect.md` teaches running kube-bench and kubescape. `investigate.md` teaches reading the output and prioritizing. `fix.sh` runs the top 5 remediations.

- [ ] **Step 1-2:** Write all 9 files and commit.

---

## Task 4: L7-04-DE.CM-03 — EDR/Falco Agent Down

**CSF 2.0:** DE.CM-03 (Computing hardware, software, services are monitored)
**CIS v8:** 13.7 (Deploy a Host-Based Intrusion Detection Solution)
**What breaks:** Falco DaemonSet scaled to 0 — runtime detection goes blind.

`break.sh`: `kubectl scale daemonset falco -n falco --replicas=0` (Note: DaemonSets don't scale with replicas — the break will patch the nodeSelector to an impossible value to evict all pods).

`detect.md`: Grafana Falco dashboard goes silent. Prometheus alert `FalcoSilent` fires. No Falco pods in `kubectl get pods -n falco`.

- [ ] **Step 1-2:** Write all 9 files and commit.

---

## Task 5: L7-05-DE.AE-02 — Alert Fatigue (No Custom Rules)

**CSF 2.0:** DE.AE-02 (Potentially adverse events are analyzed)
**CIS v8:** 8.11 (Tune Security Event Alert Thresholds)
**What breaks:** Only default Falco rules are active — no custom rules for the Portfolio application. Every container exec triggers an alert, drowning real threats in noise.

`break.sh`: Delete any custom Falco rules ConfigMap. `detect.md`: Count alerts in Grafana — if >50/hour and all the same rule, it's noise. `fix.sh`: Deploy tuned rules with allowlists for known-good processes.

- [ ] **Step 1-2:** Write all 9 files and commit.

---

## Task 6: L7-06-DE.AE-06 — Log Retention Too Short

**CSF 2.0:** DE.AE-06 (Information on adverse events is provided to authorized staff)
**CIS v8:** 8.10 (Retain Audit Logs)
**What breaks:** Loki or Fluent Bit retention set to 24 hours — forensic evidence disappears before investigation starts.

`break.sh`: Patch Loki retention to 24h. `detect.md`: Query Loki for events older than 24h — they're gone. `fix.sh`: Set retention to 90 days. `remediate.md`: FedRAMP requires 90 days, PCI-DSS requires 365 days.

- [ ] **Step 1-2:** Write all 9 files and commit.

---

## Task 7: L7-07-DE.AE-07 — Log Source Stopped

**CSF 2.0:** DE.AE-07 (Cyber threat intelligence and contextual info integrated)
**CIS v8:** 8.2 (Collect Audit Logs)
**What breaks:** Fluent Bit DaemonSet scaled down on one node — that node's logs stop flowing.

`break.sh`: Cordon one node and delete the Fluent Bit pod on it. `detect.md`: Grafana log volume dashboard shows drop for one node. Loki query returns no results for that node. `fix.sh`: Uncordon the node, verify Fluent Bit pod comes back.

- [ ] **Step 1-2:** Write all 9 files and commit.

---

## Task 8: L7-08-ID.RA-01 — Unpatched CVE in Container Image

**CSF 2.0:** ID.RA-01 (Vulnerabilities in assets are identified, validated, and recorded)
**CIS v8:** 7.4 (Perform Automated Application Patch Management)
**What breaks:** API deployment patched to use an older, vulnerable base image with known CRITICAL CVEs.

`break.sh`: `kubectl set image deployment/portfolio-anthra-portfolio-app-api api=python:3.9-slim -n anthra` (old image with known CVEs). `detect.md`: Run `trivy image python:3.9-slim --severity CRITICAL`. `fix.sh`: Roll back to the hardened image. `remediate.md`: Pin images by digest, scan in CI.

- [ ] **Step 1-2:** Write all 9 files and commit.

---

## Task 9: L7-09-RS.MI-01 — Detection Without Response

**CSF 2.0:** RS.MI-01 (Incidents are contained)
**CIS v8:** 17.2 (Establish and Maintain Contact Information for Reporting Security Incidents)
**What breaks:** Falco detects a shell exec in the API pod, but no alerting route is configured — the alert goes to stdout only.

`break.sh`: Exec into the API pod (triggers Falco rule). `detect.md`: Falco log shows the alert, but no Slack/PagerDuty/email. `investigate.md`: Check Falcosidekick outputs — are any configured? `fix.sh`: Configure Falcosidekick to route to a webhook. `remediate.md`: Detection without response = detection without value.

- [ ] **Step 1-2:** Write all 9 files and commit.

---

## Task 10: L7-10-RS.MI-02 — FIM Not Covering Critical Paths

**CSF 2.0:** RS.MI-02 (Incidents are eradicated)
**CIS v8:** 3.14 (Log Sensitive Data Access)
**What breaks:** No file integrity monitoring on the API container — an attacker could replace `/app/main.py` and nobody would know.

`break.sh`: Exec into the API pod and modify a file (write to /tmp since rootFS is read-only — demonstrate that without FIM, even /tmp modifications go unnoticed). `detect.md`: Check if Falco has rules for file modification in the container. `fix.sh`: Add a Falco rule that alerts on writes to `/app/` in the API container. `verify.sh`: Trigger a write, confirm Falco fires.

- [ ] **Step 1-2:** Write all 9 files and commit.

---

## Execution Checklist

| Task | Scenario | CSF | Files | Status |
|------|----------|-----|-------|--------|
| 0 | 00-DAY1-BASELINE | ID.AM-01 | 4 | - [ ] |
| 1 | L7-01-PR.AA-05-api-auth | PR.AA-05 | 9 | - [ ] |
| 2 | L7-02-PR.PS-01-security-headers | PR.PS-01 | 9 | - [ ] |
| 3 | L7-03-PR.PS-01-cis-benchmark | PR.PS-01 | 9 | - [ ] |
| 4 | L7-04-DE.CM-03-edr-disabled | DE.CM-03 | 9 | - [ ] |
| 5 | L7-05-DE.AE-02-alert-fatigue | DE.AE-02 | 9 | - [ ] |
| 6 | L7-06-DE.AE-06-log-retention | DE.AE-06 | 9 | - [ ] |
| 7 | L7-07-DE.AE-07-missing-logs | DE.AE-07 | 9 | - [ ] |
| 8 | L7-08-ID.RA-01-unpatched-cve | ID.RA-01 | 9 | - [ ] |
| 9 | L7-09-RS.MI-01-no-response | RS.MI-01 | 9 | - [ ] |
| 10 | L7-10-RS.MI-02-fim-disabled | RS.MI-02 | 9 | - [ ] |
| **Total** | | | **94 files** | |
