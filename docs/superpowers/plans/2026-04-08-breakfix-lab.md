# Anthra-SecLAB Break/Fix Lab Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a NIST-mapped break/fix security lab that produces real scanner evidence against the live k3d-seclab cluster.

**Architecture:** Each scenario follows a break → detect → fix → evidence cycle mapped to a NIST 800-53 control. Scripts are idempotent bash. Evidence comes from real tool runs (kubescape, polaris, kube-hunter) — never simulated. A central collection script automates the full pipeline and feeds a POA&M tracker.

**Tech Stack:** bash scripts, kubectl, kubescape (v4.0.3, JSON output), polaris (v8.5.0, JSON output), kube-hunter, trivy. Cluster: k3d-seclab (k3s v1.31.5). Namespace: `anthra`.

**Cluster context:** `k3d-seclab` with 1 server + 2 agents. Running deployments: anthra-ui, anthra-api, anthra-db, anthra-log-ingest in `anthra` namespace. No NetworkPolicies exist currently. No Falco deployed. kubescape SARIF only works on local files — use JSON for cluster scans.

---

## File Structure

```
Anthra-SecLAB/
├── docs/
│   ├── control-map.md                    # Deliverable 1: NIST control → tool mapping table
│   └── poam-template.md                  # Deliverable 4: POA&M tracking template
├── scenarios/
│   ├── SC-7-boundary-protection/         # Scenario 1
│   │   ├── break.sh
│   │   ├── detect.sh
│   │   ├── fix.sh
│   │   └── evidence-template.md
│   ├── CM-7-least-functionality/         # Scenario 2
│   │   ├── break.sh
│   │   ├── detect.sh
│   │   ├── fix.sh
│   │   └── evidence-template.md
│   └── AC-6-least-privilege/             # Scenario 3
│       ├── break.sh
│       ├── detect.sh
│       ├── fix.sh
│       └── evidence-template.md
└── tools/
    └── collect-evidence.sh               # Deliverable 3: Evidence pipeline
```

**Design decisions:**
- `detect.md` from spec becomes `detect.sh` — the detection step runs real tools, so it should be executable. A markdown header comment documents what tools are used and why.
- Each scenario dir is self-contained. No shared libraries — three scenarios don't justify abstraction.
- Evidence output goes to `evidence/YYYY-MM-DD/` (gitignored) — real scan output, not committed.

---

## Task 1: Control Map and POA&M Template (docs)

**Files:**
- Create: `docs/control-map.md`
- Create: `docs/poam-template.md`
- Create: `evidence/.gitignore`

- [ ] **Step 1: Create the control map**

Create `docs/control-map.md`:

```markdown
# Anthra-SecLAB Control Map

Maps each lab scenario to OSI layer, GP-Copilot 5 C's package, NIST 800-53 control, and tooling.

| Scenario | NIST Control | OSI Layer | 5 C's Package | Type | Preventive Tool | Detective Tool |
|----------|-------------|-----------|---------------|------|-----------------|----------------|
| SC-7 Boundary Protection | SC-7 | L3 Network | 02-CLUSTER-HARDEN | Preventive + Detective | NetworkPolicy (kubectl) | kube-hunter, Falco |
| CM-7 Least Functionality | CM-7 | L3 Network | 02-CLUSTER-HARDEN | Preventive | NetworkPolicy (kubectl) | Kubescape, Polaris |
| AC-6 Least Privilege | AC-6 | L3 Cluster | 02-CLUSTER-HARDEN | Preventive | RBAC (kubectl) | kubescape, kubectl auth can-i |

## Planned (not yet implemented)

| Scenario | NIST Control | OSI Layer | 5 C's Package | Type | Preventive Tool | Detective Tool |
|----------|-------------|-----------|---------------|------|-----------------|----------------|
| SA-11 Developer Testing | SA-11 | L7 App | 01-APP-SEC | Detective | Semgrep | ZAP |
| RA-5 Vulnerability Scanning | RA-5 | L7 App | 01-APP-SEC | Detective | Trivy | ZAP |
| SC-8 Transmission Confidentiality | SC-8 | L4 Transport | 02-CLUSTER-HARDEN | Preventive | mTLS (Linkerd/Istio) | openssl s_client |
| SC-7 Cloud Boundary | SC-7 | Cloud | 04-CLOUD-SECURITY | Preventive | Security Groups | Prowler |
```

- [ ] **Step 2: Create the POA&M template**

Create `docs/poam-template.md`:

```markdown
# Plan of Action & Milestones (POA&M)

Anthra-SecLAB — Break/Fix Evidence Tracker

| Control ID | Finding | Risk Level | Break Method | Detection Tool | Fix Applied | Evidence File | Status | Date Closed |
|-----------|---------|------------|-------------|---------------|-------------|--------------|--------|-------------|
| SC-7 | No default-deny NetworkPolicy | High | Deleted default-deny netpol | kube-hunter | Restored default-deny + per-service rules | `evidence/YYYY-MM-DD/sc7-*.json` | Open | |
| CM-7 | Wildcard ingress allows all pod-to-pod | Medium | Added allow-all ingress rule | Kubescape, Polaris | Scoped ingress to named services | `evidence/YYYY-MM-DD/cm7-*.json` | Open | |
| AC-6 | Default SA bound to cluster-admin | Critical | Bound default SA to cluster-admin | kubescape, kubectl auth can-i | Removed binding, scoped to namespace read-only | `evidence/YYYY-MM-DD/ac6-*.json` | Open | |
```

- [ ] **Step 3: Create evidence gitignore**

Create `evidence/.gitignore`:

```
# Evidence output from real scanner runs — not committed
# Run tools/collect-evidence.sh to generate
*
!.gitignore
```

- [ ] **Step 4: Commit**

```bash
git add docs/control-map.md docs/poam-template.md evidence/.gitignore
git commit -m "docs: add NIST control map and POA&M template for break/fix lab"
```

---

## Task 2: SC-7 Boundary Protection Scenario

**Files:**
- Create: `scenarios/SC-7-boundary-protection/break.sh`
- Create: `scenarios/SC-7-boundary-protection/detect.sh`
- Create: `scenarios/SC-7-boundary-protection/fix.sh`
- Create: `scenarios/SC-7-boundary-protection/evidence-template.md`

- [ ] **Step 1: Create the fix script first**

The constraint says "break scripts must have a matching fix script before they are committed." Write `fix.sh` first so we know exactly what the secure state looks like, then `break.sh` removes it.

Create `scenarios/SC-7-boundary-protection/fix.sh`:

```bash
#!/usr/bin/env bash
# SC-7 Boundary Protection — Fix
# NIST 800-53: SC-7 | Layer: L3 Network | Package: 02-CLUSTER-HARDEN
# Type: Preventive + Detective
#
# Restores default-deny NetworkPolicy and per-service ingress rules
# in the anthra namespace. Idempotent — safe to run multiple times.

set -euo pipefail

NAMESPACE="anthra"

echo "=== SC-7 Fix: Restoring boundary protection ==="

# Default-deny all ingress
cat <<'EOF' | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: anthra
  labels:
    seclab-scenario: SC-7
spec:
  podSelector: {}
  policyTypes:
    - Ingress
EOF

# Allow ingress to anthra-ui from any (NodePort traffic)
cat <<'EOF' | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-ui-ingress
  namespace: anthra
  labels:
    seclab-scenario: SC-7
spec:
  podSelector:
    matchLabels:
      app: anthra-ui
  policyTypes:
    - Ingress
  ingress:
    - ports:
        - protocol: TCP
          port: 80
EOF

# Allow ingress to anthra-api from anthra-ui only
cat <<'EOF' | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-api-from-ui
  namespace: anthra
  labels:
    seclab-scenario: SC-7
spec:
  podSelector:
    matchLabels:
      app: anthra-api
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: anthra-ui
      ports:
        - protocol: TCP
          port: 8080
EOF

# Allow ingress to anthra-db from anthra-api only
cat <<'EOF' | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-db-from-api
  namespace: anthra
  labels:
    seclab-scenario: SC-7
spec:
  podSelector:
    matchLabels:
      app: anthra-db
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: anthra-api
      ports:
        - protocol: TCP
          port: 5432
EOF

# Allow ingress to anthra-log-ingest from anthra-api only
cat <<'EOF' | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-log-ingest-from-api
  namespace: anthra
  labels:
    seclab-scenario: SC-7
spec:
  podSelector:
    matchLabels:
      app: anthra-log-ingest
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: anthra-api
      ports:
        - protocol: TCP
          port: 9090
EOF

echo "=== SC-7 Fix complete ==="
kubectl get networkpolicy -n "${NAMESPACE}" -o wide
```

- [ ] **Step 2: Create the break script**

Create `scenarios/SC-7-boundary-protection/break.sh`:

```bash
#!/usr/bin/env bash
# SC-7 Boundary Protection — Break
# NIST 800-53: SC-7 | Layer: L3 Network | Package: 02-CLUSTER-HARDEN
#
# Deliberately removes all NetworkPolicies from the anthra namespace,
# leaving pods with unrestricted ingress. Idempotent.

set -euo pipefail

NAMESPACE="anthra"

echo "=== SC-7 Break: Removing all boundary protection ==="

# Delete all NetworkPolicies labeled as SC-7 scenario
kubectl delete networkpolicy -n "${NAMESPACE}" -l seclab-scenario=SC-7 --ignore-not-found

# Also delete any other netpols in the namespace (clean slate for detection)
kubectl delete networkpolicy -n "${NAMESPACE}" --all --ignore-not-found

echo "=== SC-7 Break complete — namespace has no ingress restrictions ==="
kubectl get networkpolicy -n "${NAMESPACE}" 2>/dev/null || echo "No NetworkPolicies found"
```

- [ ] **Step 3: Create the detect script**

Create `scenarios/SC-7-boundary-protection/detect.sh`:

```bash
#!/usr/bin/env bash
# SC-7 Boundary Protection — Detect
# NIST 800-53: SC-7 | Layer: L3 Network | Package: 02-CLUSTER-HARDEN
#
# Detection tools:
#   1. kubectl — check if NetworkPolicies exist
#   2. kube-hunter — probe for exposed services from outside the cluster
#   3. kubescape — scan for NSA/CISA network policy controls
#
# Outputs JSON evidence to stdout or to $EVIDENCE_DIR if set.

set -euo pipefail

NAMESPACE="anthra"
EVIDENCE_DIR="${EVIDENCE_DIR:-}"
TIMESTAMP="$(date -u +%Y-%m-%dT%H%M%SZ)"

echo "=== SC-7 Detect: Checking boundary protection ==="

# 1. Direct check — any NetworkPolicies?
echo ""
echo "--- NetworkPolicy check ---"
NETPOL_COUNT=$(kubectl get networkpolicy -n "${NAMESPACE}" --no-headers 2>/dev/null | wc -l)
if [ "${NETPOL_COUNT}" -eq 0 ]; then
    echo "FAIL: No NetworkPolicies in namespace ${NAMESPACE}"
else
    echo "PASS: ${NETPOL_COUNT} NetworkPolicies found"
    kubectl get networkpolicy -n "${NAMESPACE}" -o wide
fi

# 2. kube-hunter — network probe
echo ""
echo "--- kube-hunter scan ---"
HUNTER_OUT="/tmp/sc7-kube-hunter-${TIMESTAMP}.json"
kube-hunter --pod --quick --report json > "${HUNTER_OUT}" 2>/dev/null || true
VULN_COUNT=$(python3 -c "import json; d=json.load(open('${HUNTER_OUT}')); print(len(d.get('vulnerabilities', [])))" 2>/dev/null || echo "0")
echo "kube-hunter found ${VULN_COUNT} vulnerabilities"

# 3. kubescape — network policy controls
echo ""
echo "--- kubescape scan (network controls) ---"
KUBESCAPE_OUT="/tmp/sc7-kubescape-${TIMESTAMP}.json"
kubescape scan control C-0260 --format json --output "${KUBESCAPE_OUT}" 2>/dev/null || true
echo "kubescape output saved to ${KUBESCAPE_OUT}"

# Copy to evidence dir if set
if [ -n "${EVIDENCE_DIR}" ]; then
    mkdir -p "${EVIDENCE_DIR}"
    cp "${HUNTER_OUT}" "${EVIDENCE_DIR}/sc7-kube-hunter.json"
    cp "${KUBESCAPE_OUT}" "${EVIDENCE_DIR}/sc7-kubescape.json"
    kubectl get networkpolicy -n "${NAMESPACE}" -o json > "${EVIDENCE_DIR}/sc7-netpol-state.json" 2>/dev/null || echo '{"items":[]}' > "${EVIDENCE_DIR}/sc7-netpol-state.json"
    echo ""
    echo "Evidence saved to ${EVIDENCE_DIR}/"
fi

echo ""
echo "=== SC-7 Detect complete ==="
```

- [ ] **Step 4: Create the evidence template**

Create `scenarios/SC-7-boundary-protection/evidence-template.md`:

```markdown
# SC-7 Boundary Protection — Evidence

**NIST Control:** SC-7 Boundary Protection
**OSI Layer:** L3 Network
**5 C's Package:** 02-CLUSTER-HARDEN
**Control Type:** Preventive + Detective

## Break

**Action:** Deleted all NetworkPolicies in `anthra` namespace.

**Command:** `bash scenarios/SC-7-boundary-protection/break.sh`

**Before state (secure):**
<!-- Paste: kubectl get netpol -n anthra -o wide -->
```
```

## Detection

**Tools:** kube-hunter, kubescape (control C-0260)

**kube-hunter results:**
<!-- Paste: vulnerability count and key findings from sc7-kube-hunter.json -->
```
```

**kubescape results:**
<!-- Paste: failed controls from sc7-kubescape.json -->
```
```

## Fix

**Action:** Restored default-deny + per-service NetworkPolicy rules.

**Command:** `bash scenarios/SC-7-boundary-protection/fix.sh`

**After state (remediated):**
<!-- Paste: kubectl get netpol -n anthra -o wide -->
```
```

## Evidence Files

| File | Description | SHA256 |
|------|-------------|--------|
| `sc7-netpol-state.json` | kubectl netpol dump (before) | |
| `sc7-kube-hunter.json` | kube-hunter probe results | |
| `sc7-kubescape.json` | kubescape network control scan | |
| `sc7-netpol-state.json` | kubectl netpol dump (after) | |
```

- [ ] **Step 5: Make scripts executable and commit**

```bash
chmod +x scenarios/SC-7-boundary-protection/{break,detect,fix}.sh
git add scenarios/SC-7-boundary-protection/
git commit -m "scenario: SC-7 boundary protection break/detect/fix"
```

---

## Task 3: CM-7 Least Functionality Scenario

**Files:**
- Create: `scenarios/CM-7-least-functionality/break.sh`
- Create: `scenarios/CM-7-least-functionality/detect.sh`
- Create: `scenarios/CM-7-least-functionality/fix.sh`
- Create: `scenarios/CM-7-least-functionality/evidence-template.md`

- [ ] **Step 1: Create the fix script**

Create `scenarios/CM-7-least-functionality/fix.sh`:

```bash
#!/usr/bin/env bash
# CM-7 Least Functionality — Fix
# NIST 800-53: CM-7 | Layer: L3 Network | Package: 02-CLUSTER-HARDEN
# Type: Preventive
#
# Removes wildcard ingress and scopes ingress rules to named services.
# Depends on SC-7 fix having run first (default-deny must exist).
# Idempotent.

set -euo pipefail

NAMESPACE="anthra"

echo "=== CM-7 Fix: Removing overpermissive ingress ==="

# Delete the wildcard ingress rule if it exists
kubectl delete networkpolicy -n "${NAMESPACE}" allow-all-ingress --ignore-not-found

# Ensure the per-service rules from SC-7 are in place
# (CM-7 fix depends on SC-7 fix — run SC-7 fix first if netpols are missing)
NETPOL_COUNT=$(kubectl get networkpolicy -n "${NAMESPACE}" --no-headers 2>/dev/null | wc -l)
if [ "${NETPOL_COUNT}" -lt 2 ]; then
    echo "WARNING: Few NetworkPolicies found. Run SC-7 fix first:"
    echo "  bash scenarios/SC-7-boundary-protection/fix.sh"
    exit 1
fi

echo "=== CM-7 Fix complete ==="
kubectl get networkpolicy -n "${NAMESPACE}" -o wide
```

- [ ] **Step 2: Create the break script**

Create `scenarios/CM-7-least-functionality/break.sh`:

```bash
#!/usr/bin/env bash
# CM-7 Least Functionality — Break
# NIST 800-53: CM-7 | Layer: L3 Network | Package: 02-CLUSTER-HARDEN
#
# Adds a wildcard ingress rule that allows all pod-to-pod traffic,
# bypassing any per-service restrictions. Idempotent.
#
# Prerequisite: SC-7 fix must have run so default-deny + per-service
# rules exist. This scenario adds a rule that overrides them.

set -euo pipefail

NAMESPACE="anthra"

echo "=== CM-7 Break: Adding wildcard ingress ==="

# Ensure SC-7 policies exist first (otherwise there's nothing to break)
NETPOL_COUNT=$(kubectl get networkpolicy -n "${NAMESPACE}" --no-headers 2>/dev/null | wc -l)
if [ "${NETPOL_COUNT}" -eq 0 ]; then
    echo "ERROR: No NetworkPolicies exist. Run SC-7 fix first:"
    echo "  bash scenarios/SC-7-boundary-protection/fix.sh"
    exit 1
fi

# Add wildcard ingress — allows all pods to talk to all pods
cat <<'EOF' | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-all-ingress
  namespace: anthra
  labels:
    seclab-scenario: CM-7
spec:
  podSelector: {}
  policyTypes:
    - Ingress
  ingress:
    - {}
EOF

echo "=== CM-7 Break complete — all pod-to-pod ingress allowed ==="
kubectl get networkpolicy -n "${NAMESPACE}" -o wide
```

- [ ] **Step 3: Create the detect script**

Create `scenarios/CM-7-least-functionality/detect.sh`:

```bash
#!/usr/bin/env bash
# CM-7 Least Functionality — Detect
# NIST 800-53: CM-7 | Layer: L3 Network | Package: 02-CLUSTER-HARDEN
#
# Detection tools:
#   1. kubectl — check for wildcard/overpermissive ingress rules
#   2. kubescape — scan for overpermissive network policies
#   3. polaris — audit for network policy best practices
#
# Outputs JSON evidence to stdout or to $EVIDENCE_DIR if set.

set -euo pipefail

NAMESPACE="anthra"
EVIDENCE_DIR="${EVIDENCE_DIR:-}"
TIMESTAMP="$(date -u +%Y-%m-%dT%H%M%SZ)"

echo "=== CM-7 Detect: Checking for overpermissive ingress ==="

# 1. Direct check — any allow-all ingress?
echo ""
echo "--- NetworkPolicy wildcard check ---"
ALLOW_ALL=$(kubectl get networkpolicy -n "${NAMESPACE}" -o json | \
    python3 -c "
import sys, json
data = json.load(sys.stdin)
for item in data.get('items', []):
    for rule in item.get('spec', {}).get('ingress', []):
        if rule == {}:
            print(f\"FAIL: {item['metadata']['name']} has wildcard ingress (empty rule)\")
" 2>/dev/null || true)

if [ -z "${ALLOW_ALL}" ]; then
    echo "PASS: No wildcard ingress rules found"
else
    echo "${ALLOW_ALL}"
fi

# 2. kubescape — overpermissive policies
echo ""
echo "--- kubescape scan ---"
KUBESCAPE_OUT="/tmp/cm7-kubescape-${TIMESTAMP}.json"
kubescape scan --format json --output "${KUBESCAPE_OUT}" 2>/dev/null || true
echo "kubescape output saved to ${KUBESCAPE_OUT}"

# 3. polaris — network audit
echo ""
echo "--- polaris audit ---"
POLARIS_OUT="/tmp/cm7-polaris-${TIMESTAMP}.json"
polaris audit --format json > "${POLARIS_OUT}" 2>/dev/null || true
echo "polaris output saved to ${POLARIS_OUT}"

# Copy to evidence dir if set
if [ -n "${EVIDENCE_DIR}" ]; then
    mkdir -p "${EVIDENCE_DIR}"
    cp "${KUBESCAPE_OUT}" "${EVIDENCE_DIR}/cm7-kubescape.json"
    cp "${POLARIS_OUT}" "${EVIDENCE_DIR}/cm7-polaris.json"
    kubectl get networkpolicy -n "${NAMESPACE}" -o json > "${EVIDENCE_DIR}/cm7-netpol-state.json"
    echo ""
    echo "Evidence saved to ${EVIDENCE_DIR}/"
fi

echo ""
echo "=== CM-7 Detect complete ==="
```

- [ ] **Step 4: Create the evidence template**

Create `scenarios/CM-7-least-functionality/evidence-template.md`:

```markdown
# CM-7 Least Functionality — Evidence

**NIST Control:** CM-7 Least Functionality
**OSI Layer:** L3 Network
**5 C's Package:** 02-CLUSTER-HARDEN
**Control Type:** Preventive

## Break

**Action:** Added wildcard ingress rule allowing all pod-to-pod traffic.

**Command:** `bash scenarios/CM-7-least-functionality/break.sh`

**Before state (secure — SC-7 policies in place):**
<!-- Paste: kubectl get netpol -n anthra -o wide -->
```
```

**After break (wildcard added):**
<!-- Paste: kubectl get netpol -n anthra -o wide -->
```
```

## Detection

**Tools:** kubescape (full scan), polaris (audit)

**Wildcard check:**
<!-- Paste: output from kubectl wildcard check -->
```
```

**kubescape results:**
<!-- Paste: key findings from cm7-kubescape.json -->
```
```

**polaris results:**
<!-- Paste: key findings from cm7-polaris.json -->
```
```

## Fix

**Action:** Removed wildcard ingress rule, leaving per-service rules intact.

**Command:** `bash scenarios/CM-7-least-functionality/fix.sh`

**After state (remediated):**
<!-- Paste: kubectl get netpol -n anthra -o wide -->
```
```

## Evidence Files

| File | Description | SHA256 |
|------|-------------|--------|
| `cm7-netpol-state.json` | kubectl netpol dump | |
| `cm7-kubescape.json` | kubescape full scan | |
| `cm7-polaris.json` | polaris audit | |
```

- [ ] **Step 5: Make scripts executable and commit**

```bash
chmod +x scenarios/CM-7-least-functionality/{break,detect,fix}.sh
git add scenarios/CM-7-least-functionality/
git commit -m "scenario: CM-7 least functionality break/detect/fix"
```

---

## Task 4: AC-6 Least Privilege Scenario

**Files:**
- Create: `scenarios/AC-6-least-privilege/break.sh`
- Create: `scenarios/AC-6-least-privilege/detect.sh`
- Create: `scenarios/AC-6-least-privilege/fix.sh`
- Create: `scenarios/AC-6-least-privilege/evidence-template.md`

- [ ] **Step 1: Create the fix script**

Create `scenarios/AC-6-least-privilege/fix.sh`:

```bash
#!/usr/bin/env bash
# AC-6 Least Privilege — Fix
# NIST 800-53: AC-6 | Layer: L3 Cluster | Package: 02-CLUSTER-HARDEN
# Type: Preventive
#
# Removes cluster-admin binding from default SA and scopes it to
# namespace-level read-only. Idempotent.

set -euo pipefail

NAMESPACE="anthra"

echo "=== AC-6 Fix: Removing overprivileged SA binding ==="

# Remove the dangerous ClusterRoleBinding
kubectl delete clusterrolebinding seclab-default-sa-cluster-admin --ignore-not-found

# Create namespace-scoped read-only Role and RoleBinding
cat <<'EOF' | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: seclab-readonly
  namespace: anthra
  labels:
    seclab-scenario: AC-6
rules:
  - apiGroups: [""]
    resources: ["pods", "services", "configmaps"]
    verbs: ["get", "list", "watch"]
EOF

cat <<'EOF' | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: seclab-default-sa-readonly
  namespace: anthra
  labels:
    seclab-scenario: AC-6
subjects:
  - kind: ServiceAccount
    name: default
    namespace: anthra
roleRef:
  kind: Role
  name: seclab-readonly
  apiGroup: rbac.authorization.k8s.io
EOF

echo "=== AC-6 Fix complete ==="
echo ""
echo "ClusterRoleBindings for default SA:"
kubectl get clusterrolebinding -o json | python3 -c "
import sys, json
data = json.load(sys.stdin)
for item in data.get('items', []):
    for subj in item.get('subjects', []):
        if subj.get('name') == 'default' and subj.get('namespace') == 'anthra':
            print(f\"  {item['metadata']['name']} -> {item['roleRef']['name']}\")
" 2>/dev/null || echo "  (none)"
echo ""
echo "RoleBindings in ${NAMESPACE}:"
kubectl get rolebinding -n "${NAMESPACE}" -l seclab-scenario=AC-6 -o wide
```

- [ ] **Step 2: Create the break script**

Create `scenarios/AC-6-least-privilege/break.sh`:

```bash
#!/usr/bin/env bash
# AC-6 Least Privilege — Break
# NIST 800-53: AC-6 | Layer: L3 Cluster | Package: 02-CLUSTER-HARDEN
#
# Binds the default service account in anthra namespace to cluster-admin.
# This gives every pod in the namespace full cluster access. Idempotent.

set -euo pipefail

NAMESPACE="anthra"

echo "=== AC-6 Break: Binding default SA to cluster-admin ==="

cat <<'EOF' | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: seclab-default-sa-cluster-admin
  labels:
    seclab-scenario: AC-6
subjects:
  - kind: ServiceAccount
    name: default
    namespace: anthra
roleRef:
  kind: ClusterRole
  name: cluster-admin
  apiGroup: rbac.authorization.k8s.io
EOF

echo "=== AC-6 Break complete — default SA is now cluster-admin ==="
echo ""
echo "Verify — can default SA create deployments cluster-wide?"
kubectl auth can-i create deployments --as=system:serviceaccount:anthra:default -A
```

- [ ] **Step 3: Create the detect script**

Create `scenarios/AC-6-least-privilege/detect.sh`:

```bash
#!/usr/bin/env bash
# AC-6 Least Privilege — Detect
# NIST 800-53: AC-6 | Layer: L3 Cluster | Package: 02-CLUSTER-HARDEN
#
# Detection tools:
#   1. kubectl auth can-i — verify SA permissions directly
#   2. kubescape — RBAC risk controls (C-0035 cluster-admin binding)
#   3. kubectl — dump ClusterRoleBindings for evidence
#
# Outputs JSON evidence to stdout or to $EVIDENCE_DIR if set.

set -euo pipefail

NAMESPACE="anthra"
EVIDENCE_DIR="${EVIDENCE_DIR:-}"
TIMESTAMP="$(date -u +%Y-%m-%dT%H%M%SZ)"

echo "=== AC-6 Detect: Checking least privilege ==="

# 1. Direct check — can default SA do things it shouldn't?
echo ""
echo "--- kubectl auth can-i check ---"
SA="system:serviceaccount:anthra:default"
CHECKS=(
    "create deployments"
    "delete pods"
    "get secrets"
    "create clusterrolebindings"
)
FAIL_COUNT=0
for CHECK in "${CHECKS[@]}"; do
    RESULT=$(kubectl auth can-i ${CHECK} --as="${SA}" -A 2>/dev/null || true)
    if [ "${RESULT}" = "yes" ]; then
        echo "FAIL: ${SA} can ${CHECK} (cluster-wide)"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    else
        echo "PASS: ${SA} cannot ${CHECK} (cluster-wide)"
    fi
done
echo ""
echo "${FAIL_COUNT} privilege escalation(s) detected"

# 2. kubescape — RBAC controls
echo ""
echo "--- kubescape RBAC scan ---"
KUBESCAPE_OUT="/tmp/ac6-kubescape-${TIMESTAMP}.json"
kubescape scan control C-0035,C-0188 --format json --output "${KUBESCAPE_OUT}" 2>/dev/null || true
echo "kubescape output saved to ${KUBESCAPE_OUT}"

# 3. ClusterRoleBinding dump
echo ""
echo "--- ClusterRoleBinding check ---"
CRB_OUT="/tmp/ac6-crb-${TIMESTAMP}.json"
kubectl get clusterrolebinding -o json | python3 -c "
import sys, json
data = json.load(sys.stdin)
findings = []
for item in data.get('items', []):
    for subj in item.get('subjects', []):
        if subj.get('name') == 'default' and subj.get('namespace') == 'anthra':
            findings.append({
                'binding': item['metadata']['name'],
                'role': item['roleRef']['name'],
                'sa': f\"{subj['namespace']}/{subj['name']}\"
            })
json.dump(findings, sys.stdout, indent=2)
" > "${CRB_OUT}" 2>/dev/null || echo '[]' > "${CRB_OUT}"
echo "ClusterRoleBindings for anthra/default:"
cat "${CRB_OUT}"

# Copy to evidence dir if set
if [ -n "${EVIDENCE_DIR}" ]; then
    mkdir -p "${EVIDENCE_DIR}"
    cp "${KUBESCAPE_OUT}" "${EVIDENCE_DIR}/ac6-kubescape.json"
    cp "${CRB_OUT}" "${EVIDENCE_DIR}/ac6-crb-state.json"
    echo ""
    echo "Evidence saved to ${EVIDENCE_DIR}/"
fi

echo ""
echo "=== AC-6 Detect complete ==="
```

- [ ] **Step 4: Create the evidence template**

Create `scenarios/AC-6-least-privilege/evidence-template.md`:

```markdown
# AC-6 Least Privilege — Evidence

**NIST Control:** AC-6 Least Privilege
**OSI Layer:** L3 Cluster
**5 C's Package:** 02-CLUSTER-HARDEN
**Control Type:** Preventive

## Break

**Action:** Bound default service account to cluster-admin ClusterRole.

**Command:** `bash scenarios/AC-6-least-privilege/break.sh`

**Before state (secure):**
<!-- Paste: kubectl auth can-i output showing denied -->
```
```

## Detection

**Tools:** kubectl auth can-i, kubescape (C-0035, C-0188)

**auth can-i results:**
<!-- Paste: privilege check output -->
```
```

**kubescape results:**
<!-- Paste: RBAC control findings from ac6-kubescape.json -->
```
```

**ClusterRoleBinding state:**
<!-- Paste: ac6-crb-state.json contents -->
```
```

## Fix

**Action:** Removed cluster-admin binding. Created namespace-scoped read-only Role.

**Command:** `bash scenarios/AC-6-least-privilege/fix.sh`

**After state (remediated):**
<!-- Paste: kubectl auth can-i output showing denied -->
```
```

## Evidence Files

| File | Description | SHA256 |
|------|-------------|--------|
| `ac6-crb-state.json` | ClusterRoleBinding dump | |
| `ac6-kubescape.json` | kubescape RBAC scan | |
```

- [ ] **Step 5: Make scripts executable and commit**

```bash
chmod +x scenarios/AC-6-least-privilege/{break,detect,fix}.sh
git add scenarios/AC-6-least-privilege/
git commit -m "scenario: AC-6 least privilege break/detect/fix"
```

---

## Task 5: Evidence Collection Pipeline

**Files:**
- Create: `tools/collect-evidence.sh`

- [ ] **Step 1: Create the evidence collection script**

Create `tools/collect-evidence.sh`:

```bash
#!/usr/bin/env bash
# Evidence Collection Pipeline
# Runs all scenario detections, collects output to evidence/YYYY-MM-DD/,
# generates SHA256 manifest, and appends findings to POA&M.
#
# Usage:
#   bash tools/collect-evidence.sh              # Run all scenarios
#   bash tools/collect-evidence.sh SC-7         # Run one scenario
#   bash tools/collect-evidence.sh --fix-first  # Run fix, then detect (baseline)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "${SCRIPT_DIR}")"
DATE="$(date -u +%Y-%m-%d)"
EVIDENCE_DIR="${PROJECT_DIR}/evidence/${DATE}"
SCENARIO_DIR="${PROJECT_DIR}/scenarios"
POAM_FILE="${PROJECT_DIR}/docs/poam-template.md"

FIX_FIRST="${1:-}"
TARGET_SCENARIO="${1:-all}"

# Handle --fix-first flag
if [ "${FIX_FIRST}" = "--fix-first" ]; then
    FIX_FIRST="yes"
    TARGET_SCENARIO="${2:-all}"
else
    FIX_FIRST="no"
fi

mkdir -p "${EVIDENCE_DIR}"

echo "============================================"
echo "Evidence Collection Pipeline"
echo "Date: ${DATE}"
echo "Output: ${EVIDENCE_DIR}/"
echo "Target: ${TARGET_SCENARIO}"
echo "Fix first: ${FIX_FIRST}"
echo "============================================"
echo ""

# Collect scenarios to run
SCENARIOS=()
if [ "${TARGET_SCENARIO}" = "all" ]; then
    for dir in "${SCENARIO_DIR}"/*/; do
        [ -d "${dir}" ] && SCENARIOS+=("$(basename "${dir}")")
    done
else
    # Match by control ID prefix (e.g., "SC-7" matches "SC-7-boundary-protection")
    for dir in "${SCENARIO_DIR}"/${TARGET_SCENARIO}*/; do
        [ -d "${dir}" ] && SCENARIOS+=("$(basename "${dir}")")
    done
fi

if [ ${#SCENARIOS[@]} -eq 0 ]; then
    echo "ERROR: No scenarios found matching '${TARGET_SCENARIO}'"
    exit 1
fi

PASS_COUNT=0
FAIL_COUNT=0

for SCENARIO in "${SCENARIOS[@]}"; do
    SCENARIO_PATH="${SCENARIO_DIR}/${SCENARIO}"
    CONTROL_ID="${SCENARIO%%-*}-${SCENARIO#*-}"
    CONTROL_ID="${SCENARIO%%[-_]*}-$(echo "${SCENARIO}" | cut -d'-' -f2)"

    echo ""
    echo "============================================"
    echo "Scenario: ${SCENARIO}"
    echo "============================================"

    # Run fix first if requested (establishes secure baseline)
    if [ "${FIX_FIRST}" = "yes" ] && [ -x "${SCENARIO_PATH}/fix.sh" ]; then
        echo ""
        echo "--- Running fix (baseline) ---"
        bash "${SCENARIO_PATH}/fix.sh" || true
    fi

    # Run detection
    if [ -x "${SCENARIO_PATH}/detect.sh" ]; then
        echo ""
        echo "--- Running detection ---"
        EVIDENCE_DIR="${EVIDENCE_DIR}" bash "${SCENARIO_PATH}/detect.sh" || true
    else
        echo "WARNING: No detect.sh found for ${SCENARIO}"
    fi
done

# Generate SHA256 manifest
echo ""
echo "============================================"
echo "Generating SHA256 manifest"
echo "============================================"
MANIFEST="${EVIDENCE_DIR}/SHA256SUMS"
if compgen -G "${EVIDENCE_DIR}/*.json" > /dev/null 2>&1; then
    (cd "${EVIDENCE_DIR}" && sha256sum *.json > SHA256SUMS)
    echo "Manifest written to ${MANIFEST}"
    cat "${MANIFEST}"
else
    echo "No evidence files found — check tool output above for errors"
fi

echo ""
echo "============================================"
echo "Evidence collection complete: ${EVIDENCE_DIR}/"
echo "============================================"
ls -la "${EVIDENCE_DIR}/"
```

- [ ] **Step 2: Make executable and commit**

```bash
chmod +x tools/collect-evidence.sh
git add tools/collect-evidence.sh
git commit -m "tools: add evidence collection pipeline with SHA256 manifest"
```

---

## Task 6: Integration Test — Full Cycle

This task runs the full break/detect/fix cycle once to verify everything works against the live cluster. No files created — just execution and verification.

- [ ] **Step 1: Run SC-7 fix to establish baseline**

```bash
cd /home/jimmie/linkops-industries/GP-copilot/GP-PROJECTS/01-instance/slot-3/Anthra-SecLAB
bash scenarios/SC-7-boundary-protection/fix.sh
```

Expected: 5 NetworkPolicies created in anthra namespace.

- [ ] **Step 2: Run SC-7 break**

```bash
bash scenarios/SC-7-boundary-protection/break.sh
```

Expected: All NetworkPolicies deleted. `kubectl get netpol -n anthra` returns empty.

- [ ] **Step 3: Run SC-7 detect**

```bash
EVIDENCE_DIR=evidence/test bash scenarios/SC-7-boundary-protection/detect.sh
```

Expected: "FAIL: No NetworkPolicies" message. kube-hunter and kubescape output saved to evidence/test/.

- [ ] **Step 4: Run SC-7 fix again**

```bash
bash scenarios/SC-7-boundary-protection/fix.sh
```

Expected: Policies restored. Idempotent — no errors.

- [ ] **Step 5: Run full evidence pipeline**

```bash
bash tools/collect-evidence.sh
```

Expected: All three scenarios run detection. Evidence files in `evidence/YYYY-MM-DD/`. SHA256SUMS manifest generated.

- [ ] **Step 6: Verify evidence files exist**

```bash
ls -la evidence/$(date -u +%Y-%m-%d)/
cat evidence/$(date -u +%Y-%m-%d)/SHA256SUMS
```

Expected: JSON files from each scenario's detect script, plus SHA256SUMS.

- [ ] **Step 7: Clean up test evidence and commit any fixes**

```bash
rm -rf evidence/test
```

If any scripts needed fixes during testing, commit them:

```bash
git add -A scenarios/ tools/
git commit -m "fix: adjust scripts after integration test"
```

---

## Execution Order & Dependencies

```
Task 1 (docs)        — no dependencies
Task 2 (SC-7)        — no dependencies
Task 3 (CM-7)        — depends on SC-7 fix existing (runtime dep, not build dep)
Task 4 (AC-6)        — no dependencies
Task 5 (pipeline)    — depends on scenario dirs existing
Task 6 (integration) — depends on all above
```

Tasks 1–4 can be built in parallel. Task 5 needs at least one scenario dir. Task 6 is sequential end-to-end.
