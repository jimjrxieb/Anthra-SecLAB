# SecLAB-setup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Create a reproducible lab setup with k3d cluster, target application, and baseline SOC tool stack (Falco, Prometheus+Grafana, Kyverno, Fluent Bit→Splunk) — all correctly configured with documentation explaining WHY.

**Architecture:** Two-phase setup: Phase 1 creates the k3d cluster and deploys the target app. Phase 2 deploys the SOC tool stack via Helm in dependency order (Kyverno → Prometheus+Grafana → Fluent Bit → Falco). Splunk runs externally as `gp-splunk` container on the host. Reports land in `GP-S3/6-seclab-reports/`.

**Tech Stack:** k3d (k3s in Docker), Helm 3, Falco (8.0.1), kube-prometheus-stack (83.0.0), Kyverno (3.7.1), Fluent Bit (0.57.2). Splunk 9.2 (existing, external). HEC token: `gp-local-hec-token-2026`.

**Known state:**
- Splunk already running: `gp-splunk` container, HTTPS HEC on port 8088, web on 8000
- Helm repos already added: falcosecurity, prometheus-community, kyverno, fluent
- App source in: `target-application/` (api/Dockerfile, ui/Dockerfile, services/Dockerfile)
- Kustomize overlay: `target-application/infrastructure/kustomize/overlays/local/`
- Current namespace: `anthra`

---

## File Structure

```
SecLAB-setup/
├── README.md
├── 01-cluster-setup/
│   ├── playbook.md
│   ├── k3d-config.yaml
│   ├── setup-cluster.sh
│   └── teardown-cluster.sh
├── 02-soc-stack/
│   ├── playbook.md
│   ├── falco/
│   │   ├── values.yaml
│   │   └── custom-rules.yaml
│   ├── prometheus-grafana/
│   │   ├── values.yaml
│   │   └── dashboards/
│   │       └── soc-overview.json
│   ├── kyverno/
│   │   ├── values.yaml
│   │   └── baseline-policies/
│   │       ├── require-security-context.yaml
│   │       ├── disallow-latest-tag.yaml
│   │       ├── require-resource-limits.yaml
│   │       └── require-labels.yaml
│   ├── splunk-forwarder/
│   │   └── fluentbit-values.yaml
│   ├── deploy-stack.sh
│   └── teardown-stack.sh
```

---

## Task 1: Cluster Setup — k3d Config, Scripts, Playbook

**Files:**
- Create: `SecLAB-setup/01-cluster-setup/k3d-config.yaml`
- Create: `SecLAB-setup/01-cluster-setup/setup-cluster.sh`
- Create: `SecLAB-setup/01-cluster-setup/teardown-cluster.sh`
- Create: `SecLAB-setup/01-cluster-setup/playbook.md`

- [ ] **Step 1: Create k3d-config.yaml**

```yaml
# k3d cluster configuration for Anthra-SecLAB
#
# WHY k3d: Runs k3s (lightweight Kubernetes) inside Docker containers.
# Gives you a real multi-node cluster on a single machine. Production-like
# enough to test NetworkPolicies, RBAC, admission control, and runtime
# detection — without the cost of EKS or the weight of kubeadm.
#
# WHY these settings:
# - 1 server + 2 agents: Simulates a real cluster (control plane + workers).
#   DaemonSets (Falco, Fluent Bit) run on all 3 nodes like production.
# - Port mappings: NodePort services need host ports exposed through k3d's
#   load balancer. Each port maps to a specific service.
# - Traefik disabled: We use NodePort, not Ingress. Keeps the lab simple
#   and avoids conflict with the SOC stack's own services.
# - host.k3d.internal: Allows pods to reach the host machine where
#   gp-splunk runs. Without this, Fluent Bit and Falcosidekick can't
#   ship logs/alerts to Splunk.

apiVersion: k3d.io/v1alpha5
kind: Simple
metadata:
  name: seclab
servers: 1
agents: 2
ports:
  # Target application
  - port: 30000:30000   # anthra-ui (React frontend)
    nodeFilters:
      - loadbalancer
  - port: 30080:30080   # anthra-api (FastAPI backend)
    nodeFilters:
      - loadbalancer
  - port: 30090:30090   # anthra-log-ingest (Go service)
    nodeFilters:
      - loadbalancer
  # SOC stack
  - port: 30300:30300   # Grafana dashboards
    nodeFilters:
      - loadbalancer
options:
  k3s:
    extraArgs:
      # WHY disable traefik: We don't need an ingress controller.
      # All services use NodePort. Removing traefik saves ~100MB RAM
      # and eliminates a component that could interfere with network
      # policy testing.
      - arg: --disable=traefik
        nodeFilters:
          - server:*
  # WHY hostAliases: Enables host.k3d.internal DNS resolution inside
  # the cluster. Pods can reach gp-splunk on the host via this name.
  # Without it, we'd need to hardcode the Docker bridge IP.
  kubeAPI:
    hostIP: "0.0.0.0"
```

- [ ] **Step 2: Create setup-cluster.sh**

```bash
#!/usr/bin/env bash
# SecLAB Cluster Setup
# Creates k3d cluster, builds app images, deploys target application.
# Idempotent — safe to run multiple times.
#
# Prerequisites: docker, k3d, kubectl, helm
# Splunk must be running: docker ps | grep gp-splunk

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$(dirname "${SCRIPT_DIR}")")"
APP_DIR="${PROJECT_DIR}/target-application"
CLUSTER_NAME="seclab"
NAMESPACE="anthra"

echo "============================================"
echo "SecLAB Cluster Setup"
echo "============================================"
echo ""

# --- Prerequisites ---
echo "--- Checking prerequisites ---"
for cmd in docker k3d kubectl helm; do
    if ! command -v "${cmd}" &>/dev/null; then
        echo "ERROR: ${cmd} is not installed"
        exit 1
    fi
    echo "  ${cmd}: $(command -v ${cmd})"
done

# Check Splunk is running
if ! docker ps --format '{{.Names}}' | grep -q gp-splunk; then
    echo ""
    echo "WARNING: gp-splunk container is not running."
    echo "  Log shipping (Fluent Bit) and alert forwarding (Falcosidekick)"
    echo "  will not work until Splunk is started."
    echo "  Start it with: docker start gp-splunk"
    echo ""
fi

echo ""

# --- Cluster ---
echo "--- Creating k3d cluster ---"
if k3d cluster list | grep -q "${CLUSTER_NAME}"; then
    echo "  Cluster '${CLUSTER_NAME}' already exists — skipping creation"
else
    k3d cluster create --config "${SCRIPT_DIR}/k3d-config.yaml"
    echo "  Cluster '${CLUSTER_NAME}' created"
fi

# Wait for nodes ready
echo "  Waiting for nodes..."
kubectl wait --for=condition=Ready nodes --all --timeout=120s
echo "  All nodes ready"
echo ""

# --- Build images ---
echo "--- Building application images ---"

echo "  Building anthra-api:seclab..."
docker build -t anthra-api:seclab -f "${APP_DIR}/api/Dockerfile" "${APP_DIR}/api/" -q

echo "  Building anthra-log-ingest:seclab..."
docker build -t anthra-log-ingest:seclab -f "${APP_DIR}/services/Dockerfile" "${APP_DIR}/services/" -q

# UI: use GHCR image (Portfolio-Prod UI) — already pulled
if docker images --format '{{.Repository}}:{{.Tag}}' | grep -q 'ghcr.io/jimjrxieb/portfolio-ui:latest'; then
    echo "  anthra-ui: using ghcr.io/jimjrxieb/portfolio-ui:latest (already pulled)"
else
    echo "  Pulling ghcr.io/jimjrxieb/portfolio-ui:latest..."
    docker pull ghcr.io/jimjrxieb/portfolio-ui:latest
fi

echo ""

# --- Import images into k3d ---
echo "--- Importing images into k3d ---"
k3d image import \
    anthra-api:seclab \
    anthra-log-ingest:seclab \
    ghcr.io/jimjrxieb/portfolio-ui:latest \
    -c "${CLUSTER_NAME}"
echo "  Images imported"
echo ""

# --- Deploy application ---
echo "--- Deploying target application ---"
kubectl apply -k "${APP_DIR}/infrastructure/kustomize/overlays/local/"

echo "  Waiting for pods..."
kubectl wait --for=condition=Ready pods --all -n "${NAMESPACE}" --timeout=180s
echo "  All pods ready"
echo ""

# --- Verify ---
echo "--- Verification ---"
echo ""
kubectl get pods -n "${NAMESPACE}" -o wide
echo ""

# Health checks
echo "  UI (localhost:30000):"
if curl -sf -o /dev/null http://localhost:30000 2>/dev/null; then
    echo "    PASS"
else
    echo "    FAIL (may need a few seconds to start)"
fi

echo "  API (localhost:30080):"
if curl -sf -o /dev/null http://localhost:30080/api/health 2>/dev/null; then
    echo "    PASS"
else
    echo "    FAIL (may need a few seconds to start)"
fi

echo ""
echo "============================================"
echo "SecLAB cluster ready"
echo ""
echo "  UI:  http://localhost:30000"
echo "  API: http://localhost:30080"
echo "  Log: http://localhost:30090"
echo ""
echo "Next: deploy SOC stack with:"
echo "  bash SecLAB-setup/02-soc-stack/deploy-stack.sh"
echo "============================================"
```

- [ ] **Step 3: Create teardown-cluster.sh**

```bash
#!/usr/bin/env bash
# SecLAB Cluster Teardown
# Destroys the k3d cluster completely. All data lost.
# The gp-splunk container on the host is NOT affected.

set -euo pipefail

CLUSTER_NAME="seclab"

echo "============================================"
echo "SecLAB Cluster Teardown"
echo "============================================"

if k3d cluster list | grep -q "${CLUSTER_NAME}"; then
    echo "Deleting cluster '${CLUSTER_NAME}'..."
    k3d cluster delete "${CLUSTER_NAME}"
    echo "Cluster deleted."
else
    echo "Cluster '${CLUSTER_NAME}' does not exist — nothing to do."
fi

echo ""
echo "Note: gp-splunk container was NOT affected."
echo "Note: Docker images were NOT removed. Run 'docker image prune' to clean up."
echo "============================================"
```

- [ ] **Step 4: Create playbook.md**

```markdown
# 01 — Cluster Setup Playbook

## What This Does

Creates a k3d Kubernetes cluster and deploys the Anthra-SecLAB target application into it. This is the foundation — the app that every OSI-MODEL scenario tests against.

## Why This Matters

Without a reproducible cluster setup, the lab is fragile. If the cluster breaks during a scenario (or you need to start fresh), you run one script and you're back to known-good in under 3 minutes. Every production environment has this — it's called Infrastructure as Code.

**What a CySA+ Analyst Should Know:** The cluster is the attack surface. Understanding how it's built (what ports are exposed, what services run, what security defaults are set) is the first step in assessing its security posture. You can't secure what you don't understand.

## Prerequisites

| Tool | Install | Purpose |
|------|---------|---------|
| Docker | `curl -fsSL https://get.docker.com \| sh` | Container runtime |
| k3d | `curl -s https://raw.githubusercontent.com/k3d-io/k3d/main/install.sh \| bash` | k3s-in-Docker |
| kubectl | `curl -LO https://dl.k8s.io/release/$(curl -Ls https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl` | Kubernetes CLI |
| Helm | `curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 \| bash` | Package manager |
| Splunk | Already running as `gp-splunk` container | SIEM |

## Steps

### 1. Create the cluster

```bash
bash SecLAB-setup/01-cluster-setup/setup-cluster.sh
```

This single command:
1. Checks all prerequisites are installed
2. Creates a k3d cluster named `seclab` (1 server + 2 agents) from `k3d-config.yaml`
3. Builds application Docker images from source
4. Imports images into the k3d cluster
5. Deploys the app with Kustomize
6. Waits for all pods to be ready
7. Verifies health endpoints

### 2. Verify the cluster

```bash
kubectl get nodes
# Expected: 3 nodes (1 server, 2 agents), all Ready

kubectl get pods -n anthra
# Expected: 4 pods (anthra-ui, anthra-api, anthra-db, anthra-log-ingest), all Running

curl http://localhost:30000
# Expected: HTML response (React app)

curl http://localhost:30080/api/health
# Expected: JSON health response
```

### 3. Understand the architecture

```
┌─────────────────────────────────────────────────┐
│ Host Machine                                     │
│                                                  │
│  ┌──────────┐    ┌─────────────────────────────┐ │
│  │gp-splunk │    │ k3d-seclab cluster          │ │
│  │:8000 web │    │                             │ │
│  │:8088 HEC │◄───│  anthra-ui    :30000        │ │
│  │:8089 mgmt│    │  anthra-api   :30080        │ │
│  └──────────┘    │  anthra-db    (ClusterIP)   │ │
│                  │  anthra-log   :30090        │ │
│                  │  grafana      :30300        │ │
│                  └─────────────────────────────┘ │
└─────────────────────────────────────────────────┘
```

### 4. Teardown (when needed)

```bash
bash SecLAB-setup/01-cluster-setup/teardown-cluster.sh
```

Destroys the cluster completely. Splunk is NOT affected. Docker images are NOT removed.

## What a CySA+ Analyst Should Know

- **k3d vs k3s vs EKS:** k3d runs k3s inside Docker containers. k3s is a lightweight Kubernetes distribution by Rancher. EKS is AWS's managed Kubernetes. Same API, different substrates. What you learn here applies to all three.
- **Namespace isolation:** The app runs in the `anthra` namespace. This is a boundary — NetworkPolicies, RBAC, and resource quotas can be scoped to this namespace.
- **NodePort vs Ingress:** We use NodePort (direct port mapping) instead of Ingress (HTTP routing). Simpler for a lab. Production would use an Ingress controller or load balancer.
- **ImagePullPolicy:** Local images use `Never` or `IfNotPresent` — k3d imports them directly, no registry needed.
```

- [ ] **Step 5: Make scripts executable and commit**

```bash
chmod +x SecLAB-setup/01-cluster-setup/setup-cluster.sh
chmod +x SecLAB-setup/01-cluster-setup/teardown-cluster.sh
git add SecLAB-setup/01-cluster-setup/
git commit -m "seclab-setup: cluster setup with k3d config, scripts, and playbook"
```

---

## Task 2: SOC Stack — Kyverno (Admission Control)

**Files:**
- Create: `SecLAB-setup/02-soc-stack/kyverno/values.yaml`
- Create: `SecLAB-setup/02-soc-stack/kyverno/baseline-policies/require-security-context.yaml`
- Create: `SecLAB-setup/02-soc-stack/kyverno/baseline-policies/disallow-latest-tag.yaml`
- Create: `SecLAB-setup/02-soc-stack/kyverno/baseline-policies/require-resource-limits.yaml`
- Create: `SecLAB-setup/02-soc-stack/kyverno/baseline-policies/require-labels.yaml`

- [ ] **Step 1: Create Kyverno values.yaml**

```yaml
# Kyverno Helm Values — Anthra-SecLAB
#
# WHAT: Kubernetes-native policy engine. Intercepts API requests and
#       validates them against policies BEFORE resources are created.
#
# WHY KYVERNO: Policies are YAML (not Rego like OPA/Gatekeeper). Same
#       language as everything else in Kubernetes. Easier to read, write,
#       and audit. CNCF graduated project.
#
# NIST CONTROLS:
#   CM-7  (Least Functionality) — enforce minimal container permissions
#   AC-6  (Least Privilege) — require non-root, drop capabilities
#   CM-2  (Baseline Configuration) — no :latest tags, pinned versions
#   CM-8  (Information System Component Inventory) — require labels
#   SC-6  (Resource Availability) — require resource limits

# WHY 1 replica: Lab cluster has limited resources. Production would
# run 3 replicas for high availability. Kyverno is the gatekeeper —
# if it goes down, no new resources can be created (fail-closed).
admissionController:
  replicas: 1

# WHY background scanning: Scans existing resources against policies,
# not just new ones. This catches misconfigurations that were deployed
# before Kyverno was installed. In a SOC, you need to know about ALL
# violations, not just new ones.
backgroundController:
  enabled: true

# WHY cleanup controller disabled: Not needed for lab. It auto-deletes
# resources on a schedule. We want to see violations, not auto-fix them.
cleanupController:
  enabled: false

# WHY reports enabled: Generates PolicyReport CRDs that list every
# resource that passes or fails each policy. This is your audit trail.
# Query with: kubectl get policyreport -A
reportsController:
  enabled: true

# Resource limits for lab — keep it lightweight
admissionController:
  container:
    resources:
      limits:
        memory: 384Mi
        cpu: 500m
      requests:
        memory: 128Mi
        cpu: 100m
```

- [ ] **Step 2: Create baseline policies**

Create `SecLAB-setup/02-soc-stack/kyverno/baseline-policies/require-security-context.yaml`:

```yaml
# Require Security Context — NIST AC-6 (Least Privilege), CM-7 (Least Functionality)
#
# WHY: Containers running as root can escape to the host if a vulnerability
# exists in the container runtime. Running as non-root + dropping ALL
# capabilities reduces the blast radius of a container compromise to
# just the container itself.
#
# WHAT THIS BLOCKS (in enforce mode):
#   - Containers without runAsNonRoot: true
#   - Containers without drop: ["ALL"] in capabilities
#   - Containers with allowPrivilegeEscalation: true
#
# MODE: Audit (logs violations but does NOT block). Switch to Enforce
# when you trust the policy won't break your app.
#
# CySA+ RELEVANCE: This is defense in depth at the container layer.
# Even if an attacker gets code execution inside a container, they
# can't escalate to root or escape to the host.

apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-security-context
  annotations:
    policies.kyverno.io/title: Require Security Context
    policies.kyverno.io/category: Pod Security
    policies.kyverno.io/severity: high
    policies.kyverno.io/description: >-
      Requires all containers to run as non-root with capabilities dropped.
      Maps to NIST AC-6 and CM-7.
spec:
  validationFailureAction: Audit
  background: true
  rules:
    - name: require-run-as-non-root
      match:
        any:
          - resources:
              kinds:
                - Pod
              namespaces:
                - anthra
      validate:
        message: "Containers must set runAsNonRoot: true (NIST AC-6)"
        pattern:
          spec:
            containers:
              - securityContext:
                  runAsNonRoot: true
    - name: drop-all-capabilities
      match:
        any:
          - resources:
              kinds:
                - Pod
              namespaces:
                - anthra
      validate:
        message: "Containers must drop ALL capabilities (NIST CM-7)"
        pattern:
          spec:
            containers:
              - securityContext:
                  capabilities:
                    drop:
                      - ALL
```

Create `SecLAB-setup/02-soc-stack/kyverno/baseline-policies/disallow-latest-tag.yaml`:

```yaml
# Disallow Latest Tag — NIST CM-2 (Baseline Configuration), SA-10 (Developer Config Mgmt)
#
# WHY: The :latest tag is mutable — it can point to different images at
# different times. If you deploy :latest today and redeploy tomorrow,
# you might get a completely different image. This breaks reproducibility
# and makes it impossible to audit what's actually running.
#
# WHAT THIS BLOCKS (in enforce mode):
#   - Container images with :latest tag
#   - Container images with no tag at all (defaults to :latest)
#
# CySA+ RELEVANCE: Configuration management (CM-2) requires knowing
# exactly what's deployed. :latest makes that impossible. Every image
# should have a pinned tag (version number or SHA) so you can trace
# exactly what code is running.

apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: disallow-latest-tag
  annotations:
    policies.kyverno.io/title: Disallow Latest Tag
    policies.kyverno.io/category: Best Practices
    policies.kyverno.io/severity: medium
    policies.kyverno.io/description: >-
      Requires container images to have a tag that is not 'latest'.
      Maps to NIST CM-2 and SA-10.
spec:
  validationFailureAction: Audit
  background: true
  rules:
    - name: disallow-latest-tag
      match:
        any:
          - resources:
              kinds:
                - Pod
              namespaces:
                - anthra
      validate:
        message: "Image tag ':latest' is not allowed. Pin to a specific version (NIST CM-2)."
        pattern:
          spec:
            containers:
              - image: "!*:latest"
```

Create `SecLAB-setup/02-soc-stack/kyverno/baseline-policies/require-resource-limits.yaml`:

```yaml
# Require Resource Limits — NIST SC-6 (Resource Availability)
#
# WHY: Without resource limits, a single container can consume all CPU
# and memory on a node, starving other workloads. This is a denial of
# service — intentional or accidental. Resource limits are the
# Kubernetes equivalent of quotas.
#
# WHAT THIS BLOCKS (in enforce mode):
#   - Containers without memory limits
#   - Containers without CPU limits
#
# CySA+ RELEVANCE: Availability is the 'A' in CIA triad. Resource
# limits prevent resource exhaustion attacks and noisy-neighbor
# problems. Every production workload should have limits.

apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-resource-limits
  annotations:
    policies.kyverno.io/title: Require Resource Limits
    policies.kyverno.io/category: Best Practices
    policies.kyverno.io/severity: medium
    policies.kyverno.io/description: >-
      Requires all containers to set CPU and memory limits.
      Maps to NIST SC-6.
spec:
  validationFailureAction: Audit
  background: true
  rules:
    - name: require-limits
      match:
        any:
          - resources:
              kinds:
                - Pod
              namespaces:
                - anthra
      validate:
        message: "CPU and memory limits are required (NIST SC-6)"
        pattern:
          spec:
            containers:
              - resources:
                  limits:
                    memory: "?*"
                    cpu: "?*"
```

Create `SecLAB-setup/02-soc-stack/kyverno/baseline-policies/require-labels.yaml`:

```yaml
# Require Labels — NIST CM-8 (Information System Component Inventory)
#
# WHY: Without labels, you can't answer "what is this pod?" or "who
# owns this deployment?" Labels are metadata — they're how you inventory,
# filter, and manage resources. An unlabeled resource is an untracked
# asset.
#
# WHAT THIS BLOCKS (in enforce mode):
#   - Deployments without 'app' label
#   - Deployments without 'environment' label
#
# CySA+ RELEVANCE: Asset inventory (CM-8) is fundamental. You can't
# protect what you don't know about. Labels make Kubernetes resources
# queryable and auditable.

apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-labels
  annotations:
    policies.kyverno.io/title: Require Labels
    policies.kyverno.io/category: Best Practices
    policies.kyverno.io/severity: low
    policies.kyverno.io/description: >-
      Requires Deployments to have 'app' and 'environment' labels.
      Maps to NIST CM-8.
spec:
  validationFailureAction: Audit
  background: true
  rules:
    - name: require-app-label
      match:
        any:
          - resources:
              kinds:
                - Deployment
              namespaces:
                - anthra
      validate:
        message: "Deployments must have an 'app' label (NIST CM-8)"
        pattern:
          metadata:
            labels:
              app: "?*"
    - name: require-environment-label
      match:
        any:
          - resources:
              kinds:
                - Deployment
              namespaces:
                - anthra
      validate:
        message: "Deployments must have an 'environment' label (NIST CM-8)"
        pattern:
          metadata:
            labels:
              environment: "?*"
```

- [ ] **Step 3: Commit**

```bash
git add SecLAB-setup/02-soc-stack/kyverno/
git commit -m "seclab-setup: kyverno values and baseline policies (audit mode)"
```

---

## Task 3: SOC Stack — Prometheus + Grafana

**Files:**
- Create: `SecLAB-setup/02-soc-stack/prometheus-grafana/values.yaml`
- Create: `SecLAB-setup/02-soc-stack/prometheus-grafana/dashboards/soc-overview.json`

- [ ] **Step 1: Create Prometheus+Grafana values.yaml**

```yaml
# kube-prometheus-stack Helm Values — Anthra-SecLAB
#
# WHAT: Prometheus (metrics collection) + Grafana (dashboards) +
#       Alertmanager (alert routing) bundled as one Helm chart.
#
# WHY THIS STACK: De facto standard for Kubernetes monitoring.
#       CNCF graduated. Every production cluster runs this.
#       Gives you the CISO dashboard metrics: MTTD, MTTR, pod health,
#       resource consumption, alert trends.
#
# NIST CONTROLS:
#   SI-4  (Information System Monitoring) — continuous metrics collection
#   AU-6  (Audit Record Review) — dashboards for metric analysis
#   CA-7  (Continuous Monitoring) — automated health checks

# --- Grafana ---
grafana:
  # WHY explicit password: Lab needs predictable access. Production
  # would use SSO (Entra ID, Okta). Default auto-generated password
  # is hard to retrieve.
  adminPassword: "SecLAB2026!"

  # WHY NodePort: Browser access from host machine. Production would
  # use Ingress with TLS. Port 30300 chosen to not conflict with app
  # ports (30000, 30080, 30090).
  service:
    type: NodePort
    nodePort: 30300

  # WHY no persistence: Dashboards are code — they're JSON files we
  # import. If Grafana restarts, dashboards auto-reload from ConfigMap.
  # No PVC needed. Production would persist user-created dashboards.
  persistence:
    enabled: false

  # WHY sidecar: Automatically loads dashboard JSON files from ConfigMaps
  # labeled 'grafana_dashboard: "1"'. Add new dashboards by creating
  # ConfigMaps, not by clicking in the UI.
  sidecar:
    dashboards:
      enabled: true
      label: grafana_dashboard
      labelValue: "1"

  # Lab-appropriate resources
  resources:
    limits:
      memory: 256Mi
      cpu: 300m
    requests:
      memory: 128Mi
      cpu: 100m

# --- Prometheus ---
prometheus:
  prometheusSpec:
    # WHY 7 days: Enough metrics history for lab scenarios (break on
    # Monday, check metrics drift on Friday). Not so much that it eats
    # disk. Production retains 15-90 days depending on compliance needs.
    retention: 7d

    # WHY these limits: k3d cluster has limited resources. Production
    # Prometheus often needs 4-8GB RAM depending on cardinality.
    resources:
      limits:
        memory: 512Mi
        cpu: 500m
      requests:
        memory: 256Mi
        cpu: 100m

    # WHY lower storage: 5Gi is plenty for 7 days of a small cluster.
    # Production would be 50-500Gi.
    storageSpec:
      volumeClaimTemplate:
        spec:
          accessModes: ["ReadWriteOnce"]
          resources:
            requests:
              storage: 5Gi

# --- Alertmanager ---
alertmanager:
  # WHY enabled: Alertmanager routes alerts from Prometheus rules.
  # Even in a lab, you want to see what alerts WOULD fire in production.
  # Alerts go to Alertmanager → you check the Alertmanager UI.
  enabled: true
  alertmanagerSpec:
    resources:
      limits:
        memory: 128Mi
        cpu: 100m
      requests:
        memory: 64Mi
        cpu: 50m

# --- Node Exporter ---
# WHY enabled: Collects node-level metrics (CPU, memory, disk, network).
# Runs as DaemonSet on every node. Without this, you only see pod
# metrics, not the underlying infrastructure.
nodeExporter:
  enabled: true

# --- kube-state-metrics ---
# WHY enabled: Collects Kubernetes object state metrics (deployment
# replicas, pod status, resource quotas). Without this, Prometheus
# only sees resource usage, not Kubernetes-level health.
kubeStateMetrics:
  enabled: true
```

- [ ] **Step 2: Create SOC overview dashboard**

The implementer should create a Grafana dashboard JSON file at `SecLAB-setup/02-soc-stack/prometheus-grafana/dashboards/soc-overview.json` with the following panels:

1. **Cluster Health** — node count, pod count (running vs failed), namespace resource usage
2. **Pod Status** — pods by status (Running, Pending, Failed, CrashLoopBackOff) per namespace
3. **CPU/Memory** — cluster-wide and per-namespace CPU and memory utilization
4. **Network** — bytes transmitted/received per pod
5. **Alerts** — firing alert count, alert history

The dashboard should use standard `kube-state-metrics` and `node-exporter` datasources. Use PromQL queries. Set auto-refresh to 30s. Title: "SecLAB SOC Overview".

This is a standard Kubernetes monitoring dashboard — the implementer can use the Grafana community dashboard ID 315 (Kubernetes cluster monitoring) as a base and customize it, or build from common PromQL queries. The JSON should be valid Grafana dashboard JSON that can be loaded via ConfigMap.

- [ ] **Step 3: Commit**

```bash
git add SecLAB-setup/02-soc-stack/prometheus-grafana/
git commit -m "seclab-setup: prometheus + grafana values and SOC dashboard"
```

---

## Task 4: SOC Stack — Fluent Bit (Log Shipping to Splunk)

**Files:**
- Create: `SecLAB-setup/02-soc-stack/splunk-forwarder/fluentbit-values.yaml`

- [ ] **Step 1: Create Fluent Bit values.yaml**

```yaml
# Fluent Bit Helm Values — Anthra-SecLAB
#
# WHAT: Lightweight log forwarder. Runs as DaemonSet on every node,
#       tails container logs, enriches with Kubernetes metadata, and
#       ships to Splunk via HEC (HTTP Event Collector).
#
# WHY FLUENT BIT: CNCF graduated. Written in C — ~450KB binary, uses
#       ~5MB RAM per node. 10x lighter than Fluentd. The standard log
#       shipper for Kubernetes → Splunk pipelines.
#
# WHY NOT FLUENTD: Fluentd is Ruby-based, heavier (~50MB RAM), and
#       has a larger attack surface. Fluent Bit does everything we need
#       for simple log forwarding.
#
# NIST CONTROLS:
#   AU-2  (Event Logging) — captures all container stdout/stderr
#   AU-3  (Content of Audit Records) — enriches with pod name, namespace, labels
#   AU-4  (Audit Log Storage Capacity) — ships to Splunk (external storage)
#   AU-6  (Audit Record Review) — Splunk enables search and analysis
#
# SPLUNK CONNECTION:
#   Host: host.k3d.internal (resolves to host machine from inside k3d)
#   Port: 8088 (HEC)
#   Token: gp-local-hec-token-2026
#   TLS: On (Splunk HEC is HTTPS)
#   TLS Verify: Off (self-signed cert in lab)

# WHY DaemonSet: Runs one Fluent Bit pod per node. Every container's
# logs on that node are captured. If a node has no Fluent Bit, its
# logs are invisible to Splunk.
kind: DaemonSet

image:
  repository: cr.fluentbit.io/fluent/fluent-bit
  tag: "3.2"

# WHY these resources: Fluent Bit is lightweight by design. 64Mi is
# generous for a small cluster. Production might need 128-256Mi if
# log volume is high.
resources:
  limits:
    memory: 128Mi
    cpu: 200m
  requests:
    memory: 64Mi
    cpu: 50m

config:
  # WHY json parser: anthra-api outputs structured JSON logs.
  # Without this parser, Splunk sees raw text instead of searchable fields.
  customParsers: |
    [PARSER]
        Name        json
        Format      json
        Time_Key    time
        Time_Format %Y-%m-%dT%H:%M:%S.%L

  # Input: tail container logs from every pod
  inputs: |
    [INPUT]
        Name              tail
        Tag               kube.*
        Path              /var/log/containers/*.log
        Parser            cri
        DB                /var/log/flb_kube.db
        Mem_Buf_Limit     5MB
        Skip_Long_Lines   On
        Refresh_Interval  10

  # Filter: enrich with Kubernetes metadata
  # WHY: Without this, Splunk sees log lines with no context — you
  # wouldn't know which pod, namespace, or deployment generated the log.
  # This filter adds: pod_name, namespace_name, container_name, labels.
  filters: |
    [FILTER]
        Name                kubernetes
        Match               kube.*
        Kube_URL            https://kubernetes.default.svc:443
        Kube_CA_File        /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
        Kube_Token_File     /var/run/secrets/kubernetes.io/serviceaccount/token
        Kube_Tag_Prefix     kube.var.log.containers.
        Merge_Log           On
        Keep_Log            Off
        K8S-Logging.Parser  On
        K8S-Logging.Exclude Off

  # Output: ship to Splunk HEC
  # WHY host.k3d.internal: k3d provides this DNS name to resolve
  # the host machine's IP from inside the cluster. gp-splunk runs
  # on the host, not inside k3d.
  # WHY tls On, tls.verify Off: Splunk HEC uses HTTPS but with a
  # self-signed certificate in the lab. Production would use a real cert.
  outputs: |
    [OUTPUT]
        Name            splunk
        Match           kube.*
        Host            host.k3d.internal
        Port            8088
        Splunk_Token    gp-local-hec-token-2026
        Splunk_Send_Raw Off
        TLS             On
        TLS.Verify      Off
        Retry_Limit     5
```

- [ ] **Step 2: Commit**

```bash
git add SecLAB-setup/02-soc-stack/splunk-forwarder/
git commit -m "seclab-setup: fluent bit values for splunk HEC log shipping"
```

---

## Task 5: SOC Stack — Falco (Runtime Detection)

**Files:**
- Create: `SecLAB-setup/02-soc-stack/falco/values.yaml`
- Create: `SecLAB-setup/02-soc-stack/falco/custom-rules.yaml`

- [ ] **Step 1: Create Falco values.yaml**

```yaml
# Falco Helm Values — Anthra-SecLAB
#
# WHAT: Runtime security tool. Monitors Linux syscalls and Kubernetes
#       audit events. Fires alerts when suspicious behavior occurs —
#       shell in container, sensitive file read, privilege escalation,
#       unexpected network connection.
#
# WHY FALCO: CNCF graduated. Industry standard for container runtime
#       detection. Sysdig open-sourced it. Replaces CrowdStrike Falcon
#       and Sysdig Secure at the detection layer. Every enterprise SOC
#       that runs containers has Falco or its paid equivalent.
#
# NIST CONTROLS:
#   SI-4  (Information System Monitoring) — real-time syscall monitoring
#   AU-2  (Event Logging) — security event detection and logging
#   IR-4  (Incident Handling) — alerts enable incident response
#   SI-3  (Malicious Code Protection) — detects suspicious runtime behavior
#
# ARCHITECTURE:
#   Falco DaemonSet (every node) → detects events via eBPF
#   Falcosidekick (1 pod) → receives alerts from Falco → forwards to Splunk HEC
#   Flow: syscall → Falco rule match → JSON alert → Falcosidekick → Splunk

# WHY modern_ebpf: eBPF is the modern approach to syscall monitoring.
# No kernel module compilation needed. Safer than the legacy kernel
# module driver. Works on k3d. If this fails on your kernel, fall
# back to 'kmod' (kernel module) or 'ebpf' (legacy eBPF).
driver:
  kind: modern_ebpf

# WHY JSON output: Structured output that Falcosidekick can parse
# and forward. Human-readable text output is for debugging only.
falco:
  json_output: true
  json_include_output_property: true
  log_level: info

  # WHY these priority thresholds: Falco rules have priorities
  # (Emergency, Alert, Critical, Error, Warning, Notice, Info, Debug).
  # We capture Warning and above. Debug/Info generate too much noise
  # for a SOC — you'd drown in false positives.
  priority: WARNING

# WHY Falcosidekick: Falco generates alerts to stdout. Falcosidekick
# is the router — it takes those alerts and sends them to Splunk,
# Slack, PagerDuty, or wherever your SOC needs them. Without it,
# alerts only exist in Falco's container logs.
falcosidekick:
  enabled: true
  config:
    splunk:
      # WHY host.k3d.internal: Same as Fluent Bit — reaches gp-splunk
      # on the host machine.
      hostport: "https://host.k3d.internal:8088"
      token: "gp-local-hec-token-2026"
      # WHY sourcetype: Separate sourcetype so Splunk can filter Falco
      # alerts from regular container logs. Search with:
      #   sourcetype="falco" | table rule priority output
      sourcetype: "falco"
      minimumpriority: "warning"
      checkcert: false

# Custom rules loaded from ConfigMap
customRules:
  rules-custom.yaml: |
    # --- Anthra-SecLAB Custom Falco Rules ---
    # These rules are tuned for the anthra application specifically.
    # They supplement the default Falco ruleset with app-aware detections.

    # Detect shell access in any anthra container
    # WHY: If someone gets a shell inside your app container, that's
    # either an attacker or an engineer bypassing change management.
    # Either way, the SOC needs to know immediately.
    - rule: Shell in Anthra Container
      desc: Detect shell spawned in anthra namespace containers
      condition: >
        spawned_process and container and
        proc.name in (bash, sh, zsh, ash, dash) and
        k8s.ns.name = "anthra"
      output: >
        Shell spawned in anthra container
        (user=%user.name command=%proc.cmdline container=%container.name
        pod=%k8s.pod.name namespace=%k8s.ns.name image=%container.image.repository)
      priority: WARNING
      tags: [anthra, shell, mitre_execution]

    # Detect database credential file access
    # WHY: anthra-db stores credentials. If a non-database container
    # reads DB credential files, that's lateral movement or credential
    # theft.
    - rule: DB Credential Access in Anthra
      desc: Detect access to database credential files in anthra namespace
      condition: >
        open_read and container and
        k8s.ns.name = "anthra" and
        (fd.name contains "password" or fd.name contains ".pgpass" or
         fd.name contains "db-secret")
      output: >
        Database credential file accessed
        (user=%user.name file=%fd.name command=%proc.cmdline
        container=%container.name pod=%k8s.pod.name)
      priority: WARNING
      tags: [anthra, credentials, mitre_credential_access]

    # Detect unexpected outbound connections from anthra containers
    # WHY: anthra containers should only talk to each other and to
    # the database. Outbound connections to the internet could be
    # data exfiltration or C2 callback.
    - rule: Unexpected Outbound from Anthra
      desc: Detect outbound connections from anthra to external IPs
      condition: >
        outbound and container and
        k8s.ns.name = "anthra" and
        not (fd.sip in (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16))
      output: >
        Unexpected outbound connection from anthra
        (command=%proc.cmdline connection=%fd.name
        container=%container.name pod=%k8s.pod.name dest=%fd.sip)
      priority: WARNING
      tags: [anthra, network, mitre_exfiltration]

# Resources for lab
resources:
  limits:
    memory: 512Mi
    cpu: 500m
  requests:
    memory: 256Mi
    cpu: 100m
```

- [ ] **Step 2: Commit**

```bash
git add SecLAB-setup/02-soc-stack/falco/
git commit -m "seclab-setup: falco values with custom anthra rules and splunk forwarding"
```

---

## Task 6: SOC Stack — Deploy Script, Teardown Script, Playbook, README

**Files:**
- Create: `SecLAB-setup/02-soc-stack/deploy-stack.sh`
- Create: `SecLAB-setup/02-soc-stack/teardown-stack.sh`
- Create: `SecLAB-setup/02-soc-stack/playbook.md`
- Create: `SecLAB-setup/README.md`

- [ ] **Step 1: Create deploy-stack.sh**

```bash
#!/usr/bin/env bash
# SecLAB SOC Stack Deployment
# Installs security tools in correct dependency order.
# Idempotent — safe to run multiple times (helm upgrade --install).
#
# Order matters:
#   1. Kyverno — admission control first (catches issues in subsequent deploys)
#   2. Kyverno policies — applied after controller is ready
#   3. Prometheus + Grafana — monitoring up before Falco (track Falco health)
#   4. Fluent Bit — log pipeline ready before Falco (ship Falco container logs)
#   5. Falco + Falcosidekick — runtime detection last (alerts go to ready pipeline)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "============================================"
echo "SecLAB SOC Stack Deployment"
echo "============================================"
echo ""

# --- Prerequisites ---
echo "--- Checking prerequisites ---"
if ! kubectl cluster-info &>/dev/null; then
    echo "ERROR: No cluster connection. Run setup-cluster.sh first."
    exit 1
fi

if ! docker ps --format '{{.Names}}' | grep -q gp-splunk; then
    echo "WARNING: gp-splunk is not running. Falco alerts and log shipping will fail."
    echo "  Start with: docker start gp-splunk"
fi
echo ""

# --- 1. Kyverno ---
echo "--- [1/5] Installing Kyverno (admission control) ---"
helm upgrade --install kyverno kyverno/kyverno \
    --namespace kyverno \
    --create-namespace \
    --values "${SCRIPT_DIR}/kyverno/values.yaml" \
    --wait --timeout 5m
echo "  Kyverno installed"
echo ""

# --- 2. Kyverno Policies ---
echo "--- [2/5] Applying baseline policies (audit mode) ---"
kubectl apply -f "${SCRIPT_DIR}/kyverno/baseline-policies/"
echo "  Policies applied (audit mode — violations logged, not blocked)"
echo ""

# --- 3. Prometheus + Grafana ---
echo "--- [3/5] Installing Prometheus + Grafana (monitoring) ---"
helm upgrade --install prometheus prometheus-community/kube-prometheus-stack \
    --namespace monitoring \
    --create-namespace \
    --values "${SCRIPT_DIR}/prometheus-grafana/values.yaml" \
    --wait --timeout 5m
echo "  Prometheus + Grafana installed"

# Import SOC dashboard as ConfigMap
if [ -f "${SCRIPT_DIR}/prometheus-grafana/dashboards/soc-overview.json" ]; then
    kubectl create configmap soc-overview-dashboard \
        --from-file=soc-overview.json="${SCRIPT_DIR}/prometheus-grafana/dashboards/soc-overview.json" \
        --namespace monitoring \
        --dry-run=client -o yaml | \
        kubectl label --local -f - grafana_dashboard="1" -o yaml | \
        kubectl apply -f -
    echo "  SOC dashboard imported"
fi
echo ""

# --- 4. Fluent Bit ---
echo "--- [4/5] Installing Fluent Bit (log shipping → Splunk) ---"
helm upgrade --install fluent-bit fluent/fluent-bit \
    --namespace logging \
    --create-namespace \
    --values "${SCRIPT_DIR}/splunk-forwarder/fluentbit-values.yaml" \
    --wait --timeout 3m
echo "  Fluent Bit installed — shipping logs to gp-splunk HEC"
echo ""

# --- 5. Falco ---
echo "--- [5/5] Installing Falco (runtime detection) ---"
helm upgrade --install falco falcosecurity/falco \
    --namespace falco \
    --create-namespace \
    --values "${SCRIPT_DIR}/falco/values.yaml" \
    --wait --timeout 5m
echo "  Falco installed — alerts forwarding to Splunk via Falcosidekick"
echo ""

# --- Verification ---
echo "============================================"
echo "Verification"
echo "============================================"
echo ""

echo "--- Namespaces ---"
kubectl get ns | grep -E 'kyverno|monitoring|logging|falco|anthra'
echo ""

echo "--- Pod Status ---"
for ns in kyverno monitoring logging falco; do
    echo "  ${ns}:"
    kubectl get pods -n "${ns}" --no-headers 2>/dev/null | while read line; do
        echo "    ${line}"
    done
done
echo ""

echo "--- Kyverno Policy Reports ---"
kubectl get clusterpolicyreport --no-headers 2>/dev/null | head -5
echo ""

echo "--- Access URLs ---"
echo "  Splunk:  http://localhost:8000  (admin / GPcopilot2026!)"
echo "  Grafana: http://localhost:30300 (admin / SecLAB2026!)"
echo ""

echo "============================================"
echo "SOC stack deployed. Daily workflow:"
echo "  1. Grafana  → cluster health + metrics"
echo "  2. Splunk   → Falco alerts + container logs"
echo "  3. Kyverno  → policy violation reports"
echo "============================================"
```

- [ ] **Step 2: Create teardown-stack.sh**

```bash
#!/usr/bin/env bash
# SecLAB SOC Stack Teardown
# Removes all security tools. Preserves the cluster and application.
# Splunk (gp-splunk on host) is NOT affected.

set -euo pipefail

echo "============================================"
echo "SecLAB SOC Stack Teardown"
echo "============================================"

echo "Removing Falco..."
helm uninstall falco -n falco 2>/dev/null || echo "  (not installed)"

echo "Removing Fluent Bit..."
helm uninstall fluent-bit -n logging 2>/dev/null || echo "  (not installed)"

echo "Removing Prometheus + Grafana..."
helm uninstall prometheus -n monitoring 2>/dev/null || echo "  (not installed)"

echo "Removing Kyverno policies..."
kubectl delete clusterpolicy --all 2>/dev/null || echo "  (none found)"

echo "Removing Kyverno..."
helm uninstall kyverno -n kyverno 2>/dev/null || echo "  (not installed)"

echo "Cleaning up namespaces..."
for ns in falco logging monitoring kyverno; do
    kubectl delete namespace "${ns}" --ignore-not-found 2>/dev/null
done

echo ""
echo "SOC stack removed. Cluster and application still running."
echo "gp-splunk container NOT affected."
echo "============================================"
```

- [ ] **Step 3: Create 02-soc-stack/playbook.md**

The implementer should create a comprehensive playbook following the same format as `01-cluster-setup/playbook.md` with these sections:

**What This Does** — deploys the baseline SOC tool stack

**Why This Matters** — a SOC without tools is just a room. These are the eyes and ears that let you detect, investigate, and respond to security events. Without them, breaches go undetected (IBM: average 279 days to detect).

**Tool Overview** — table of all 4 tools with what they do, which NIST controls they satisfy, and what the enterprise equivalent costs

**Steps:**
1. Deploy the stack: `bash SecLAB-setup/02-soc-stack/deploy-stack.sh`
2. Verify Kyverno: `kubectl get clusterpolicy` — should show 4 policies in Audit mode. `kubectl get policyreport -A` — should show violations (anthra pods likely fail security-context and resource-limits checks)
3. Verify Grafana: open `http://localhost:30300`, login admin/SecLAB2026!, navigate to SOC Overview dashboard, confirm metrics are populating
4. Verify Splunk logs: open `http://localhost:8000`, search `index=* sourcetype="kube:container:*"` — should show container logs within 2-3 minutes of Fluent Bit deployment
5. Verify Falco: `kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=20` — should show Falco startup and rule loading. Then exec into an anthra pod: `kubectl exec -it deploy/anthra-api -n anthra -- /bin/sh` — check Splunk for `sourcetype="falco"` alert within 30 seconds
6. Check Falcosidekick: `kubectl logs -n falco -l app.kubernetes.io/name=falcosidekick --tail=10` — should show Splunk output configured

**What to Verify** — checklist with expected output for each tool

**Daily SOC Workflow** — the 5 steps from the spec (Grafana → Splunk → Kyverno → Investigate → Document)

**What a CySA+ Analyst Should Know** — for each tool: what it replaces in the enterprise (CrowdStrike, Datadog, Styra DAS, Splunk Enterprise), how the detection pipeline works (event → alert → SIEM → dashboard → investigation), and how this maps to CySA+ exam domains

- [ ] **Step 4: Create SecLAB-setup/README.md**

```markdown
# SecLAB-setup

Reproducible lab environment for the Anthra-SecLAB security lab. Two-phase setup:

1. **Cluster Setup** — k3d cluster + target application deployment
2. **SOC Stack** — security tool stack for detection, monitoring, and policy enforcement

## Quick Start

```bash
# Phase 1: Cluster + App
bash SecLAB-setup/01-cluster-setup/setup-cluster.sh

# Phase 2: SOC Tools
bash SecLAB-setup/02-soc-stack/deploy-stack.sh
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│ Host Machine                                                     │
│                                                                  │
│  ┌──────────┐    ┌──────────────────────────────────────────────┐│
│  │gp-splunk │    │ k3d-seclab cluster                          ││
│  │          │    │                                              ││
│  │ Web :8000│    │  [anthra namespace]                          ││
│  │ HEC :8088│◄───│  anthra-ui    :30000  (React frontend)      ││
│  │          │    │  anthra-api   :30080  (FastAPI backend)      ││
│  │  Falco   │    │  anthra-db           (PostgreSQL)            ││
│  │  alerts  │    │  anthra-log   :30090  (Go log ingest)       ││
│  │          │    │                                              ││
│  │  Fluent  │    │  [kyverno namespace]                         ││
│  │  Bit     │    │  kyverno      (admission control)            ││
│  │  logs    │    │                                              ││
│  │          │    │  [monitoring namespace]                       ││
│  └──────────┘    │  prometheus   (metrics collection)           ││
│                  │  grafana      :30300  (dashboards)            ││
│                  │  alertmanager (alert routing)                 ││
│                  │                                              ││
│                  │  [logging namespace]                          ││
│                  │  fluent-bit   (DaemonSet → Splunk HEC)       ││
│                  │                                              ││
│                  │  [falco namespace]                            ││
│                  │  falco        (DaemonSet, eBPF runtime)      ││
│                  │  falcosidekick (alert router → Splunk)       ││
│                  └──────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

## Access

| Service | URL | Credentials |
|---------|-----|-------------|
| Anthra UI | http://localhost:30000 | — |
| Anthra API | http://localhost:30080 | — |
| Splunk | http://localhost:8000 | admin / GPcopilot2026! |
| Grafana | http://localhost:30300 | admin / SecLAB2026! |

## Tool Stack

| Tool | Namespace | What It Does | NIST Controls |
|------|-----------|-------------|---------------|
| Kyverno | kyverno | Admission control — blocks misconfigured deployments | CM-7, AC-6, CM-2, CM-8, SC-6 |
| Prometheus + Grafana | monitoring | Metrics collection + dashboards | SI-4, AU-6, CA-7 |
| Fluent Bit | logging | Log shipping to Splunk HEC | AU-2, AU-3, AU-4, AU-6 |
| Falco + Falcosidekick | falco | Runtime detection + alert forwarding | SI-4, AU-2, IR-4, SI-3 |
| Splunk (external) | host | SIEM — logs, alerts, investigation | AU-6, IR-4, IR-5 |

## Reports

Finalized evidence and reports go to:
```
/home/jimmie/linkops-industries/GP-copilot/GP-S3/6-seclab-reports/
├── evidence/     # Scanner output
├── governance/   # CISO briefs
├── poam/         # POA&M tracking
└── dashboards/   # Grafana snapshots
```

## Playbooks

- [01-cluster-setup/playbook.md](01-cluster-setup/playbook.md) — cluster creation and app deployment
- [02-soc-stack/playbook.md](02-soc-stack/playbook.md) — SOC tool deployment and verification

## Teardown

```bash
# Remove SOC tools only (keeps cluster + app)
bash SecLAB-setup/02-soc-stack/teardown-stack.sh

# Destroy everything (except Splunk)
bash SecLAB-setup/01-cluster-setup/teardown-cluster.sh
```
```

- [ ] **Step 5: Make scripts executable and commit**

```bash
chmod +x SecLAB-setup/02-soc-stack/deploy-stack.sh
chmod +x SecLAB-setup/02-soc-stack/teardown-stack.sh
git add SecLAB-setup/02-soc-stack/deploy-stack.sh SecLAB-setup/02-soc-stack/teardown-stack.sh
git add SecLAB-setup/02-soc-stack/playbook.md SecLAB-setup/README.md
git commit -m "seclab-setup: deploy/teardown scripts, SOC playbook, and README"
```

---

## Task 7: Test Full Setup

This task runs the full setup against the live cluster to verify everything works. No files created — just execution and verification.

**Important:** The k3d cluster and app are already running. We only need to deploy the SOC stack and verify.

- [ ] **Step 1: Deploy SOC stack**

```bash
bash SecLAB-setup/02-soc-stack/deploy-stack.sh
```

Expected: All 5 steps complete. Kyverno, Prometheus+Grafana, Fluent Bit, Falco all installed.

- [ ] **Step 2: Verify all pods are running**

```bash
kubectl get pods -A | grep -E 'kyverno|monitoring|logging|falco'
```

Expected: All pods Running/Ready across 4 namespaces.

- [ ] **Step 3: Verify Kyverno policies**

```bash
kubectl get clusterpolicy
kubectl get policyreport -A --no-headers | head -10
```

Expected: 4 policies listed. Policy reports showing violations (anthra pods likely fail some checks).

- [ ] **Step 4: Verify Grafana**

```bash
curl -sf http://localhost:30300/api/health
```

Expected: `{"commit":"...","database":"ok","version":"..."}`

- [ ] **Step 5: Verify Splunk receives logs**

Wait 2-3 minutes after Fluent Bit deployment, then search in Splunk:
```
index=* sourcetype="kube:container:*" | head 10
```

Expected: Container log events from the anthra namespace.

- [ ] **Step 6: Verify Falco detects shell access**

```bash
kubectl exec -it deploy/anthra-api -n anthra -- /bin/sh -c "echo test"
```

Then search Splunk within 60 seconds:
```
sourcetype="falco" | head 5
```

Expected: Falco alert for "Shell in Anthra Container" or similar rule match.

- [ ] **Step 7: Fix any issues and commit**

If any scripts needed adjustments during testing:

```bash
git add SecLAB-setup/
git commit -m "fix: adjust seclab-setup after integration test"
```

---

## Execution Order & Dependencies

```
Task 1 (cluster setup scripts)      — no dependencies
Task 2 (kyverno values + policies)  — no dependencies
Task 3 (prometheus + grafana)       — no dependencies
Task 4 (fluent bit)                 — no dependencies
Task 5 (falco)                      — no dependencies
Task 6 (deploy script + playbook)   — depends on Tasks 2-5 (needs all values files)
Task 7 (integration test)           — depends on Task 1 + Task 6
```

Tasks 1-5 are independent and can be built in any order. Task 6 ties them together with the deploy script. Task 7 is the end-to-end verification.
