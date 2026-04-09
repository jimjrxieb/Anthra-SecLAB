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
