# SecLAB-setup — Baseline SOC Lab Design Spec

## Purpose

Create a reproducible lab setup that deploys the k3d cluster, the target application, and a baseline SOC tool stack — correctly configured with best-practice documentation explaining WHY each config choice was made. This is the known-good baseline that OSI-MODEL break/fix scenarios will test against.

The audience is a CySA+ analyst learning to operate a SOC. Mentors and interviewers will review this. Every configuration choice must be explained.

## Current State

- **Cluster:** k3d-seclab (1 server + 2 agents), created manually, no setup script
- **App:** 4 deployments in `anthra` namespace (anthra-ui, anthra-api, anthra-db, anthra-log-ingest)
- **App source:** `target-application/` directory
- **Splunk:** Already running as `gp-splunk` container (splunk/splunk:9.2) on host — ports 8000 (web), 8088 (HEC), 8089 (mgmt)
- **Security tools:** None deployed. Helm repos added for Falco, Prometheus, Kyverno, Gatekeeper
- **Disk:** 400GB free, ~1GB needed for tool stack

## Directory Structure

```
SecLAB-setup/
├── README.md                          # Overview, architecture, daily SOC workflow
├── 01-cluster-setup/
│   ├── playbook.md                    # Step-by-step cluster + app setup with WHY
│   ├── k3d-config.yaml                # Declarative k3d cluster config
│   ├── setup-cluster.sh               # Create cluster, build images, deploy app
│   └── teardown-cluster.sh            # Destroy cluster cleanly
├── 02-soc-stack/
│   ├── playbook.md                    # What each tool does, WHY this config, daily CySA workflow
│   ├── falco/
│   │   ├── values.yaml                # Helm values with security best-practice comments
│   │   └── custom-rules.yaml          # Rules tuned for anthra app (shell in container, DB access, etc.)
│   ├── prometheus-grafana/
│   │   ├── values.yaml                # Helm values for kube-prometheus-stack
│   │   └── dashboards/
│   │       └── soc-overview.json      # Pre-built SOC dashboard (MTTD, MTTR, pod health, alerts)
│   ├── kyverno/
│   │   ├── values.yaml                # Helm values
│   │   └── baseline-policies/
│   │       ├── require-security-context.yaml
│   │       ├── disallow-latest-tag.yaml
│   │       ├── require-resource-limits.yaml
│   │       └── require-labels.yaml
│   ├── splunk-forwarder/
│   │   └── fluentbit-values.yaml      # Fluent Bit helm values — ships to gp-splunk HEC
│   ├── deploy-stack.sh                # Helm install all tools in correct order
│   └── teardown-stack.sh              # Helm uninstall all
```

## Tool Stack

### Falco — Runtime Detection (L2-L7)

**What it does:** Monitors syscalls at runtime and fires alerts when suspicious behavior occurs — shell spawned in container, sensitive file read, unexpected network connection, privilege escalation.

**Why Falco:** Industry standard for container runtime detection. Sysdig open-sourced it. CNCF graduated project. Replaces CrowdStrike Falcon and Sysdig Secure at the detection layer. Every SOC that runs containers has Falco or its enterprise equivalent.

**Helm chart:** `falcosecurity/falco`

**Key config decisions (values.yaml):**
- `driver.kind: modern_ebpf` — eBPF driver, no kernel module needed. Works on k3d. WHY: eBPF is the modern approach — safer than kernel modules, no recompilation needed on kernel updates
- `falcosidekick.enabled: true` — sidekick forwards alerts to Splunk HEC. WHY: Falco generates alerts, sidekick routes them to your SIEM. Without this, alerts only go to stdout
- `falcosidekick.config.splunk.url` — points to `http://host.k3d.internal:8088`. WHY: k3d maps `host.k3d.internal` to the host machine where gp-splunk runs
- `customRules` — tuned for anthra app: alert on shell in anthra containers, alert on DB credential file access, alert on unexpected outbound connections

**What a CySA sees daily:** Falco alerts in Splunk showing runtime anomalies — shell access attempts, privilege escalation, suspicious file access. These are the alerts you investigate.

### Prometheus + Grafana — Metrics and Dashboards (L3-L7)

**What it does:** Prometheus scrapes metrics from all pods and nodes. Grafana visualizes them in dashboards. Together they give you the CISO dashboard metrics: health status, resource usage, alert counts, SLA tracking.

**Why Prometheus + Grafana:** De facto standard for Kubernetes monitoring. CNCF graduated. Every production cluster runs this stack. The kube-prometheus-stack helm chart bundles Prometheus, Grafana, and alertmanager in one install.

**Helm chart:** `prometheus-community/kube-prometheus-stack`

**Key config decisions (values.yaml):**
- `grafana.adminPassword` — set explicitly, not auto-generated. WHY: lab needs predictable access
- `grafana.persistence.enabled: false` — no PVC needed for lab. WHY: dashboards are code (JSON files), reimportable
- `prometheus.prometheusSpec.retention: 7d` — 7 days of metrics. WHY: enough for lab work, doesn't eat disk
- `prometheus.prometheusSpec.resources` — limited to 512Mi/500m. WHY: lab cluster has limited resources, production would be higher
- Pre-built SOC dashboard: pod health, node resources, alert counts, Falco alert rate, Kyverno policy violations

**What a CySA sees daily:** Grafana dashboard showing cluster health, resource consumption, alert trends, and any anomalies in pod behavior.

### Kyverno — Admission Control (L3-L7)

**What it does:** Intercepts every Kubernetes API request and validates it against policies BEFORE the resource is created. Blocks misconfigurations at deploy time — running as root, missing resource limits, latest tags, missing labels.

**Why Kyverno:** Native Kubernetes (no Rego language to learn). Policies are YAML — same language as everything else in K8s. Replaces OPA/Gatekeeper and Styra DAS. Easier to read and write than Rego for the same coverage.

**Helm chart:** `kyverno/kyverno`

**Key config decisions (values.yaml):**
- `admissionController.replicas: 1` — single replica for lab. WHY: HA not needed in k3d
- `backgroundController.enabled: true` — scans existing resources, not just new ones. WHY: catches misconfigs that were deployed before Kyverno was installed
- Policies deployed in `Audit` mode initially, not `Enforce`. WHY: audit mode logs violations without blocking. You learn what would be blocked, then switch to enforce once you trust the policies. This is how production rollouts work.

**Baseline policies:**
- `require-security-context.yaml` — pods must set `runAsNonRoot: true`, drop ALL capabilities. NIST: AC-6, CM-7
- `disallow-latest-tag.yaml` — image tags must be pinned, not `:latest`. NIST: CM-2, SA-10
- `require-resource-limits.yaml` — CPU and memory limits required. NIST: SC-6
- `require-labels.yaml` — app, environment, managed-by labels required. NIST: CM-8

**What a CySA sees daily:** Kyverno policy reports showing which resources violate policy. In audit mode, these are warnings. In enforce mode, these are blocked deployments.

### Fluent Bit → Splunk — Log Shipping (L7)

**What it does:** Fluent Bit runs as a DaemonSet, tails container logs from every node, and ships them to Splunk via HEC (HTTP Event Collector).

**Why Fluent Bit:** Lightweight (C-based, ~450KB binary). CNCF graduated. Better resource usage than Fluentd for simple log forwarding. The standard log shipper for Kubernetes → Splunk pipelines.

**Helm chart:** `fluent/fluent-bit`

**Key config decisions (fluentbit-values.yaml):**
- `outputs.splunk.host: host.k3d.internal` — routes to gp-splunk on the host. WHY: k3d provides this DNS name for host access
- `outputs.splunk.port: 8088` — HEC port
- `outputs.splunk.tls: off` — no TLS for lab. WHY: localhost communication, no network exposure. Production would require TLS
- `filters.kubernetes` — enriches logs with pod name, namespace, labels. WHY: without this, Splunk sees raw text with no context about which pod generated it
- `parsers.json` — parses JSON-formatted app logs. WHY: anthra-api outputs structured JSON, Splunk needs parsed fields for searching

**What a CySA sees daily:** All cluster logs in Splunk — searchable by pod, namespace, severity. Failed logins, API errors, health check failures, Falco alerts all in one place.

## Setup Scripts

### setup-cluster.sh

Idempotent. Safe to run multiple times. Steps:
1. Check prerequisites (docker, k3d, kubectl, helm)
2. Create k3d cluster from `k3d-config.yaml` (skip if exists)
3. Build app images from `target-application/` (anthra-api:seclab, anthra-log-ingest:seclab)
4. Import images into k3d
5. Deploy app with `kubectl apply -k target-application/infrastructure/kustomize/overlays/local/`
6. Wait for all pods ready
7. Verify: curl localhost:30000 (UI), curl localhost:30080/api/health (API)
8. Print status summary

### deploy-stack.sh

Idempotent. Installs tools in correct dependency order:
1. Kyverno (admission control must be first — catches issues in subsequent deploys)
2. Apply baseline policies (audit mode)
3. Prometheus + Grafana (monitoring must be up before Falco so we can track Falco's own health)
4. Import SOC dashboard into Grafana
5. Fluent Bit (log shipping — needs to be running before Falco so Falco alerts get shipped)
6. Falco + Falcosidekick (runtime detection — last because it generates alerts, and we want the pipeline ready)
7. Verify: all pods healthy, Grafana accessible, Falco running, logs appearing in Splunk
8. Print access URLs and status

### k3d-config.yaml

Declarative cluster config:
- Name: seclab
- 1 server, 2 agents
- Port mappings: 30000 (UI), 30080 (API), 30090 (log-ingest), 30300 (Grafana)
- host.k3d.internal enabled (for Splunk HEC access)
- k3s args: `--disable=traefik` (not needed, using NodePort)

### teardown scripts

Clean destroy — cluster teardown deletes the k3d cluster. Stack teardown helm uninstalls all tools but preserves the cluster and app.

## Playbook Documentation Standard

Every playbook follows this format:

```markdown
## [Section]

### What This Does
One sentence.

### Why This Matters
2-3 sentences explaining the security or operational reason. What would happen without this.

### Steps
Numbered steps with exact commands.

### What to Verify
How to confirm it worked. Expected output.

### What a CySA+ Analyst Should Know
Key concept, certification relevance, interview talking point.
```

## Constraints

- All scripts idempotent — safe to run multiple times
- All Helm values.yaml files commented with WHY for every non-default setting
- Kyverno policies in audit mode by default (switch to enforce is a manual decision)
- Splunk is external (gp-splunk container on host) — not deployed by these scripts
- No Suricata (Falco covers container-level L3 detection, k3d has no real L3 to monitor)
- No Sentinel (needs Azure subscription, Splunk covers SIEM for lab)
- Grafana on NodePort 30300 for browser access

## Access URLs (after full setup)

| Service | URL | Purpose |
|---------|-----|---------|
| Anthra UI | http://localhost:30000 | Target application |
| Anthra API | http://localhost:30080 | API health check |
| Splunk | http://localhost:8000 | SIEM — logs, alerts, investigation |
| Grafana | http://localhost:30300 | Dashboards — metrics, health, SOC overview |

## Report Output

All reports, evidence, and scan outputs land in the centralized GP-S3 storage:

```
/home/jimmie/linkops-industries/GP-copilot/GP-S3/6-seclab-reports/
├── evidence/YYYY-MM-DD/          # Scanner output from scenario runs (Falco alerts, kubescape JSON, etc.)
├── governance/                    # Completed CISO governance briefs
├── poam/                          # POA&M tracking documents
└── dashboards/                    # Exported Grafana dashboard snapshots
```

The local `evidence/` directory in SecLAB is the working area. `tools/collect-evidence.sh` gathers scanner output there during scenario runs. Finalized reports get copied to `GP-S3/6-seclab-reports/` for centralized access across slots.

**Why GP-S3:** GP-S3 is the centralized storage layer for the GP-Copilot framework. All engagement outputs (findings DBs, reports, knowledge base) live there. SecLAB reports follow the same pattern so they're accessible to JADE, other agents, and cross-slot reporting.

## Daily SOC Workflow (what this enables)

1. Open Grafana — check cluster health dashboard, any red/amber alerts
2. Open Splunk — review Falco alerts from overnight, check log volume
3. Check Kyverno reports — any policy violations on new deployments
4. Investigate anything anomalous — drill into Falco alert → Splunk logs → Grafana metrics
5. Document findings using OSI-MODEL governance templates
6. Copy finalized evidence and reports to `GP-S3/6-seclab-reports/`
