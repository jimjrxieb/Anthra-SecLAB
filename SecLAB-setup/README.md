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
