# 02 — SOC Stack Playbook

## What This Does

Deploys the baseline SOC (Security Operations Center) tool stack into the k3d-seclab cluster. This gives you runtime detection, admission control, metrics monitoring, and centralized log shipping — the four pillars of a functioning SOC.

## Why This Matters

A SOC without tools is just a room. These are the eyes and ears that let you detect, investigate, and respond to security events in real time. Without them, breaches go undetected — IBM's Cost of a Data Breach Report shows the average time to detect a breach is 279 days. That number drops dramatically when you have runtime detection (Falco), centralized logging (Fluent Bit to Splunk), policy enforcement (Kyverno), and health monitoring (Prometheus + Grafana) working together.

**What a CySA+ Analyst Should Know:** This is what a real SOC stack looks like. Enterprise SOCs spend six figures on commercial tools. This lab builds the same detection pipeline with open source — same concepts, same alert flow, same investigation workflow. The skills transfer directly.

## Tool Overview

| Tool | What It Does | NIST Controls | Enterprise Equivalent | Annual Cost |
|------|-------------|---------------|----------------------|-------------|
| Kyverno | Admission control — blocks misconfigured deployments before they run | CM-7, AC-6, CM-2, CM-8, SC-6 | Styra DAS / OPA Enterprise | $50-150K |
| Prometheus + Grafana | Metrics collection + dashboards — cluster and app health at a glance | SI-4, AU-6, CA-7 | Datadog / New Relic | $50-200K |
| Fluent Bit | Log shipping — collects container logs and sends to Splunk via HEC | AU-2, AU-3, AU-4, AU-6 | Cribl / native Splunk forwarder | $30-100K |
| Falco + Falcosidekick | Runtime detection — watches syscalls for malicious behavior, routes alerts | SI-4, AU-2, IR-4, SI-3 | CrowdStrike Falcon / Sysdig Secure | $100-300K |
| Splunk (external) | SIEM — centralized log storage, search, correlation, investigation | AU-6, IR-4, IR-5 | Splunk Enterprise (same tool) | $100K+ |

**Total enterprise equivalent:** $330K-$850K/year. This lab: $0 in licensing.

## Prerequisites

- k3d-seclab cluster running (Phase 1 complete)
- Application deployed in `anthra` namespace
- `gp-splunk` container running on host (HEC on port 8088)
- Helm repos added: kyverno, prometheus-community, fluent, falcosecurity

## Steps

### 1. Deploy the SOC stack

```bash
bash SecLAB-setup/02-soc-stack/deploy-stack.sh
```

The script installs tools in dependency order:
1. **Kyverno** — admission control first, so it catches issues in subsequent deployments
2. **Kyverno policies** — 4 baseline policies in audit mode (log violations, don't block yet)
3. **Prometheus + Grafana** — monitoring up before Falco so we can track Falco's own health
4. **Fluent Bit** — log pipeline ready before Falco so Falco container logs ship to Splunk
5. **Falco + Falcosidekick** — runtime detection last, alerts flow to the already-ready pipeline

### 2. Verify Kyverno

```bash
# Check policies are installed
kubectl get clusterpolicy
# Expected: 4 policies — disallow-latest-tag, require-labels,
#           require-resource-limits, require-security-context
# All should show "Audit" in ADMISSION column

# Check for violations against existing workloads
kubectl get policyreport -A
# Expected: Reports in anthra namespace showing violations
# (anthra pods likely fail security-context and resource-limits checks)

# Detailed violation view
kubectl get policyreport -n anthra -o yaml | grep -A 5 "result: fail"
```

**What you're seeing:** Kyverno scanned the anthra pods that were deployed BEFORE the policies existed. In audit mode, it reports what WOULD have been blocked. This is how you roll out policies safely — audit first, enforce after fixing violations.

### 3. Verify Grafana

Open http://localhost:30300 in your browser.
- Login: admin / SecLAB2026!
- Navigate to Dashboards > SOC Overview
- Confirm metrics are populating (CPU, memory, pod counts)

```bash
# CLI health check
curl -sf http://localhost:30300/api/health
# Expected: {"commit":"...","database":"ok","version":"..."}

# Check dashboard was loaded
curl -sf -u admin:SecLAB2026! http://localhost:30300/api/search?query=SOC
# Expected: JSON array containing the SOC Overview dashboard
```

### 4. Verify Splunk receives logs

Open http://localhost:8000 in your browser.
- Login: admin / GPcopilot2026!
- Wait 2-3 minutes after Fluent Bit deployment for logs to arrive

Run this search in Splunk:
```
index=* sourcetype="kube:container:*" | head 10
```
Expected: Container log events from pods across all namespaces.

Filter to anthra application logs:
```
index=* sourcetype="kube:container:*" kubernetes.namespace_name="anthra" | head 10
```

### 5. Verify Falco runtime detection

```bash
# Check Falco is running and rules loaded
kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=20
# Expected: "Falco initialized" message, custom rules loaded

# Check Falcosidekick has Splunk configured
kubectl logs -n falco -l app.kubernetes.io/name=falcosidekick --tail=10
# Expected: Output showing Splunk webhook configured
```

Now trigger a detection — exec into a container (this is suspicious behavior Falco watches for):

```bash
kubectl exec -it deploy/anthra-api -n anthra -- /bin/sh -c "echo test"
```

Within 30 seconds, check Splunk:
```
sourcetype="falco" | head 5
```
Expected: Falco alert for "Shell in Anthra Container" or similar rule match showing the exec event, container name, and priority level.

### 6. Verify Falcosidekick alert routing

```bash
# Check Falcosidekick is forwarding to Splunk
kubectl logs -n falco -l app.kubernetes.io/name=falcosidekick --tail=20
# Expected: Log lines showing successful POST to Splunk HEC endpoint

# Check Falcosidekick metrics
kubectl port-forward -n falco svc/falco-falcosidekick 2801:2801 &
curl -sf http://localhost:2801/metrics | grep falcosidekick_outputs
# Kill the port-forward when done
kill %1 2>/dev/null
```

## What to Verify — Checklist

| Check | Command | Expected |
|-------|---------|----------|
| Kyverno running | `kubectl get pods -n kyverno` | All pods Running |
| 4 policies active | `kubectl get clusterpolicy` | 4 policies, Audit mode |
| Policy reports exist | `kubectl get policyreport -A` | Reports in anthra namespace |
| Prometheus running | `kubectl get pods -n monitoring` | All pods Running |
| Grafana accessible | `curl -sf http://localhost:30300/api/health` | database: ok |
| Dashboard loaded | `kubectl get cm -n monitoring -l grafana_dashboard=1` | soc-overview-dashboard |
| Fluent Bit running | `kubectl get pods -n logging` | DaemonSet pods on all nodes |
| Logs in Splunk | Splunk search: `sourcetype="kube:container:*"` | Container log events |
| Falco running | `kubectl get pods -n falco` | DaemonSet pods on all nodes |
| Falco detects exec | `kubectl exec` then check Splunk | Falco alert in Splunk |
| Falcosidekick routing | `kubectl logs -n falco -l app.kubernetes.io/name=falcosidekick` | Splunk POST success |

## Daily SOC Workflow

This is the workflow a SOC analyst follows every day. Same pattern whether you're using open source or a $500K commercial stack.

### 1. Grafana — Cluster Health Check (5 min)

Open http://localhost:30300 and check the SOC Overview dashboard:
- Are all pods healthy? (green = running, red = crashloop/OOM)
- CPU and memory trending up unexpectedly? (could indicate cryptominer or resource abuse)
- Any pod restarts? (Falco pods restarting = runtime detection gaps)

### 2. Splunk — Review Falco Alerts (15 min)

```
sourcetype="falco" earliest=-24h | stats count by rule priority | sort -priority
```

Triage by priority:
- **Critical/Warning:** Investigate immediately (shell access, sensitive file read, privilege escalation)
- **Notice:** Review pattern (DNS queries, outbound connections to unusual IPs)
- **Info:** Batch review, look for volume anomalies

### 3. Kyverno — Policy Violations (10 min)

```bash
kubectl get policyreport -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.summary}{"\n"}{end}'
```

New violations since yesterday mean someone deployed something that doesn't meet policy. Track the trend — violations should decrease as teams fix their manifests.

### 4. Investigate Anomalies (time varies)

For any finding from steps 1-3:
1. Identify the pod/container involved
2. Check container logs: `kubectl logs <pod> -n <namespace> --tail=100`
3. Check Splunk for correlated events: `sourcetype="falco" OR sourcetype="kube:container:*" kubernetes.pod_name="<pod>"`
4. Determine if it's legitimate activity or a security event

### 5. Document Findings

Record what you found and what action was taken:
- Evidence goes to `GP-S3/6-seclab-reports/evidence/`
- Decisions go to `jade-context/decisions/`
- Unresolved items go to `findings/inbox/`

## What a CySA+ Analyst Should Know

### Falco = CrowdStrike Falcon (Runtime Detection)

**What it replaces:** CrowdStrike Falcon ($100-300K/year for endpoint detection and response).

**How the detection pipeline works:**
1. Falco runs as a DaemonSet — one instance per node, watching every container's syscalls via eBPF
2. Syscalls are matched against rules (e.g., "shell spawned in container", "sensitive file read")
3. Matching events generate alerts with priority (Emergency > Alert > Critical > Error > Warning > Notice > Info)
4. Falcosidekick receives alerts and routes them to Splunk via HEC webhook
5. Splunk indexes the alert, making it searchable and correlatable with other log data

**CySA+ mapping:** Domain 2 (Vulnerability Management), Domain 3 (Incident Response). Runtime detection is how you move from "we scan weekly" to "we detect in real time."

### Prometheus + Grafana = Datadog (Monitoring)

**What it replaces:** Datadog ($50-200K/year for infrastructure monitoring and dashboards).

**How the monitoring pipeline works:**
1. Prometheus scrapes metrics from every pod, node, and Kubernetes component on a 30-second interval
2. Metrics are stored as time series data (metric name + labels + timestamp + value)
3. Grafana queries Prometheus and renders dashboards with panels, graphs, and alerts
4. Alertmanager (part of the stack) can route alerts to Slack, PagerDuty, or email

**CySA+ mapping:** Domain 1 (Security Operations), Domain 4 (Reporting and Communication). Dashboards are how you demonstrate continuous monitoring to auditors (NIST CA-7).

### Kyverno = Styra DAS (Policy Enforcement)

**What it replaces:** Styra DAS / OPA Enterprise ($50-150K/year for policy-as-code management).

**How the admission pipeline works:**
1. Developer runs `kubectl apply` to deploy a resource
2. Kubernetes API server receives the request and sends it to admission webhooks
3. Kyverno's webhook evaluates the resource against all ClusterPolicies
4. In Audit mode: violations are logged in PolicyReports but the resource is allowed
5. In Enforce mode: violations are rejected — the resource never gets created
6. PolicyReports provide a compliance dashboard of all violations across the cluster

**CySA+ mapping:** Domain 1 (Security Operations), Domain 2 (Vulnerability Management). Prevention is better than detection. Kyverno stops misconfigurations before they become vulnerabilities.

### Fluent Bit + Splunk = Centralized Logging

**What it replaces:** Cribl + native Splunk forwarders ($30-100K/year for log pipeline management).

**How the log pipeline works:**
1. Fluent Bit runs as a DaemonSet — one instance per node, tailing every container's stdout/stderr
2. Logs are enriched with Kubernetes metadata (pod name, namespace, labels, node)
3. Enriched logs are batched and sent to Splunk via HTTP Event Collector (HEC)
4. Splunk indexes logs with sourcetype `kube:container:*` for structured search
5. Analysts search, correlate, and build dashboards in Splunk

**CySA+ mapping:** Domain 1 (Security Operations), Domain 3 (Incident Response). Log centralization is NIST AU-6 — you cannot investigate what you cannot search.

### The Detection Pipeline (End to End)

```
Container syscall → Falco (detect) → Falcosidekick (route) → Splunk (index)
Container stdout  → Fluent Bit (collect) → Splunk (index)
K8s admission     → Kyverno (evaluate) → PolicyReport (record)
All metrics       → Prometheus (scrape) → Grafana (visualize)
                                               ↓
                                    SOC Analyst (investigate)
                                               ↓
                                    Finding (document + remediate)
```

This is the same pipeline every enterprise SOC runs. The tools have different names and different price tags, but the pattern is identical: detect, collect, centralize, visualize, investigate, respond.
