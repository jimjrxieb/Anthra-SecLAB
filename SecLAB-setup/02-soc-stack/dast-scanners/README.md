# DAST Scanners — SecLAB Setup

ZAP and Nuclei deployed as Kubernetes Jobs inside the cluster. Managed by the analyst, not auto-run by the SOC stack deployment.

## What Gets Deployed

| File | Purpose |
|------|---------|
| `scanner-networkpolicy.yaml` | Allows scanner pods (`seclab-tool: dast`) to reach API pods on port 8000 |
| `deploy-dast.sh` | Full deployment: NetworkPolicy + jobs + wait + copy results |

Job manifests live in the consulting package and are referenced by the deploy script:
```
GP-CONSULTING/09-OSI-MODEL-SECURITY/07-APPLICATION-LAYER/03-templates/dast/
  zap-job.yaml
  nuclei-job.yaml
```

## How to Run

The NetworkPolicy is deployed automatically by `deploy-stack.sh` (step 6). Scans are analyst-triggered:

```bash
# Run both scanners against the default target
bash dast-scanners/deploy-dast.sh

# Override target service or port
bash dast-scanners/deploy-dast.sh --target my-api-service --port 3000
```

The script handles cleanup of previous runs, deployment, waiting, and result collection automatically.

## Where Results Go

```
Anthra-SecLAB/evidence/dast/
  YYYYMMDD-HHMMSS-zap-report.json
  YYYYMMDD-HHMMSS-zap-report.html
  YYYYMMDD-HHMMSS-nuclei-results.jsonl
```

Each run is timestamped. Previous runs are not overwritten.

## Viewing in Splunk

Falco detects scanner activity (network connections, process spawns) and forwards to Splunk. To see scanner-triggered detections:

```
index=gp_security sourcetype=falco
| search pod_name="zap-*" OR pod_name="nuclei-*"
```

This lets you verify your detection pipeline sees active scanning. If Falco is silent during a scan, that is a detection gap — tune accordingly.

You can also check for rules that fire during the scan:
```
index=gp_security sourcetype=falco earliest=-30m
| stats count by rule
| sort -count
```

## NetworkPolicy Behavior

The `scanner-networkpolicy.yaml` adds an ingress rule to API pods allowing traffic from `seclab-tool: dast` labeled pods. Without this, the scanner pods cannot reach the target and the scan fails — which validates your segmentation is working.

After scanning, you can remove the NetworkPolicy to restore strict segmentation:
```bash
kubectl delete networkpolicy allow-dast-to-portfolio -n anthra
```

The SOC stack deployment (`deploy-stack.sh`) only applies the NetworkPolicy, not the scan jobs. Scans run on analyst demand.

## Control Mapping

| Control | What It Covers |
|---------|---------------|
| CSF 2.0 ID.RA-01 | Active vulnerability identification via DAST |
| CIS v8 16.12 | Security checks extended to running application endpoints |
| NIST RA-5 | Vulnerability scanning of deployed services |
| NIST SC-7 | NetworkPolicy validates boundary protection |
