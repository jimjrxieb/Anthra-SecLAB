# Plan of Action & Milestones (POA&M)

Anthra-SecLAB — Break/Fix Evidence Tracker

| Control ID | Finding | Risk Level | Break Method | Detection Tool | Fix Applied | Evidence File | Status | Date Closed |
|-----------|---------|------------|-------------|---------------|-------------|--------------|--------|-------------|
| SC-7 | No default-deny NetworkPolicy | High | Deleted default-deny netpol | kube-hunter | Restored default-deny + per-service rules | `evidence/YYYY-MM-DD/sc7-*.json` | Open | |
| CM-7 | Wildcard ingress allows all pod-to-pod | Medium | Added allow-all ingress rule | Kubescape, Polaris | Scoped ingress to named services | `evidence/YYYY-MM-DD/cm7-*.json` | Open | |
| AC-6 | Default SA bound to cluster-admin | Critical | Bound default SA to cluster-admin | kubescape, kubectl auth can-i | Removed binding, scoped to namespace read-only | `evidence/YYYY-MM-DD/ac6-*.json` | Open | |
