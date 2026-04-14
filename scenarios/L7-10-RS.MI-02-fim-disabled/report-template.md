# L7-10 RS.MI-02 — Incident Report

**Finding:** FIM Not Covering Critical Writable Container Paths
**Date:** _______________
**Analyst:** _______________
**Status:** [ ] Open  [ ] Remediated  [ ] Verified  [ ] Closed

---

## Finding Summary

| Field | Value |
|-------|-------|
| Asset | portfolio-anthra-portfolio-app-api |
| Namespace | anthra |
| Affected Path | /tmp (emptyDir mount) |
| FIM Coverage (before) | |
| FIM Coverage (after) | |
| Files Found | |
| Data Sensitivity | |
| Exfiltration Risk | |
| CSF Subcategory | RS.MI-02 (Incidents are eradicated) |
| CIS v8 | 3.14 (Log Sensitive Data Access) |
| NIST 800-53 | SI-7 (Software, Firmware, and Information Integrity) |
| Severity | MEDIUM-HIGH |
| Rank | C (Falco config change requires approval) |

## Files Found in /tmp

| File | Purpose | Risk |
|------|---------|------|
| backdoor.sh | curl exfiltration stub | Staged tool for data exfil |
| staged-data.txt | Simulated RAG pipeline output | Sensitive data staged for exfil |

## Timeline

| Time | Action |
|------|--------|
| | Baseline captured (baseline.sh) |
| | readOnlyRootFilesystem confirmed on /app |
| | /tmp writable confirmed (emptyDir) |
| | Falco rule search — no /tmp coverage found |
| | break.sh executed — files planted in /tmp |
| | Detection attempted — Falco silent (no rule) |
| | Manual /tmp inspection — files discovered |
| | Investigation completed — C-rank classified |
| | fix.sh executed — Falco FIM rules deployed |
| | verify.sh — test write detected by Falco |
| | Report filed |

## Root Cause

readOnlyRootFilesystem protects /app (the application code) but /tmp is mounted as an
emptyDir volume — writable by design. Kubernetes requires at least one writable path for
most applications (temp files, caches, sockets). Without a Falco rule covering /tmp writes
in the anthra namespace, an attacker who gains shell access can stage tools and data for
exfiltration with zero detection.

## Remediation Applied

- [ ] Confirmed readOnlyRootFilesystem is true (PROTECT layer)
- [ ] Identified writable paths (/tmp, /var/cache, /var/run)
- [ ] Searched Falco rules for /tmp coverage — none found
- [ ] Deployed custom Falco rule: Write to Temp in Portfolio API (WARNING/T1074)
- [ ] Deployed custom Falco rule: Execute from Temp in Portfolio API (ERROR/T1059)
- [ ] Falco restarted and rules active
- [ ] Test write triggered — Falco alert confirmed
- [ ] Cleaned up planted files from /tmp

## Falco Rules Deployed

```yaml
- rule: Write to Temp in Portfolio API
  priority: WARNING
  tags: [filesystem, mitre_collection, T1074]

- rule: Execute from Temp in Portfolio API
  priority: ERROR
  tags: [filesystem, mitre_execution, T1059]
```

## Evidence Artifacts

| Artifact | Location | SHA256 |
|----------|----------|--------|
| Baseline /tmp listing | | |
| Falco rule ConfigMap | | |
| Falco alert log (test write) | | |
| verify.sh output | | |

## POA&M Entry

| ID | Control | Status | Priority | Target Date | Owner |
|----|---------|--------|----------|-------------|-------|
| L7-10 | RS.MI-02 / CIS 3.14 / SI-7 | REMEDIATED | MEDIUM-HIGH | | |

## GRC Section: What Paths Need FIM?

Run this to inventory all writable paths in your namespace:

```bash
kubectl get pods -n anthra -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{range .spec.volumes[*]}  {.name}: {.emptyDir}{"\n"}{end}{end}'
```

| Writable Path | Purpose | FIM Covered? | Compensating Control |
|---------------|---------|-------------|---------------------|
| /tmp | Application temp files | | |
| /var/cache/nginx | Nginx cache (UI pod) | | |
| /var/run | Nginx PID file (UI pod) | | |

## Lessons Learned

**Tool gaps:**
- Falco default rules do not cover /tmp writes in application containers
- readOnlyRootFilesystem is PROTECT (prevents writes to /app) — FIM is DETECT (catches writes to /tmp)
- Both are needed. One without the other leaves a gap.

**Improvement actions:**
1.
2.
3.

---

**Signature:** _______________
**Reviewed by:** _______________
