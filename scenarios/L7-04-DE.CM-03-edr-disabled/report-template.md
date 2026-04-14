# L7-04 DE.CM-03 — Exercise Fill-In Template

**Finding:** Runtime Monitoring (Falco) Offline — EDR Coverage Gap
**Date:** [YYYY-MM-DD]
**Analyst:** [Name / Badge]
**Status:** [ ] Open  [ ] Remediated  [ ] Verified  [ ] Closed

---

## Finding Summary

| Field | Value |
|-------|-------|
| Asset | Falco DaemonSet — namespace: falco |
| Cluster | k3d-seclab |
| Nodes affected | All — ___ nodes, 0 Falco pods during gap |
| CSF | DE.CM-03 — Computing hardware, software, services monitored |
| CIS v8 | 13.7 — Deploy Host-Based Intrusion Detection Solution |
| NIST 800-53 | SI-4 — Information System Monitoring |
| Severity | HIGH |
| Rank | C |
| Gap Start | _______________ |
| Gap End | _______________ |
| Gap Duration | _______________ |
| Detection Lag | _______________ |

---

## Timeline

| Time (UTC) | Event |
|------------|-------|
| [YYYY-MM-DDTHH:MM] | Baseline captured (baseline.sh) — Falco pods: ___ |
| [YYYY-MM-DDTHH:MM] | Break applied (break.sh) — bad nodeSelector injected |
| [YYYY-MM-DDTHH:MM] | Last Falco pod terminated — gap START |
| [YYYY-MM-DDTHH:MM] | Gap detected by analyst via: _______________ |
| [YYYY-MM-DDTHH:MM] | Investigation documented (investigate.md) |
| [YYYY-MM-DDTHH:MM] | Fix applied (fix.sh) — bad nodeSelector removed |
| [YYYY-MM-DDTHH:MM] | All Falco pods Running — gap END |
| [YYYY-MM-DDTHH:MM] | Verification passed (verify.sh) — ___ / ___ checks PASS |

**Total monitoring gap duration:** _______________
**Detection lag (gap start to analyst noticed):** _______________

---

## Detection Method

How did you first identify the monitoring gap?

- [ ] Grafana dashboard: Falco event rate went flat at _______________
- [ ] Prometheus: `up{job="falco"}` showed 0 at _______________
- [ ] kubectl: `kubectl get pods -n falco` showed 0 pods at _______________
- [ ] Alertmanager: Alert `_______________` fired at _______________
- [ ] None of the above — I did not detect it independently

**Detection notes:** _______________

---

## Falco Pod Count

| Metric | Before Break | During Gap | After Fix |
|--------|-------------|------------|-----------|
| Falco pods running | ___ | 0 | ___ |
| Nodes in cluster | ___ | ___ | ___ |
| Coverage % | 100% | 0% | 100% |
| Falcosidekick pods | ___ | ___ | ___ |

---

## Root Cause

A bad nodeSelector `{seclab-break: evict}` was injected into the Falco DaemonSet
spec. No node in the cluster carries that label. Kubernetes evicted all existing
Falco pods and could not schedule replacements. Runtime syscall-level detection
was absent across all nodes for the duration of the gap.

**How would this happen in production?**
_______________
(e.g., bad Helm values override, botched CI pipeline, manual kubectl error)

---

## Activity During Monitoring Gap

**Was any suspicious activity detected in available logs during the gap window?**
- [ ] Yes — describe: _______________
- [ ] No — no evidence found in pod logs, API audit logs, or network flow logs
- [ ] Unknown — insufficient logging to determine

**Important:** Absence of evidence is not evidence of absence. Falco was the layer
that would detect syscall-level activity. Activity that would normally produce
alerts was completely invisible during this window.

**Logs reviewed:**
- [ ] anthra pod logs
- [ ] Kubernetes API audit log
- [ ] Falcosidekick forwarded events (pre-gap)
- [ ] Splunk gp_security index
- [ ] Other: _______________

---

## Remediation Applied

- [ ] baseline.sh ran — Falco pod count and nodeSelector captured
- [ ] break.sh ran — bad nodeSelector confirmed injected
- [ ] investigate.md completed — gap window and root cause documented
- [ ] fix.sh ran — bad nodeSelector removed, pods rescheduled
- [ ] verify.sh ran — ___ / ___ checks passed

---

## POA&M Entry — DE.CM-03

| Field | Value |
|-------|-------|
| POA&M ID | POA&M-L7-04-[YYYY-MM-DD] |
| Control ID | DE.CM-03 / SI-4 |
| CIS Control | 13.7 — Deploy Host-Based IDS |
| Finding | Runtime monitoring (Falco) offline — EDR coverage gap |
| Severity | HIGH |
| Status | [ ] Open  [ ] In Progress  [ ] Completed |
| Gap Start | _______________ |
| Gap End | _______________ |
| Gap Duration | _______________ |
| Nodes Affected | All — ___ nodes, 0 Falco pods |
| Root Cause | Bad DaemonSet nodeSelector {seclab-break: evict} |
| Corrective Action | Remove bad nodeSelector; add FalcoPodNotRunning Alertmanager rule |
| Due Date | _______________ |
| Responsible Party | _______________ |
| Verified | Yes / No |

---

## GRC Section — Justifying the Risk During the Monitoring Gap

**Question: How would you justify the risk during the monitoring gap to an auditor?**

**Compensating controls that were active during the gap:**

| Control | Status | What It Covered |
|---------|--------|-----------------|
| Kubernetes API audit log | Active | API-level calls logged (not syscall-level) |
| NetworkPolicy | Active | Egress/ingress enforced |
| Pod Security Standards | Active | Admission policy enforced |
| Falcosidekick | Running | Alert pipeline ready; no Falco events to forward |
| Splunk SIEM | Active | Other feeds active; Falco feed empty |
| Image scanning (Trivy) | Pre-deployment only | Images scanned before deployment |

**What these controls did NOT cover:**
- Syscall-level activity inside running containers
- Interactive shell spawns in existing pods
- Credential access (reading /etc/shadow, service account tokens)
- Privilege escalation attempts by running processes
- Crypto mining and exfiltration via permitted ports

**Risk acceptance statement (fill in):**

During the monitoring gap from _______________ to _______________ (duration: _______________),
runtime syscall-level detection was completely absent across ___ cluster nodes.
Compensating controls listed above were active and provided partial coverage at
the network and API layers. No evidence of exploitation was found in reviewed logs,
but syscall-level activity during this window remains unverifiable.
Risk accepted by: _______________ (name/role) on _______________.

---

## Lessons Learned

1. Detection lag was _______________. Acceptable? What should the target SLA be?

2. Was an Alertmanager rule configured for Falco pod count? Y / N
   If No: adding `FalcoPodNotRunning` is a required corrective action.

3. Who can patch the falco DaemonSet? Should RBAC restrict this further?

4. What could an attacker accomplish during a _______________ minute unmonitored window?

5. If this happened during an active incident response, how does the gap change your confidence in the investigation?

6. One process change to prevent recurrence: _______________

---

## Improvement Actions

- [ ] Add Alertmanager rule: `FalcoPodNotRunning` fires if Falco pods = 0 for > 5m
- [ ] Restrict write access to `falco` namespace via RBAC
- [ ] Add Kyverno policy to protect Falco DaemonSet nodeSelector
- [ ] Schedule periodic verify.sh as a cronjob or CI check
- [ ] Document the gap in the SOC runbook as a known monitoring blind spot pattern

---

## Sign-Off

| Role | Name | Date |
|------|------|------|
| Analyst (completed exercise) | _______________ | _______________ |
| Team Lead (reviewed) | _______________ | _______________ |
| ISSO (POA&M accepted) | _______________ | _______________ |
