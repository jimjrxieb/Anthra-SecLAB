# L7-05 — DE.AE-02: Report Template

Fill in all `[brackets]` before submitting. This template produces:
1. A GRC finding record (AU-6 / CIS 8.11 / DE.AE-02)
2. A POA&M entry suitable for FedRAMP Moderate documentation
3. An audit evidence package for the alert tuning decision log

---

## Finding Record

| Field | Value |
|-------|-------|
| Finding ID | SEC-[YYYY]-[NNN] |
| Date identified | [Date you ran baseline.sh] |
| Identified by | [Your name / role] |
| System | k3d-seclab — anthra namespace |
| Finding title | Falco alert tuning not implemented; alert fatigue condition present |
| CSF subcategory | DE.AE-02 — Potentially adverse events analyzed |
| CIS v8 control | 8.11 — Tune Security Event Alert Thresholds |
| NIST 800-53 | AU-6 — Audit Record Review, Analysis, and Reporting |
| Severity | MEDIUM |
| Status | [Open / Remediated] |

---

## Alert Metrics — Before and After

| Metric | Before Tuning | After Tuning | Target |
|--------|--------------|--------------|--------|
| Alerts per hour | [Fill from baseline.sh] | [Fill from verify.sh] | < 50 |
| False positive rate | [Fill from investigate.md Step 3] | [Fill from verify.sh] | < 10% |
| Custom rules (Portfolio-specific) | 0 | 3 | >= 3 |
| Rules with AU-6 justification | 0 | All exceptions | 100% |
| Noise reduction percentage | N/A | [Calculate: (before-after)/before * 100]% | > 80% |

---

## Top 5 Rules Tuned

Document each rule you changed. This is required for AU-6 evidence.

| Rule Name | Action | Justification | Approved by | Review date |
|-----------|--------|--------------|-------------|------------|
| Launch Package Management Process in Container | Exception added | pip in init containers is expected startup behavior. Not a runtime threat. | [Name] | [Date] |
| Read sensitive file untrusted | Exception added (scope: /proc/self/*, /etc/hostname) | Health probe reads on every probe interval. Not initiated by application code. | [Name] | [Date] |
| [3rd rule you tuned] | [Action] | [Justification] | [Name] | [Date] |
| [4th rule] | | | | |
| [5th rule] | | | | |

---

## Custom Rules Added

| Rule Name | Priority | Trigger Condition | What It Detects |
|-----------|---------|-------------------|----------------|
| Portfolio API Shell Spawn | CRITICAL | sh/bash spawned in api container | Command injection, container compromise |
| Portfolio API Credential File Read | ERROR | /etc/passwd or /etc/shadow read in api container | Credential dumping, privilege escalation |
| Portfolio API Unexpected Outbound Connection | WARNING | TCP to non-RFC1918 IP from api container | Data exfiltration, C2 callback |

---

## Verification Evidence

Custom rule detection test (required for audit):

```
Test performed:     kubectl exec -n anthra deployment/[api-deploy] -- sh -c 'echo test'
Expected result:    Falco fires 'Portfolio API Shell Spawn' rule at CRITICAL priority
Actual result:      [PASS / FAIL — fill in from verify.sh output]
Tested by:          [Your name]
Test date:          [Date]
```

Alert rate comparison:

```
Baseline rate:      [X] alerts/hour (timestamp: [from baseline.sh])
Post-tuning rate:   [Y] alerts/hour (timestamp: [from verify.sh])
Reduction:          [Z]%
Sample window:      [N] log lines across [M] seconds
```

---

## POA&M Entry

**Plan of Action and Milestones — DE.AE-02 / CIS 8.11 / AU-6**

```
POA&M ID:            POA-[YYYY]-[NNN]
Control:             AU-6 / CIS 8.11 / DE.AE-02
Finding:             Alert fatigue — untuned Falco default rules generate
                     ~500 alerts/hour with ~95% false positive rate in anthra
                     namespace. Analysts have ceased routine review due to volume.
                     No custom rules exist for Portfolio-specific threat patterns.

Root cause:          Falco deployed with factory default community ruleset.
                     No tuning performed for Portfolio application behavior.
                     No exceptions for known-good processes (health probes, pip).
                     No custom rules for application-specific threat indicators.

Impact:              Detection layer is analytically non-functional despite being
                     technically operational. Real threats hide in noise. AU-6
                     review and analysis requirements cannot be met at this volume.

Remediation:         Deploy custom rules ConfigMap (falco-custom-portfolio-rules)
                     with documented exceptions and Portfolio-specific detection
                     rules. Restart Falco to reload ruleset.

Corrective actions:
  1. [DONE / DATE] Deploy falco-custom-portfolio-rules ConfigMap
  2. [DONE / DATE] Add exception: pip in init containers (AU-6 justification filed)
  3. [DONE / DATE] Add exception: health probe file reads (AU-6 justification filed)
  4. [DONE / DATE] Add custom rule: Portfolio API Shell Spawn (CRITICAL)
  5. [DONE / DATE] Add custom rule: Portfolio API Credential File Read (ERROR)
  6. [DONE / DATE] Add custom rule: Portfolio API Unexpected Outbound Connection (WARNING)
  7. [TARGET DATE] Establish quarterly alert tuning review process
  8. [TARGET DATE] Document AU-6 review cadence in security plan

Milestones:
  Date opened:       [Date]
  Scheduled fix:     [Date + 30 days]
  Verified closed:   [Date verify.sh passed]

Compensating controls (during remediation period):
  Manual log review at 2x frequency (daily instead of weekly) until tuning complete.
  Increased analyst watch on [top noisy rule] for potential true positives.
```

---

## Lessons Learned

Answer these three questions. They go in your AU-6 review cadence documentation.

**1. What triggered the alert fatigue condition?**

[Fill in: was it a new workload, a dependency update, a new Falco version with
more rules, or was tuning never done from day one?]

**2. How would you detect alert fatigue earlier next time?**

[Possible answers: alert rate threshold alert in Alertmanager; weekly FP rate metric;
analyst survey on alert quality; automated FP rate calculation in Splunk dashboard]

**3. What process change prevents this from recurring?**

[Recommended answer: every new workload deployment triggers a Falco tuning review
before the workload goes live. New rules are never applied unreviewed to production.
Quarterly review of all active rules and exceptions is mandatory.]

---

## AU-6 Review Process Documentation

File this section in your GRC system under AU-6 supporting evidence.

```
Review frequency:    [Daily / Weekly — choose and justify based on alert volume]
Review owner:        [Name or role]
Review method:       [Falcosidekick dashboard URL] + Splunk gp_security index
Review duration:     [Estimated time per review session]

Escalation path:
  L1 identifies potential true positive → creates L2 triage ticket within [X] hours
  L2 confirms true positive → creates incident ticket within [Y] hours
  L2 identifies pattern requiring rule change → creates change record

False positive suppression approval:
  L1 identifies FP rule → documents in GRC ticket
  L2 approves exception → exception written into ConfigMap
  Exception reviewed quarterly → confirmed or removed

Evidence retention:
  Falco logs → Splunk (gp_security index) → retained [90 / 365] days
  Alert review records → GRC system → retained [1 year]
  Tuning decisions → ConfigMap annotations + GRC tickets → retained indefinitely
```

---

## Sign-off

| Role | Name | Date | Signature |
|------|------|------|-----------|
| Analyst (L1) | | | |
| Reviewer (L2) | | | |
| GRC owner | | | |
