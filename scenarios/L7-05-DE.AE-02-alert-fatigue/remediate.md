# L7-05 — DE.AE-02: Remediate Phase

## Why SIEM Tuning Matters (CIS 8.11 and AU-6)

This document explains the "why" behind the fix: what alert fatigue actually costs,
why the industry has a named control for tuning, and how to document your decisions
so they hold up in an audit.

---

## The Real Cost of False Positives

A false positive is not a minor inconvenience. It is a training event.

Every time an analyst opens Falco output and sees a known-good process fire a rule,
the analyst updates their mental model: "this rule is noise." After enough repetitions,
the analyst stops checking. The behavior is rational. The outcome is catastrophic.

The attack surface created by alert fatigue is not in the code. It is in the analyst.
A threat actor who understands your SIEM ruleset can operate inside your blind spots
indefinitely — not by evading detection, but by triggering noise.

Alert fatigue is the mechanism by which a functioning detection layer becomes
indistinguishable from no detection layer at all.

---

## Before vs. After: The Tuning Impact

| Metric | Before Tuning | After Tuning | Target |
|--------|--------------|--------------|--------|
| Alerts per hour | ~500 | ~20-40 | < 50 |
| False positive rate | ~95% | ~10-15% | < 10% |
| Custom Portfolio rules | 0 | 3 | 3-5 per app tier |
| Rules with AU-6 justification | 0 | All exceptions | 100% |
| Analyst review completion rate | Low (fatigue) | High (manageable) | > 90% |
| Mean time to detect (real event) | Unknown | Measurable | < 5 min |

The goal is not zero alerts. Zero alerts means either nothing is happening or nothing
is being monitored. The goal is the lowest alert rate that still catches everything
real. Every alert above that floor is noise. Every noise alert costs analyst time and
erodes analyst trust.

---

## CIS 8.11 — Tune Security Event Alert Thresholds

CIS Control 8.11 is explicit: organizations must tune security event alert thresholds
to balance operational and security needs.

What "tuned" means in practice:

1. Each active rule has a known expected trigger rate in the production environment
2. Rules with high false positive rates either have documented exceptions or are disabled
3. New workloads trigger a tuning review before their alerts go live
4. The tuning decisions are logged and reviewed on a defined schedule

What "not tuned" looks like (the default state we fixed):

1. Factory rules applied to all workloads with no customization
2. No record of which rules have acceptable false positive rates
3. No exceptions for known application behavior
4. Alert volumes that exceed analyst review capacity

CIS 8.11 is not a preference. It is a named control. Operating on untuned defaults
is a direct gap against this control.

---

## NIST AU-6 — Audit Record Review, Analysis, and Reporting

AU-6 requires three things:

**Review:** Audit records are looked at. If analysts have stopped looking because the
volume is overwhelming, AU-6 is not being met regardless of what the tooling does.

**Analysis:** What is found in audit records is analyzed to identify anomalies. An
analyst who scans 500 alerts and closes the tab has performed review but not analysis.
AU-6 requires both.

**Reporting:** When analysis identifies something significant, it is reported through
defined channels. If real threats hide in noise and are never identified, they are
never reported. The reporting requirement fails at the analysis step.

Alert fatigue attacks AU-6 at the review and analysis steps simultaneously.

---

## How to Document Alert Tuning Decisions for AU-6

Every Falco rule exception must be documented before it is applied. The documentation
goes in three places:

**1. In the ConfigMap itself** (machine-readable, version-controlled):
```yaml
annotations:
  seclab.au6-justification: "Suppress health probe reads; pip in init containers"
  seclab.tuned-by: "L2 analyst Jane Smith"
  seclab.reviewed-date: "2026-04-12"
  seclab.next-review: "2026-07-12"
```

**2. In your GRC system** (auditor-readable):
```
Exception ID:   EXC-2026-001
Rule suppressed: Launch Package Management Process in Container
Scope:          pip/pip3 in init containers only (container.name = init)
Justification:  Portfolio uses pip to install pinned dependencies at container
                startup. This is expected, version-controlled behavior that does
                not represent an active package install threat.
Risk accepted:  Low. Limited to init containers, not runtime containers.
Approved by:    [L2 analyst name]
Review date:    2026-04-12
Next review:    2026-07-12
```

**3. In your incident/change management system** (traceability):
Create a change record for each tuning deployment. The auditor needs to trace:
- When the rule was suppressed
- Who approved it
- What business justification exists
- When it was last reviewed

---

## Quarterly Review Requirement

Alert tuning is not a one-time activity. CIS 8.11 implies ongoing calibration.
AU-6 requires review at defined frequencies.

Minimum quarterly review checklist:
- [ ] Are all documented exceptions still valid? (Application still behaves the same way?)
- [ ] Have any new workloads been added that require new exceptions?
- [ ] Have any new custom rules become necessary for new application features?
- [ ] What was the true positive rate for the quarter? (Did any custom rules fire?)
- [ ] What was the false positive rate? (Did any suppressed rules miss a real event?)
- [ ] Are there new threat patterns for the Portfolio application that need rules?

File the quarterly review as AU-6 evidence. The auditor expects to see both the
current rule set and the history of changes with justifications.

---

## What Stays Out of Scope

Things you should not suppress without escalating to B-rank:

- `Terminal shell in container` for non-init containers (always investigate)
- `Container drift detected` (new binary in running container)
- Any rule that fired an actual true positive in the last 90 days
- Rules covering privilege escalation paths
- Rules watching /etc/kubernetes/, TLS cert paths, or kubeconfig files

When in doubt: escalate before suppressing. A rule that fires twice a week on
a real threat is not noise. A rule that fires 500 times a day on health checks is.
The difference is the investigation — which is exactly what AU-6 requires you to do.

---

## Next Step

Run `verify.sh` to confirm noise reduction and custom rule coverage.
