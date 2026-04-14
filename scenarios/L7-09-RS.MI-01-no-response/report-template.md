# L7-09 — Report Template: Detection Without Response

**Scenario:** L7-09-RS.MI-01-no-response
**Analyst:** [Your name]
**Date:** [YYYY-MM-DD]
**System:** Anthra-SecLAB / k3d-seclab / namespace: anthra + falco
**Classification:** [Internal / Confidential]

---

## Incident Summary

A terminal shell was spawned inside the Portfolio API container (`portfolio-anthra-portfolio-app-api`)
in the `anthra` namespace at [TIMESTAMP]. Falco detected the event via its
`Terminal shell in container` rule within approximately 2 seconds. Falcosidekick
received the alert. No notification was delivered to any analyst, Slack channel,
SIEM, or other human-facing system.

**Detection status:** Functional (Falco fired correctly)
**Response status:** Broken (no routing configured in Falcosidekick)
**MTTD:** approximately 2 seconds
**MTTN before fix:** Infinite (no output configured)
**MTTN after fix:** [measurable -- fill in from verify.sh output]

---

## Alert Details

| Field | Value |
|-------|-------|
| Rule Triggered | Terminal shell in container |
| Priority | WARNING / HIGH |
| Container | api |
| Namespace | anthra |
| Pod | [pod name from Falco log] |
| Command | /bin/sh -c echo 'attacker-simulation...' |
| User | [user from Falco log -- likely root] |
| Timestamp (T0) | [from Falco log] |
| Falco Pod | [from kubectl get pods -n falco] |

---

## Alert Routing: Before / After

| Output Channel | Before Fix | After Fix |
|----------------|-----------|----------|
| Slack | Not configured | [Configured / Not configured] |
| PagerDuty | Not configured | [Configured / Not configured] |
| Webhook | Not configured | [Configured / Not configured] |
| Alertmanager | Not configured | [Configured / Not configured] |
| Splunk (gp_security) | Not configured | [Configured / Not configured] |
| Stdout (Falcosidekick log) | Not enabled | Enabled |
| Dashboard (Falcosidekick UI) | Available | Available |

---

## MTTD / MTTN / MTTR Measurement

| Metric | Value Before Fix | Value After Fix | Target (FedRAMP HIGH) |
|--------|-----------------|-----------------|----------------------|
| MTTD | ~2 seconds | ~2 seconds | < 60 seconds |
| MTTN | Infinite | [fill in] | < 5 minutes |
| MTTR | Infinite | [fill in -- depends on IR playbook] | < 30 minutes |

**Key finding:** MTTD is excellent. MTTN was infinite. The detection capability exists
but does not produce a response capability. These are not the same thing.

---

## IR-4 Phase Assessment

| IR-4 Phase | Before Fix | After Fix |
|------------|-----------|----------|
| Preparation | Partial (no playbook, no routing) | Partial (routing configured; playbook needed) |
| Detection | Functional | Functional |
| Analysis | Manual only (dashboard) | Notified analyst can begin triage |
| Containment | Not possible (infinite MTTN) | Possible (analyst now notified) |
| Eradication | Not possible | Possible |
| Recovery | Not possible | Possible |

---

## Plan of Action and Milestones (POA&M)

### Item 1 -- No Alert Routing Configured in Falcosidekick

| Field | Value |
|-------|-------|
| POAM-ID | L7-09-[DATE]-001 |
| Control | IR-4 (Incident Handling) |
| CSF Subcategory | RS.MI-01 (Incidents are contained) |
| CIS v8 | 17.2 -- Establish and Maintain Contact Info for Incidents |
| Finding | Falcosidekick has no output channels configured; alerts go nowhere |
| Severity | HIGH |
| Date Identified | [YYYY-MM-DD] |
| Remediation Due | [YYYY-MM-DD + 30 days] |
| Remediation Action | Configure Slack/PagerDuty output in Falcosidekick Helm values |
| Date Remediated | [YYYY-MM-DD] |
| Verification Method | Trigger exec; confirm alert appears in configured output |
| Status | [Open / Closed] |

### Item 2 -- No IR Playbook for Terminal Shell in Container

| Field | Value |
|-------|-------|
| POAM-ID | L7-09-[DATE]-002 |
| Control | IR-4 (Incident Handling) / IR-2 (Incident Response Training) |
| Finding | No documented playbook for responding to shell-in-container alerts |
| Severity | MEDIUM |
| Date Identified | [YYYY-MM-DD] |
| Remediation Due | [YYYY-MM-DD + 60 days] |
| Remediation Action | Write and test IR playbook; include in on-call runbook |
| Status | Open |

### Item 3 -- No Tested Alert Routing Validation

| Field | Value |
|-------|-------|
| POAM-ID | L7-09-[DATE]-003 |
| Control | IR-3 (Incident Response Testing) |
| Finding | Alert routing was never tested after Falcosidekick deployment |
| Severity | MEDIUM |
| Date Identified | [YYYY-MM-DD] |
| Remediation Due | [YYYY-MM-DD + 60 days] |
| Remediation Action | Add alert routing test to post-deployment checklist; test after every upgrade |
| Status | Open |

---

## GRC Section: Risk Committee Presentation

**Q: How did we have Falco deployed but no notifications working?**
A: Falco and Falcosidekick were deployed as part of the runtime security stack. The
deployment was confirmed to be running. The alert routing configuration -- the outputs
section of Falcosidekick -- was left at default (empty). This was not caught because
there was no post-deployment test verifying that an alert would actually reach a human.
The detection tool worked. The response infrastructure was never validated.

**Q: What is our exposure? Did an attacker use this gap?**
A: This scenario was a training exercise. In production, the gap means any exec into
a container would have generated a Falco alert that reached no human. We cannot confirm
or deny whether the gap was exploited in a real environment without reviewing all Falco
log history. Recommend a log review for `Terminal shell in container` events in the
past 30 days.

**Q: How do we prevent this from happening again?**
A: Three actions: (1) Configure production-grade outputs in Falcosidekick before any
cluster goes to production. (2) Add an alert routing test to the post-deployment
checklist -- exec into a test container, confirm the alert reaches the configured
destination. (3) Test routing after every Falco or Falcosidekick upgrade, as upgrades
can reset configuration.

---

## Recommendations

1. Immediate: Configure at minimum one production-grade output (Slack or PagerDuty)
2. Immediate: Configure Splunk gp_security index as secondary output for SIEM correlation
3. Short-term: Write IR playbook for Terminal shell in container (MTTR < 30 minutes)
4. Short-term: Add alert routing test to post-deployment checklist
5. Long-term: Implement automated alert routing validation (fire synthetic alert, confirm receipt)
6. Long-term: Configure priority-based routing (CRITICAL to PagerDuty, WARNING to Slack)

---

## References

- NIST 800-53 Rev 5: IR-4 Incident Handling
- NIST CSF 2.0: RS.MI-01 Incidents are contained
- CIS Controls v8: 17.2
- FedRAMP IR reporting SLA: 1 hour for incidents affecting FedRAMP data
- Falcosidekick: https://github.com/falcosecurity/falcosidekick
- CompTIA CySA+ OBJ 2.5, 3.1
