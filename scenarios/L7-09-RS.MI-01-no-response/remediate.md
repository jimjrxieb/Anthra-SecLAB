# L7-09 — Remediate: Detection Without Response

**Phase:** REMEDIATE
**CySA+ Reference:** OBJ 2.5 — IR lifecycle concepts; OBJ 3.1 — IR process
**Objective:** Understand the complete incident response capability requirement and how to build it

---

## The Detection-Response Gap

Detection without response is not security. It is evidence collection with no consumer.

The gap this scenario exposes is not a Falco configuration problem. Falco is working
correctly. The gap is a process and architecture problem: no defined path from
detection to human action.

Fixing Falcosidekick output is the technical remediation. Understanding why the path
must exist — and what IR-4 requires of it — is the remediation mindset.

---

## CIS 17.2: Why Contact Information Is Not Enough

CIS Control 17.2 is titled "Establish and Maintain Contact Information for Reporting
Security Incidents." The phrasing suggests a simple list of names and phone numbers.
In practice, for a Kubernetes environment with automated detection, CIS 17.2 requires:

1. A routing path: Falco → Falcosidekick → [Slack / PagerDuty / SIEM]
2. A defined recipient: the on-call security analyst or automated triage queue
3. A tested path: you have confirmed the routing works (not just configured it)
4. A documented escalation path: L1 sees alert → L2 triages → incident commander acts

Contact information with no routing path is useless. A phone number for the security
team does not help if the security team never receives the alert that should prompt them
to call back.

---

## MTTD, MTTN, MTTR — The Three Metrics That Matter

**MTTD (Mean Time to Detect):** Time from malicious event to alert generation.
- Falco's MTTD for shell-in-container: 1-3 seconds (eBPF kernel events)
- Target: under 60 seconds for HIGH and CRITICAL events
- This lab: 2 seconds. Excellent.

**MTTN (Mean Time to Notify):** Time from alert generation to human awareness.
- Before fix: infinity (no routing configured)
- After fix: seconds (Falcosidekick routes to configured output)
- Target: under 5 minutes for HIGH and CRITICAL events (for 24/7 coverage)
- FedRAMP requirement: incidents must be reported within 1 hour of identification

**MTTR (Mean Time to Respond):** Time from human awareness to containment action.
- Cannot start until MTTN completes
- Depends on: IR playbook quality, analyst experience, tooling availability
- Target: under 30 minutes for containment of active shell-in-container event

The relationship is sequential. MTTR cannot beat MTTN. MTTN cannot beat MTTD.
Optimizing only MTTD (which is what most teams do by deploying Falco) without
addressing MTTN produces a false sense of security. The tool is fast. The process
is broken.

---

## IR-4 Incident Handling: The Six Phases

IR-4 requires a complete incident handling capability. Map the Falco ecosystem to
each phase:

**Phase 1 — Preparation:**
- Falco rules tuned to the workload (see L7-05 alert fatigue scenario)
- Falcosidekick outputs configured to at least two channels (primary + backup)
- IR playbook written and accessible to on-call analyst
- Tabletop exercise completed to validate the playbook

**Phase 2 — Detection and Analysis:**
- Falco fires the alert (done)
- Falcosidekick routes to Slack / PagerDuty (this fix)
- L1 analyst receives notification and begins triage
- L1 classifies severity: is this a real exec (HIGH) or a known-good process (FP)?

**Phase 3 — Containment:**
- Isolate the affected pod: `kubectl cordon` the node or delete the pod
- Apply a NetworkPolicy to cut egress from the namespace
- Capture forensic evidence: logs, pod state, network connections, memory dump if available

**Phase 4 — Eradication:**
- Identify how the attacker got in (initial access vector)
- Remove the malicious artifact (if any was planted)
- Rotate any credentials that may have been exposed (service account tokens, mounted secrets)

**Phase 5 — Recovery:**
- Redeploy the workload from a clean image
- Verify no persistence mechanisms remain
- Restore normal traffic

**Phase 6 — Lessons Learned:**
- Document the full incident timeline
- Identify what failed (routing gap, insufficient NetworkPolicy, etc.)
- Update the IR playbook
- File the POA&M update

In this scenario, everything from Phase 3 forward was blocked because MTTN was
infinite. Phases 3-6 cannot execute without a human knowing the alert fired.

---

## What a Complete Alert Routing Architecture Looks Like

Minimum viable configuration for FedRAMP:

```
[Falco] → [Falcosidekick] → [Primary: Slack/PagerDuty] + [Secondary: SIEM/Splunk]
                          → [Tertiary: Alertmanager] (for K8s-native routing)
```

- Primary: immediate human notification (Slack, PagerDuty)
- Secondary: audit trail and correlation (SIEM, Splunk gp_security index)
- Tertiary: automated response trigger (Alertmanager → silencers, runbooks)

The Splunk index `gp_security` is the GP-Copilot standard destination for Falco events.
See `03-RUNTIME-SECURITY/05-splunk-integration/` for setup instructions.

**Minimum viable for lab:**
- Stdout output enabled on Falcosidekick (verifiable via kubectl logs)
- At least one external output configured before production go-live

---

## GRC: Prioritizing Alert Routing

In a risk committee conversation, the argument is simple:

"We have a detection capability. We do not have a response capability. Detection
without response has the same security outcome as no detection at all — the attacker
completes their objective before any human learns the alert existed. The cost to fix
this is one webhook URL or Slack integration. The cost of not fixing it is an
undetected breach with infinite MTTR."

The control gap is RS.MI-01: incidents cannot be contained if the team is never
notified. The remediation cost is low. The risk of not remediating is high. This
should be the easiest risk acceptance conversation in the room — and the answer
should be to fix it immediately.

---

## Alert Severity Routing Best Practice

Not all alerts require the same routing. Configure Falcosidekick to route by priority:

| Falco Priority | Destination | Response SLA |
|---------------|-------------|-------------|
| CRITICAL | PagerDuty (immediate page) + SIEM | < 5 minutes |
| HIGH | Slack #security-alerts + SIEM | < 15 minutes |
| WARNING | Slack #security-monitoring + SIEM | < 1 hour |
| NOTICE | SIEM only | Next business day |
| INFO | SIEM only (or discard) | Review weekly |

Routing all priorities to the same channel creates alert fatigue. Routing only
CRITICAL creates gaps where HIGH events go unnoticed. The configuration should
match the priority to the response expectation.

---

## References

- NIST 800-53 Rev 5: IR-4 Incident Handling
- NIST CSF 2.0: RS.MI-01 Incidents are contained
- CIS Controls v8: 17.2 Establish and Maintain Contact Information
- FedRAMP IR requirements: 1-hour reporting SLA for FedRAMP data incidents
- Falcosidekick outputs: https://github.com/falcosecurity/falcosidekick/blob/master/README.md
- Splunk integration: GP-CONSULTING/03-RUNTIME-SECURITY/05-splunk-integration/
- CompTIA CySA+ Exam Objectives 2.5 and 3.1
