# L7-09 — RS.MI-01: Detection Without Response

## Scenario Summary

Falco is running. The rule fires. The alert is generated. And then it disappears.

The Portfolio API pod is exec'd into — a clear indicator of compromise that Falco's
`Terminal shell in container` rule is designed to catch. The rule fires correctly.
The alert appears in Falco's stdout. Falcosidekick receives it. And then: nothing.
No Slack message. No webhook. No email. No PagerDuty ticket. The alert routes to
no output that a human will ever see.

The mean time to detect (MTTD) is 2 seconds. The mean time to notify (MTTN) is
infinite. An attacker who execs into a container and exfiltrates data will complete
their operation long before any analyst learns the alert existed.

This scenario tests the gap between detection and response — the gap that IR-4 is
designed to close. A detection engine with no downstream routing is not a detection
capability. It is a log generator. Logs that nobody reads are not security controls.
They are compliance theater.

---

## Control Mapping

| Field            | Value                                                                              |
|------------------|------------------------------------------------------------------------------------|
| CSF Function     | RESPOND                                                                            |
| CSF Category     | RS.MI — Incident Mitigation                                                        |
| CSF Subcategory  | RS.MI-01 — Incidents are contained                                                 |
| CIS v8 Control   | 17.2 — Establish and Maintain Contact Information for Reporting Security Incidents |
| NIST 800-53      | IR-4 — Incident Handling                                                           |
| OSI Layer        | Layer 7 — Application                                                              |
| Severity         | HIGH                                                                               |
| Rank             | C — Analyst configures routing; architecture decisions escalate to B               |
| Difficulty       | Level 1                                                                            |

---

## What Is Already Broken

Falcosidekick is deployed alongside Falco. Falcosidekick is designed to route Falco
alerts to downstream systems: Slack, webhook endpoints, email, PagerDuty, SIEM,
Prometheus Alertmanager, and more.

In the default lab deployment, Falcosidekick has no output channels configured.
The `falcosidekick-ui` is available for viewing alerts in a browser dashboard — but
a dashboard that requires someone to already be watching it is not an alert system.
It is a monitoring system. Monitoring requires someone to be looking. Alerting
routes to someone whether or not they are looking.

The break step makes this gap concrete: exec into a container (an attacker-like
action), confirm Falco fires the alert, then trace where the alert goes — and confirm
it goes nowhere a human will see.

---

## Affected Assets

- **Namespace:** falco (Falco + Falcosidekick)
- **Namespace:** anthra (target workload)
- **Deployment:** portfolio-anthra-portfolio-app-api (exec target)
- **Falco rule triggered:** Terminal shell in container
- **Falcosidekick outputs:** None configured (finding)

---

## Scenario Lifecycle

| Phase       | File                 | What Happens                                                       |
|-------------|----------------------|--------------------------------------------------------------------|
| Baseline    | `baseline.sh`        | Document current Falcosidekick config and output channels          |
| Break       | `break.sh`           | Exec into API pod to trigger Falco rule; confirm no notification   |
| Detect      | `detect.md`          | L1: Find the Falco alert in logs; trace where it was routed        |
| Investigate | `investigate.md`     | Analyze detection vs notification gap; measure MTTD vs MTTN        |
| Fix         | `fix.sh`             | Configure Falcosidekick webhook output; verify routing works       |
| Remediate   | `remediate.md`       | IR-4 lifecycle; MTTD/MTTN concepts; CIS 17.2 requirements          |
| Verify      | `verify.sh`          | Trigger alert again; confirm it reaches configured output          |
| Report      | `report-template.md` | Incident timeline, routing gap POA&M, IR procedure assessment      |

---

## Why This Matters

NIST IR-4 (Incident Handling) requires organizations to implement an incident handling
capability that includes preparation, detection, analysis, containment, eradication,
and recovery. A detection engine with no notification path provides detection and
analysis — but it cannot trigger containment. Containment requires a human to act.
A human cannot act on an alert they never received.

RS.MI-01 (Incidents are contained) is a Respond-function outcome. Containment requires
that someone receive the alert, assess it, and take action. The chain breaks completely
if the alert never leaves the Falco log stream.

CIS 17.2 requires that contact information for reporting security incidents be
established and maintained. The spirit of this control is that when something fires,
there is a known person or system that receives the notification. A Falcosidekick with
zero configured outputs satisfies no interpretation of CIS 17.2.

In a FedRAMP assessment, the auditor will ask: "If Falco detects a terminal shell in
a production container at 2am, who gets paged?" If the answer is "nobody, unless
someone happens to be watching the dashboard," the IR-4 control is not satisfied.

---

## CySA+ OBJ 2.5 Teaching Point

Incident response requires a notification path. CySA+ OBJ 2.5 covers the IR lifecycle
and the difference between detection tools and incident response capability.

Detection tools identify events. Incident response capability transforms identified
events into coordinated human action. The gap between detection and response is exactly
where this scenario lives.

MTTD (mean time to detect): how fast the tool identifies the event.
MTTN (mean time to notify): how fast a human learns about it.
MTTR (mean time to respond): how fast the team contains the incident.

A best-in-class MTTD with infinite MTTN means MTTR is also infinite. Falco running
with no alert routing is not a security control. It is a very sophisticated log file.

---

## References

- NIST 800-53 Rev 5: IR-4 Incident Handling
- NIST CSF 2.0: RS.MI-01 Incidents are contained
- CIS Controls v8: 17.2 Establish and Maintain Contact Information
- Falcosidekick output configuration: https://github.com/falcosecurity/falcosidekick
- Falco rules: https://falco.org/docs/rules/
- CompTIA CySA+ Exam Objective 2.5: Explain concepts related to attack methodology frameworks
