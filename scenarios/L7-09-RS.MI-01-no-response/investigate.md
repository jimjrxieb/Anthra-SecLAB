# L7-09 — Investigate: Detection Without Response

**Phase:** INVESTIGATE
**CySA+ Reference:** OBJ 2.5 — Explain concepts related to attack methodology frameworks
**Objective:** Analyze the detection-to-notification gap, measure MTTD vs MTTN, assess IR procedure gap

---

## Context

You have confirmed the finding: Falco detected the exec, Falcosidekick received the
alert, and no human was notified. Now you need to understand the scope of the problem —
what an attacker could accomplish during the notification gap — and document it in a
way that explains the risk to a risk committee or auditor.

---

## Step 1 — Reconstruct the Incident Timeline

Build the incident timeline from available data. This is what IR-4 requires for the
"detection" and "analysis" phases.

```bash
# Get the exact Falco alert timestamp
FALCO_POD=$(kubectl get pods -n falco \
  -l app.kubernetes.io/name=falco \
  --no-headers | awk '{print $1}' | head -1)

kubectl logs -n falco "${FALCO_POD}" --tail=100 2>/dev/null | \
  grep -iE "(shell|exec|terminal|spawn)" | tail -5
```

Extract from the log:
- Alert timestamp (T0): when Falco detected the exec
- Rule fired: `Terminal shell in container`
- Container: `api` in namespace `anthra`
- Command: the shell command that was run
- User: the user inside the container (likely root)

Your timeline:

```
T0 + 0:00   Attacker execs into container
T0 + 0:02   Falco detects the shell spawn and generates alert
T0 + 0:02   Falcosidekick receives the alert via HTTP
T0 + ????   Analyst receives notification    <-- UNKNOWN (no routing configured)
T0 + ????   Analyst begins investigation     <-- UNKNOWN
T0 + ????   Containment action taken         <-- UNKNOWN
```

The unknowns are all downstream of the routing gap. If MTTN is infinite, every
subsequent time metric is also infinite.

---

## Step 2 — What Could an Attacker Do During the Gap?

Model the attacker's opportunity window. If the alert fires at T0 and nobody sees it
for 24 hours (realistic for a dashboard-only system with no after-hours coverage),
what can an attacker accomplish?

```
0-30 seconds:  Confirm they have a shell. Read /etc/passwd, /etc/hosts.
               Check what secrets are mounted: ls /var/run/secrets/
               Check environment variables: env | grep -iE "(key|token|secret|pass)"

30-120 seconds: Exfiltrate mounted secrets.
               cat /var/run/secrets/kubernetes.io/serviceaccount/token
               Try to curl the Kubernetes API with the service account token.

2-10 minutes:  If the service account has list/get on secrets cluster-wide:
               Query the API for secrets in other namespaces.
               Extract database credentials, API keys, other service tokens.

10-60 minutes: Plant a persistence mechanism.
               Write a cron entry or backdoor to /tmp.
               Curl a C2 endpoint (if egress is unrestricted).

1+ hours:      Pivot to ChromaDB, the UI pod, or other in-cluster services.
               Exfiltrate data from the vector database.
               Modify application content through the API.
```

In 24 hours with no notification: full compromise of the namespace and any adjacent
resources the service account can reach. The attacker was detected at T0 + 2 seconds.
The detection was meaningless because it went nowhere.

---

## Step 3 — Measure MTTD vs MTTN

**MTTD (Mean Time to Detect):**
The time from the malicious event to when the detection system generates an alert.

Falco's MTTD for `Terminal shell in container`:
- Falco uses eBPF kernel event interception. Latency from syscall to alert: 1-3 seconds.
- MTTD = approximately 2 seconds. Excellent.

**MTTN (Mean Time to Notify):**
The time from alert generation to when a human analyst receives it.

With Falcosidekick and no outputs configured:
- MTTN = infinity (or "when someone next logs into the Falcosidekick UI")
- In a 24/7 SOC environment with active dashboard monitoring: still hours
- In a small team with no 24/7 coverage: potentially days

**The math:**
```
MTTD:   2 seconds     (excellent — Falco is doing its job)
MTTN:   ∞             (broken — Falcosidekick has no output)
MTTR:   ∞             (impossible without notification)
```

A world-class MTTD with infinite MTTN does not produce a better security outcome
than having no detection at all. The attacker does not care about your MTTD. They
care about MTTR. And MTTR cannot start until MTTN completes.

---

## Step 4 — IR-4 Incident Handling Gap Analysis

NIST IR-4 defines six phases of incident handling. Map what exists to each phase.

| IR-4 Phase | Required Capability | Current State | Gap |
|------------|--------------------|--------------|----|
| Preparation | Playbooks, contact lists, tooling | Falco deployed | No notification routing |
| Detection | Automated event detection | Falco fires correctly | No |
| Analysis | Alert triage and investigation | Manual (dashboard only) | Analyst must be watching |
| Containment | Stop the attacker from progressing | Not possible without notification | Yes — critical gap |
| Eradication | Remove attacker access | Not possible without notification | Yes |
| Recovery | Restore normal operations | Not possible without notification | Yes |

Three of six IR-4 phases are blocked by the MTTN gap. The detection phase works.
Every subsequent phase does not.

---

## Step 5 — GRC: What Does IR-4 Actually Require?

IR-4 (Incident Handling) requires an incident handling capability that includes:

1. **Preparation:** Incident response procedures exist AND are documented
2. **Detection and Analysis:** Automated detection tools AND analyst review procedures
3. **Containment, Eradication, Recovery:** Documented steps AND authority to act

For FedRAMP Moderate, IR-4 also requires:
- Incident handling is tested at least annually (IR-4(a))
- Automated mechanisms to support incident handling are available (IR-4(1) if required)
- Incidents affecting FedRAMP data are reported to FedRAMP PMO within 1 hour of detection

The 1-hour FedRAMP reporting requirement is impossible to satisfy if MTTN is infinite.
If an analyst never receives the alert, they cannot report the incident to FedRAMP PMO
within any time frame, let alone 1 hour.

This is the compliance argument for fixing the routing gap. It is not abstract. The
auditor will ask: "Show me the alert notification that was sent when this exec occurred."
If the answer is "there was no notification," the IR-4 control is Not Satisfied.

---

## Step 6 — CIS 17.2 Gap Analysis

CIS Control 17.2 requires: "Establish and maintain contact information for parties that
need to be contacted to report a security incident, including: role or title, email
address, telephone number, etc."

The spirit of the control is that there is a known, tested path from detection to
notification to response. An alert that fires in a log file that nobody monitors is
not a "contact information" gap. It is the entire control gap. You cannot contact
anyone with information they never received.

What CIS 17.2 implies in a Kubernetes environment:
- Falco or equivalent fires an alert
- Falcosidekick routes it to at least one channel: Slack, PagerDuty, email, SIEM
- The channel is monitored by a human or triggers an automated response
- There is a documented escalation path (L1 → L2 → incident commander)

In this lab, the escalation path terminates before the first human. That is the gap.

---

## Next Step

Proceed to `fix.sh` to configure Falcosidekick with a working output channel.
Then read `remediate.md` for the full IR-4 lifecycle and what a complete incident
response capability looks like.
