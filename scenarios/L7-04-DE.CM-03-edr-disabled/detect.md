# L7-04 — DE.CM-03: Detect — EDR Coverage Gap

## How You Got Here

This is the one scenario where the SIEM should catch it first — if your alerting
is configured correctly. If it is not, that absence of alert is itself a finding.

**Path A — Alertmanager fired (best case):** Alertmanager triggered a
`FalcoPodNotRunning` or `FalcoSilent` alert. You received a page or saw it in
Slack. The alert means your monitoring-of-the-monitor is working. Follow this
playbook to confirm scope and remediate.

**Path B — Day 1 Checklist:** Your baseline checklist (section 2.1) includes
verifying that Falco pods are running and producing output. You ran it, saw zero
Falco pods in the `falco` namespace, and opened this scenario.

**Path C — Grafana went silent:** You were reviewing the Falco dashboard and
noticed the event rate graph went flat. No new data points after a certain
timestamp. The dashboard did not error — it just stopped updating. The timestamp
where the line went flat is the start of your monitoring gap.

If none of these paths triggered and you only noticed because you were explicitly
looking — that is also a finding. Document it. The detection mechanism failed.

Your job now is to confirm the absence, measure how long Falco has been down, and
determine what events were missed during the gap.

---

## Detection Path 1 — Grafana Dashboard

Open the Falco dashboard in Grafana.

What you expect to see:
- `falco_events_total` — a counter that increments continuously as Falco processes syscalls
- Event rate graphs showing steady background activity

What you see when Falco is down:
- The counter line goes flat or disappears entirely
- No new data points after the break timestamp
- The dashboard does not error — it just shows nothing

**Key question:** When did the line go flat? That timestamp is when your monitoring
gap started.

---

## Detection Path 2 — Prometheus Queries

Open Prometheus or run these queries:

Check if any Falco targets are up:
```
up{job="falco"}
```
Expected when healthy: `1` for each Falco pod
Expected when broken: no results, or `0`

Check for absence of Falco events (alerting rule form):
```
absent(falco_events_total)
```
Returns a value of `1` when the metric has disappeared entirely — meaning no
Falco instance is reporting. This is the PromQL expression you would put in an
Alertmanager rule to fire when EDR goes silent.

Check scrape status:
```
up{job=~".*falco.*"}
```
If this returns nothing or all zeros, Prometheus has lost all Falco scrape targets.

---

## Detection Path 3 — kubectl Direct Check

The fastest check. Run this from any terminal with cluster access:

```bash
kubectl get pods -n falco
```

Expected when healthy:
```
NAME                        READY   STATUS    RESTARTS   AGE
falco-xxxxx                 2/2     Running   0          2d
falco-yyyyy                 2/2     Running   0          2d
falco-zzzzz                 2/2     Running   0          2d
falcosidekick-aaa-bbb       1/1     Running   0          2d
falcosidekick-ccc-ddd       1/1     Running   0          2d
```

Expected when broken:
```
NAME                        READY   STATUS    RESTARTS   AGE
falcosidekick-aaa-bbb       1/1     Running   0          2d
falcosidekick-ccc-ddd       1/1     Running   0          2d
```

The Falco pods are gone. The Falcosidekick pods are still running — but they have
nothing to forward because nothing is generating events.

Also check the DaemonSet state:
```bash
kubectl describe daemonset falco -n falco
```
Look for:
- `Desired Number of Nodes Scheduled: 0` — this tells you the scheduler cannot
  place the pod on any node
- Events section: may show `FailedScheduling` or similar

---

## Detection Path 4 — Alertmanager

If your Prometheus alerting rules include Falco coverage checks, you should see
alerts firing in Alertmanager:

- `FalcoPodNotRunning` — fires when `kube_daemonset_status_number_ready{daemonset="falco"} == 0`
- `FalcoSilent` — fires when `absent(falco_events_total)` is true for more than N minutes

In this lab, check whether either alert is firing. If neither is configured, that is a
finding of its own — your alerting rules did not cover the EDR-down scenario.

```bash
# Check Alertmanager API directly
kubectl port-forward svc/alertmanager -n monitoring 9093:9093 &
curl -s http://localhost:9093/api/v2/alerts | python3 -m json.tool | grep -A5 "falco"
```

---

## The Detection Gap — Why This Is the Real Finding

Falco going down is a misconfiguration. That is fixable in minutes.

The real finding is: **how long did it take you to notice?**

- If you noticed in 5 minutes: your alerting coverage is good.
- If you noticed in 2 hours: an attacker had a 2-hour unmonitored window.
- If you noticed because break.sh printed a warning: you have no automated detection of EDR loss.

An attacker who knows your EDR tool will target the window between "EDR goes down"
and "someone notices." Container escapes, privilege escalation, lateral movement,
credential harvesting — all of these produce Falco alerts under normal conditions.
During the gap, they are invisible.

The monitoring gap is not just an operational issue. It is a compliance issue. GRC
requires you to document when a control was absent, for how long, and what risk
existed during that period. That documentation goes into the POA&M.

---

## L1 Checklist

- [ ] Checked Grafana — Falco event rate graph went flat at: _______________
- [ ] Checked Prometheus — `up{job="falco"}` returns: _______________
- [ ] Checked kubectl — `kubectl get pods -n falco` shows: ___ Falco pods running
- [ ] Checked Alertmanager — alert firing: Yes / No / Not configured
- [ ] Identified gap start time: _______________
- [ ] Identified gap end time (after fix.sh): _______________
- [ ] Total gap duration: _______________

---

## NEXT STEP

Go to `investigate.md` to classify the finding, determine root cause, and prepare
the GRC documentation. Then run `fix.sh` to restore Falco coverage.
