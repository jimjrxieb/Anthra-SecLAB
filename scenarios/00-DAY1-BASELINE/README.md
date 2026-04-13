# Day 1 Baseline — Anthra-SecLAB

## Who You Are

You are a Level 1 analyst on your first day at Anthra Corp. Your team runs a cybersecurity training lab
built on a real Kubernetes cluster. Before any break/fix scenarios run, you need to capture the baseline
state of this environment. That means: inventory what is running, verify the security stack is healthy,
document what is and is not configured correctly, and sign off that you saw it with your own eyes.

This is not a test. If something looks wrong in the baseline, it is wrong. Write it down. The report you
file today becomes the "before" state that every future scenario compares against.

You have access to kubectl, kubescape, kube-bench, trivy, semgrep, and gitleaks. You do not need to
install anything. All tools are on the path.

---

## Your Environment

### Cluster

| Field | Value |
|-------|-------|
| Cluster name | k3d-seclab |
| Nodes | 3 (1 server, 2 agents) |
| Kubernetes version | k3s v1.31 |
| Context | k3d-seclab |

Verify you are in the right context before running anything:

```
kubectl config current-context
```

Expected output: `k3d-seclab`

If you see anything else, stop. Do not run commands against the wrong cluster.

### Target Application

Anthra Corp runs the Portfolio application in the `anthra` namespace. It is a three-component stack:

| Component | Deployment | Port |
|-----------|-----------|------|
| API | portfolio-anthra-portfolio-app-api | 8000 |
| UI | portfolio-anthra-portfolio-app-ui | 3000 |
| Vector DB | portfolio-anthra-portfolio-app-chroma | 8000 |

The application is the subject of every break/fix scenario. If the application is broken before a
scenario runs, that matters. Document it.

### Security Stack

| Tool | Namespace | Purpose |
|------|-----------|---------|
| Falco | falco | Runtime threat detection — watches kernel syscalls |
| Kyverno | kyverno | Admission control — enforces policies at deploy time |
| Fluent Bit | logging | Log shipping — collects and forwards container logs |
| Prometheus | monitoring | Metrics collection |
| Grafana | monitoring | Metrics visualization |

All four must be running before any scenario executes. If any of them are down, the scenario results
are unreliable. Do not proceed with break/fix work until the security stack is healthy.

---

## What You Do Today

Your Day 1 has three deliverables:

**1. Run the automated baseline capture.**

```
bash scenarios/00-DAY1-BASELINE/run-baseline.sh
```

This script collects cluster state, namespace inventory, security stack health, policy configuration,
RBAC bindings, NetworkPolicies, and image versions. It saves everything to the evidence directory.
It takes under two minutes. Run it, let it finish, note where the output went.

**2. Walk the guided checklist.**

Open `scenarios/00-DAY1-BASELINE/checklist.md`. Go through every section in order. The checklist
gives you the exact command, the expected output, and what to do if it does not match. Run each
command yourself. Do not skip sections. The point is that you see the environment with your own eyes,
not that a script ran.

**3. Fill out the baseline report.**

Open `scenarios/00-DAY1-BASELINE/baseline-report-template.md`. Fill in every table. If a check
passed, write PASS. If it failed, write what you saw. If something was missing, write MISSING. No
blanks. Sign and date the report when you are done.

---

## Framework Reference

This lab maps findings to NIST CSF 2.0 and CIS Controls v8. You do not need to memorize the
framework. The checklist tells you which control each check maps to. The mapping exists so that when
a finding gets escalated to the security team, they can reference the standard it violates.

### NIST CSF 2.0 Functions

| Function | What It Means | Day 1 Relevance |
|----------|--------------|-----------------|
| Identify (ID) | Know what you have | Asset inventory, RBAC audit, vulnerability scan |
| Protect (PR) | Prevent harm | Security contexts, NetworkPolicies, policy enforcement |
| Detect (DE) | See when something goes wrong | Falco running, log shipping healthy, Prometheus scraping |
| Respond (RE) | React to incidents | Out of scope for Day 1 — you are in Identify/Protect/Detect |
| Recover (RC) | Restore normal operations | Out of scope for Day 1 |

Today covers ID, PR, and DE. You are establishing the baseline against which future detections and
responses will be measured.

---

## Mindset

A senior engineer walks the environment before touching it. That is what you are doing today. You are
not here to fix anything yet. You are here to understand what is running, verify that the security
tools are doing their jobs, and document the starting state.

If you find something that looks wrong, write it down in the Pre-Existing Issues section of the
report. Do not fix it. Do not escalate it yet. Just document it. The scenarios that follow will
intentionally introduce additional problems. If you cannot distinguish between a pre-existing issue
and a scenario-injected problem, the training exercise breaks down.

Clear eyes. Write everything down. Ask if something does not make sense.
