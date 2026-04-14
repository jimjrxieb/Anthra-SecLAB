# L7-10 RS.MI-02 — Remediate: FIM Coverage for Writable Container Paths

**Role:** L1 Security Analyst / GRC Analyst
**CSF:** RESPOND / RS.MI-02
**CIS v8:** 3.14
**NIST 800-53:** SI-7

This document explains why FIM on writable paths matters, how to document
FIM coverage in a control assessment, and what to track for ongoing coverage.

---

## Why FIM Matters: The PREVENT/DETECT Model

Security controls work in layers. For container filesystem integrity, there are
two distinct control types that work together — neither replaces the other.

### PREVENT Layer: readOnlyRootFilesystem

```yaml
securityContext:
  readOnlyRootFilesystem: true
```

This tells the Linux kernel to mount the container's root filesystem read-only.
Writes to `/app`, `/etc`, `/usr`, `/bin`, and similar system paths are blocked
at the kernel level. An attacker who gains a shell cannot overwrite the application
binary, inject a backdoor into the source tree, or modify configuration files.

**What it covers:** The container's root filesystem — all paths not explicitly
mounted as writable volumes.

**What it does not cover:** Any `emptyDir`, `hostPath`, or `PVC` mount. These are
writable by design. `/tmp` mounted as an emptyDir is the most common example.

### DETECT Layer: Falco FIM Rule

```yaml
- rule: Write to Temp in Portfolio API
  condition: >
    evt.type in (open, openat, openat2) and
    evt.is_open_write=true and
    fd.name startswith /tmp/ and
    k8s.ns.name = "anthra" and
    k8s.pod.label.app.kubernetes.io/component = "api"
  priority: WARNING
```

This tells Falco to watch every `open()`/`openat()` syscall, filter for writes,
and fire when the write is to `/tmp` inside the Portfolio API container. The
application can still write to `/tmp` — this is not a PREVENT control. It is
a DETECT control: if anything unexpected writes to `/tmp`, there is an alert.

**The combination:**
- PREVENT stops writes where they should never happen (`/app`)
- DETECT alerts on writes where they are expected but must be monitored (`/tmp`)

Neither alone is sufficient. Together they implement defense in depth.

---

## Common Writable Paths That Need FIM

Every emptyDir or hostPath mount is a potential attacker staging ground.
Map these for your application:

| Path        | Purpose                          | FIM required?                        |
|-------------|----------------------------------|---------------------------------------|
| /tmp        | Application scratch space        | Yes — most common staging path        |
| /var/cache  | Cache files                      | Yes — attacker can cache tools here   |
| /var/run    | PID files, sockets               | Yes — socket files can be backdoored  |
| /dev/shm    | Shared memory (tmpfs)            | Yes — often overlooked, exec-capable  |
| /mnt/*      | Mounted volumes                  | Depends on mount type and sensitivity |

The rule deployed in fix.sh covers `/tmp`. If the application has other writable
mounts, add conditions to the same rule or create additional rules.

---

## GRC: Documenting FIM Coverage in a Control Assessment

When an auditor assesses SI-7 (Software, Firmware, and Information Integrity),
they will ask specific questions. Know how to answer them.

### Question 1: What is your FIM tool?

**Answer format:**
```
FIM Tool: Falco (open source, syscall-based)
Deployment: DaemonSet in falco namespace, watching all nodes
Rule source: Default Falco rules + custom rules in ConfigMap falco-fim-anthra-rules
Alert destination: Falco Sidekick → [Splunk / Slack / PagerDuty]
```

### Question 2: What paths are monitored?

**Answer format:**
```
Default Falco rules cover:
  /etc — system configuration
  /bin, /sbin, /usr/bin — system binaries
  /lib, /usr/lib — system libraries
  /proc — process filesystem anomalies

Custom rules (falco-fim-anthra-rules) cover:
  /tmp in anthra/api containers — writable emptyDir mount
```

### Question 3: What paths are NOT monitored?

This is the honest answer a FedRAMP auditor requires. Do not hide gaps.

**Answer format:**
```
Unmonitored paths (as of [date]):
  /var/cache — no custom rule (low sensitivity, no known data flows through here)
  /dev/shm — no custom rule (compensating control: NetworkPolicy restricts egress)
  Application PVC mounts — monitored at the storage layer (AWS EBS CloudTrail events)

Compensating controls for unmonitored paths:
  - NetworkPolicy: egress restricted to cluster-internal services only
  - Pod Security: runAsNonRoot=true, all capabilities dropped
  - Container image scanning: no known tools in the base image
```

### Question 4: How do you test FIM coverage?

**Answer format:**
```
Monthly: Run verify.sh from scenario L7-10-RS.MI-02-fim-disabled
         Expected: test write to /tmp triggers Falco WARNING alert
         Evidence: Falco log output saved to GP-S3/5-consulting-reports/
Quarterly: Full FIM coverage review against updated application volume mounts
```

### Question 5: What is your alert-to-response SLA?

**Answer format:**
```
Falco WARNING (/tmp write): 15 minutes to SOC triage
Falco ERROR (script execution from /tmp): 5 minutes, auto-page on-call
```

---

## POA&M Entry

If FIM coverage was incomplete at time of assessment, this generates a POA&M
entry. Fill in with your actual findings:

| Field               | Value                                                         |
|---------------------|---------------------------------------------------------------|
| POA&M ID            | POA&M-L7-10-[YYYY-MM-DD]                                     |
| Control             | SI-7 / RS.MI-02 / CIS 3.14                                   |
| Weakness            | No FIM coverage on writable emptyDir mounts (/tmp)           |
| Asset               | portfolio-anthra-portfolio-app-api (anthra namespace)         |
| Risk Level          | Medium-High                                                   |
| Mitigation Applied  | Custom Falco rule deployed (falco-fim-anthra-rules ConfigMap) |
| Scheduled Completion | [Date — should be same day for MEDIUM finding]               |
| Responsible Party   | [Security engineer / platform team]                           |
| Status              | [ ] Open  [ ] In Progress  [ ] Completed                      |

---

## Ongoing Coverage: What to Track

FIM is not a set-and-forget control. Application changes can introduce new
writable paths, or existing paths can change their data sensitivity.

Add these to your operational runbook:

1. **On every new Deployment:** Check for new emptyDir or PVC mounts. If a
   new writable path is added, add a corresponding Falco rule before deploying.

2. **On every new namespace:** Create namespace-scoped rules as part of the
   onboarding checklist (similar to NetworkPolicy and RBAC).

3. **Monthly:** Run verify.sh to confirm FIM is still firing. Rule regressions
   happen when Falco is upgraded or ConfigMaps are overwritten.

4. **Quarterly:** Review the list of monitored vs unmonitored paths against
   the current application architecture. Update the control assessment artifact.

---

## Falco Rule Quality Checklist

Before declaring a FIM rule production-ready, verify:

- [ ] Rule fires on a test write (verify.sh passes)
- [ ] Rule is scoped to the correct namespace and component (not wildcard)
- [ ] Rule has meaningful output fields (user, command, file, pod, namespace)
- [ ] Rule has MITRE ATT&CK tags where applicable
- [ ] Rule is in a named ConfigMap under source control (not applied ad hoc)
- [ ] Alert destination is configured (Falco Sidekick → SIEM)
- [ ] Suppression/allow-list exists for known-good application writes (if needed)
- [ ] Rule is documented in the control assessment artifact

---

## References

- NIST 800-53 Rev 5: SI-7 Software, Firmware, and Information Integrity
  - SI-7(1): Integrity checks at startup / periodically
  - SI-7(6): Cryptographic protection of integrity mechanisms
- NIST CSF 2.0: RS.MI-02 — Incidents are eradicated
- CIS Controls v8: 3.14 — Log Sensitive Data Access
- MITRE ATT&CK: T1074 — Data Staged
- MITRE ATT&CK: T1059 — Command and Scripting Interpreter
- Falco rules documentation: https://falco.org/docs/rules/
- Falco custom rules: https://falco.org/docs/rules/custom-rules/
