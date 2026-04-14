# L7-10 — RS.MI-02: FIM Not Covering Critical Writable Paths

## Scenario Summary

The Portfolio API container runs with `readOnlyRootFilesystem: true`. That protects
`/app` — the attacker cannot overwrite the application binary or inject code into
the source tree. But the container has a writable `emptyDir` mounted at `/tmp`.
That is intentional. The application uses `/tmp` for scratch space.

Without File Integrity Monitoring (FIM), an attacker who gains a shell inside the
container can write tools, stage exfiltration payloads, and persist artifacts in
`/tmp` without triggering any alert. The rootFS protection is a **PREVENT** control.
Falco FIM on writable paths is the **DETECT** control. This scenario shows what
happens when the detect layer is missing.

Default Falco rules watch for writes to `/etc`, `/bin`, `/usr`, and similar
system directories. They do not fire on `/tmp` within a specific application
container namespace. The gap is real, documented, and fixable with a targeted
custom rule.

---

## Control Mapping

| Field              | Value                                                          |
|--------------------|----------------------------------------------------------------|
| CSF Function       | RESPOND                                                        |
| CSF Category       | RS.MI — Incident Mitigation                                    |
| CSF Subcategory    | RS.MI-02 — Incidents are eradicated                            |
| CIS v8 Control     | 3.14 — Log Sensitive Data Access                               |
| NIST 800-53        | SI-7 — Software, Firmware, and Information Integrity           |
| OSI Layer          | Layer 7 — Application                                          |
| Severity           | Medium-High (data-sensitivity dependent)                       |
| Rank               | C — Propose Falco rule change, wait for approval               |
| Difficulty         | Level 1                                                        |

---

## The Detection Gap Explained

```
readOnlyRootFilesystem: true
│
├── /app/         PROTECTED  — attacker cannot write here
├── /etc/         PROTECTED  — read-only
├── /bin/         PROTECTED  — read-only
│
└── /tmp/         WRITABLE   — emptyDir mount, intentional
    │
    ├── backdoor.sh      ← attacker drops tools here
    ├── staged-data.txt  ← attacker stages exfil data here
    └── ...              ← NO FALCO RULE FIRES
```

Default Falco covers system paths. Application writable scratch space is
out of scope unless a custom rule adds it explicitly.

---

## Affected Assets

- **Namespace:** anthra
- **Deployment:** portfolio-anthra-portfolio-app-api
- **Writable path:** /tmp (emptyDir, by design)
- **FIM tool:** Falco (namespace: falco)
- **Gap:** No Falco rule targets /tmp writes in anthra/api containers

---

## Scenario Lifecycle

| Phase       | File                 | What Happens                                              |
|-------------|----------------------|-----------------------------------------------------------|
| Baseline    | `baseline.sh`        | Check Falco rules for /tmp coverage, inspect /tmp state   |
| Break       | `break.sh`           | Write attacker artifacts to /tmp — backdoor + staged data |
| Detect      | `detect.md`          | L1 analyst: check Falco logs, inspect /tmp, find the gap  |
| Investigate | `investigate.md`     | What was written, when, by what process, could it exfil?  |
| Fix         | `fix.sh`             | Deploy custom Falco rule for /tmp writes in anthra/api    |
| Remediate   | `remediate.md`       | Why FIM matters, GRC documentation guidance               |
| Verify      | `verify.sh`          | Write test file, confirm Falco alert fires, clean up      |
| Report      | `report-template.md` | Evidence template, POA&M, lessons learned                 |

---

## Key Teaching Points

1. **readOnlyRootFilesystem is PREVENT. FIM is DETECT. You need both.**
   One stops writes to the application filesystem. The other detects writes
   to the intentional writable paths attackers will use as staging ground.

2. **emptyDir mounts are common and necessary.** Apps need scratch space.
   The answer is not to remove /tmp — it is to watch /tmp.

3. **Default Falco rules do not cover application-specific writable paths.**
   FIM coverage requires targeted rules that know your application topology.
   Generic rules catch generic attacks. Targeted rules catch targeted attacks.

4. **Data sensitivity determines severity.** If /tmp contains processed PII,
   RAG pipeline output, or session tokens — the finding is HIGH. If it is
   truly scratch space for temporary computation — MEDIUM. The analyst must
   inspect what was staged, not just that something was staged.

5. **RS.MI-02 is about eradication.** You cannot eradicate what you cannot
   detect. FIM is the prerequisite to eradication.

---

## Why This Matters

NIST SI-7 requires the system to detect unauthorized changes to software,
firmware, and information. An emptyDir mount that an attacker can write to
without detection is a SI-7 gap.

CIS 3.14 requires logging sensitive data access. If the container processes
any sensitive data that flows through /tmp (query results, pipeline outputs,
cached tokens), writes to that path must be logged.

In a FedRAMP Moderate environment, this gap appears in the SI family assessment.
The auditor will ask: "What paths are monitored by your FIM solution? How are
writable mounts covered?" Without a custom Falco rule, the honest answer is:
"They are not covered."

---

## References

- NIST 800-53 Rev 5: SI-7 Software, Firmware, and Information Integrity
- NIST CSF 2.0: RS.MI-02 — Incidents are eradicated
- CIS Controls v8: 3.14 — Log Sensitive Data Access
- Falco rules reference: https://falco.org/docs/rules/
- MITRE ATT&CK: T1074 — Data Staged
