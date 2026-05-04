# Post-Incident Review

## Purpose

Learn from the incident. Improve detection, response, and prevention. Document for compliance.

## When to Hold

Within 5 business days of incident closure. While memories are fresh.

## Participants

- Lead incident analyst
- Security manager
- Affected system/service owner
- IT operations (if systems were impacted)
- Legal/compliance (for P1/P2 incidents)

## Review Questions

**Timeline accuracy:**
- When did the attacker first gain access vs. when did we detect it? (Dwell time)
- What was our mean time to detect (MTTD)?
- What was our mean time to respond (MTTR)?

**Detection gaps:**
- What indicator should have fired an alert earlier?
- What log source was missing that would have helped?
- Was there a detection rule that should have caught this?

**Response effectiveness:**
- Did we follow our playbook?
- What steps were unclear or missing from the playbook?
- Did containment prevent additional damage?

**Prevention:**
- What control failure allowed the initial access?
- What would have prevented this entirely?

## Output

1. **Incident Report** — full written summary, timeline, impact, root cause, remediation actions
2. **Lessons Learned** — 3-5 concrete action items with owners and due dates
3. **Detection improvements** — new or tuned SIEM rules
4. **Playbook updates** — revisions based on what worked and what didn't
5. **Control improvements** — new or updated security controls

## Metrics to Track

- Total incidents per month/quarter
- MTTD (Mean Time to Detect)
- MTTR (Mean Time to Respond)
- Incidents by type and severity
- Repeat incidents (same root cause = systemic problem)
