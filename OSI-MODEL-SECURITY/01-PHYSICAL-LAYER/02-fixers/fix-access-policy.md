# Fix: PE-3 Physical Access Control Gaps

## When This Control Fails

PE-3 failures typically appear as one or more of the following:

- Entry points that are not badge-controlled (propped doors, key-only locks, no access system)
- Visitor logs that are paper-based, incomplete, or not maintained
- Terminated employees whose badge credentials were not deactivated promptly
- Server room access granted to personnel who no longer require it
- No formal access list review process — privilege accumulates over time
- Escort policy exists on paper but is not enforced in practice

Any of these conditions is an audit finding. NIST SP 800-53 PE-3 requires organizations to enforce approved authorizations for physical access, maintain audit logs, and control entry/exit.

---

## How to Fix

### Badge System Deployment

If no electronic badge access system exists:

1. Assess all entry points — document each door, gate, and access point that requires control.
2. Select a badge system. Enterprise options: Genetec Security Center, Lenel OnGuard, Honeywell Pro-Watch. For smaller environments: Brivo, Verkada, or HID Origo.
3. Install card readers at all controlled entry points. Server rooms require a dedicated reader separate from the building perimeter.
4. Enroll all personnel. Assign minimum necessary access — not blanket building access.
5. Configure access logs to write to a SIEM or centralized log management system.
6. Test the deactivation workflow: terminate a test account and verify the credential stops working within the required SLA (typically 24 hours or same business day).

If a badge system exists but access is inconsistent:

1. Pull the current access list from the badge system.
2. Cross-reference against HR active employee list.
3. Revoke access for any account not in HR active roster.
4. Document the reconciliation as evidence.

### Visitor Log Process

Minimum viable visitor log entry fields:
- Full name
- Organization / company
- Government-issued ID number (or type)
- Date and time in
- Date and time out
- Host employee name and badge number
- Purpose of visit

For paper logs: use a bound log book (not loose pages). Store completed books for at least 1 year. For regulated environments (FedRAMP, HIPAA): 3 years minimum.

For electronic logs: Envoy, Proxyclick, and SwipedOn are purpose-built visitor management systems that integrate with badge access and export audit-ready reports.

### Access List Review Procedure

1. Schedule a recurring review — quarterly for server rooms, annually for general facility access.
2. Export the current access list from the badge system.
3. Send the list to each department manager for certification: "Does each person on this list still require access?"
4. Revoke any access that is not certified.
5. Document the review: who reviewed, date, number of accounts reviewed, number revoked.
6. Store the documentation as evidence for auditors.

---

## Evidence for Auditors

After remediation, an auditor will ask for:

| Evidence Item | What to Provide |
|---------------|-----------------|
| Badge access logs | Export from badge system — last 30/60/90 days |
| Terminated employee deactivation | HR separation record cross-referenced with badge deactivation timestamp |
| Visitor log | Last 90 days of visitor log entries (redact PII for HIPAA environments) |
| Access list review | Signed certification document or system-generated review report |
| Server room access list | Current list with job title justification for each person |
| Escort policy | Policy document with effective date and last review date |

All evidence should be timestamped and stored in the engagement evidence directory:
`/tmp/jsa-evidence/physical-access-<TIMESTAMP>/`
