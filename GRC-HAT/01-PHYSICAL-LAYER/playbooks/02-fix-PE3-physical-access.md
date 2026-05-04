# Layer 1 Physical — Fix PE-3 Physical Access

| Field | Value |
|-------|-------|
| NIST Controls | PE-3 Physical Access Control |
| Tools | Badge system admin console, HR active employee roster |
| Enterprise Equivalent | Genetec Security Center, Lenel OnGuard, Honeywell Pro-Watch |
| Time Estimate | 2–8 hours (depends on scope of gaps) |
| Rank | D — follow prescribed steps, verify outcome |

## What This Does

Remediates findings from the PE-3 physical access assessment. Covers three primary gap categories: badge access deployment or cleanup, visitor log implementation, and access list review process establishment. Each step produces evidence that an auditor can verify.

## Why This Matters

PE-3 is one of the most frequently cited physical control failures in FISMA and FedRAMP audits. It is also the easiest to fix — most gaps are process failures, not hardware failures. An organization that has a badge system but no access list review process is one terminated employee away from a physical access incident. Fixing this takes an afternoon, not a capital budget.

---

## Remediation Steps

### Step 1 — Assess the Scope

Identify which PE-3 gaps were found in the assessment:

- [ ] Badge system missing or partial
- [ ] Terminated badges not deactivated promptly
- [ ] No visitor log or incomplete log
- [ ] Escort policy not enforced
- [ ] Server room access not separately controlled
- [ ] Access list reviews not performed

Each gap has a separate fix below. Address them in order — infrastructure before process.

### Step 2 — Badge Access Remediation

If badge access is missing at any entry point, refer to the full deployment guide:

```
02-fixers/fix-access-policy.md — Badge System Deployment section
```

If badge access exists but terminated credentials are not being deactivated:

```bash
# Checklist: establish badge deactivation SLA
# 1. Define the process: HR notifies Facilities/Physical Security within 2 hours of separation
# 2. Facilities deactivates badge within the same business day
# 3. Badge system generates a "deactivation log" entry with timestamp
# 4. HR keeps separation record with timestamp
# 5. Reconcile monthly: compare HR terminations to badge deactivations
```

### Step 3 — Visitor Log Implementation

Minimum viable visitor log (paper or electronic):

| Field | Required | Notes |
|-------|----------|-------|
| Full name | Yes | |
| Organization | Yes | |
| ID type | Yes | Driver's license, passport, etc. |
| Date | Yes | |
| Time in | Yes | |
| Time out | Yes | |
| Host employee | Yes | Name + badge/employee number |
| Purpose of visit | Yes | |

For electronic visitor management: Envoy, Proxyclick, and SwipedOn all export audit-ready reports. SwipedOn is the most cost-effective for small sites.

### Step 4 — Access List Review

Establish the recurring access list review process:

1. Pull current access list from badge system (CSV or PDF export).
2. Pull current active employee list from HR.
3. Identify accounts in badge system that are not in HR active roster — these are revocation candidates.
4. Send the list to each department manager: "Please confirm each person on this list still requires access."
5. Revoke any access that is not certified by the responsible manager.
6. Document: who reviewed, date, count reviewed, count revoked.
7. Store documentation in `evidence/` and present to auditors.

Schedule this review:
- Server room access: quarterly
- General building access: annually
- After any organizational restructure: immediately

### Step 5 — Verify Fixes

After remediation, re-run the physical access audit:

```bash
./01-auditors/audit-physical-access.sh
```

All items that previously failed should now pass. Save the new evidence file.

---

## Evidence Package for Auditors

Collect the following and store in `evidence/PE-3-<date>/`:

| Item | Source |
|------|--------|
| Badge access log export | Badge system admin console — last 30 days |
| Termination reconciliation | HR termination list vs. badge deactivation timestamps |
| Visitor log — last 90 days | Visitor management system export or scanned paper log |
| Access list review record | Signed manager certifications or system-generated report |
| Server room access list with justifications | Badge system export with job title for each person |
| Escort policy document | Policy with effective date and last review |
| Audit script results (before) | `/tmp/jsa-evidence/physical-access-<old-timestamp>/results.txt` |
| Audit script results (after) | `/tmp/jsa-evidence/physical-access-<new-timestamp>/results.txt` |
