# Layer 1 Physical — Validate After Fixes

| Field | Value |
|-------|-------|
| NIST Controls | PE-3, PE-14, PE-6, PE-11, PE-13, PE-15 |
| Tools | audit-physical-access.sh, audit-environmental-controls.sh, run-all-audits.sh |
| Enterprise Equivalent | Qualys VMDR re-scan, Rapid7 validated findings |
| Time Estimate | 1–2 hours |
| Rank | D — re-run audits, compare before/after, save evidence |

## What This Does

Re-runs all Layer 1 physical auditors after remediation is complete. Documents the before and after state as auditor-ready evidence. A finding is not closed until the re-audit passes and the evidence is saved.

## Why This Matters

Remediation without validation is a hypothesis, not a fix. Auditors require evidence that controls were not only implemented but tested and confirmed effective. The before/after audit trail is the proof. Without it, the work happened but cannot be verified — which is the same as not doing it from a compliance standpoint.

---

## Validation Procedure

### Step 1 — Confirm Remediation Is Complete

Before re-running audits, verify each fix from the remediation playbooks is actually in place:

- [ ] Badge deactivation SLA: test by checking a recent termination — badge should be inactive
- [ ] Visitor log: confirm log entries from the last week exist
- [ ] Access list review: signed certification document is on file
- [ ] Environmental alerts: trigger a test alert (if system supports it) or confirm alert contacts
- [ ] HVAC maintenance: service record is on file

### Step 2 — Run Full Audit Suite

```bash
./tools/run-all-audits.sh
```

This runs both audit scripts sequentially and produces new evidence files in `/tmp/jsa-evidence/`.

Note the new evidence directory path — you will need it for Step 4.

### Step 3 — Compare Before and After

```bash
# Locate before and after evidence files
ls /tmp/jsa-evidence/

# Compare physical access results
diff \
  /tmp/jsa-evidence/physical-access-<OLD-TIMESTAMP>/results.txt \
  /tmp/jsa-evidence/physical-access-<NEW-TIMESTAMP>/results.txt

# Compare environmental results
diff \
  /tmp/jsa-evidence/environmental-controls-<OLD-TIMESTAMP>/results.txt \
  /tmp/jsa-evidence/environmental-controls-<NEW-TIMESTAMP>/results.txt
```

Any item that changed from `n` to `y` is a closed finding. Document it.

### Step 4 — Save Evidence to Layer Directory

```bash
LAYER_DIR=/home/jimmie/linkops-industries/GP-copilot/GP-PROJECTS/01-instance/slot-3/Anthra-SecLAB/OSI-MODEL-SECURITY/01-PHYSICAL-LAYER

# Create dated evidence directory
EVIDENCE_DATE=$(date +%Y%m%d)
mkdir -p "$LAYER_DIR/evidence/validation-${EVIDENCE_DATE}"

# Copy audit results
cp /tmp/jsa-evidence/physical-access-*/results.txt \
  "$LAYER_DIR/evidence/validation-${EVIDENCE_DATE}/physical-access-results.txt"

cp /tmp/jsa-evidence/environmental-controls-*/results.txt \
  "$LAYER_DIR/evidence/validation-${EVIDENCE_DATE}/environmental-results.txt"
```

### Step 5 — Update Assessment Checklist

Open `03-templates/pe-assessment-checklist.md` and update:

- Status columns for all items that changed from Fail to Pass
- Notes column: add "Remediated — validated [DATE]"
- Summary table: update Pass/Fail counts

### Step 6 — Document Remaining Open Findings

If any items still fail after remediation:

1. Record the finding with the reason remediation is incomplete.
2. Create a POA&M entry (Plan of Action and Milestones) if this is a formal engagement.
3. Set a target date for full remediation.
4. Escalate if the finding is high-severity and cannot be remediated within 30 days.

---

## Validation Complete — Checklist

- [ ] All previously-failed PE-3 items now pass (or are formally deferred with POA&M)
- [ ] All previously-failed PE-14 items now pass (or are formally deferred with POA&M)
- [ ] Before/after diff documented
- [ ] Evidence copied to `evidence/validation-<DATE>/`
- [ ] Assessment checklist updated
- [ ] Any remaining open findings have a target remediation date

---

## Before/After Summary Template

| Control | Item | Before | After | Evidence File |
|---------|------|--------|-------|---------------|
| PE-3 | Badge deactivation SLA | FAIL | PASS | physical-access-results.txt |
| PE-3 | Access list review | FAIL | PASS | physical-access-results.txt |
| PE-14 | Environmental alerts | FAIL | PASS | environmental-results.txt |
| | | | | |

Fill in this table and attach to the engagement report.
