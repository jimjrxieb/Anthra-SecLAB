# Chain of Custody Template

Use this template for every piece of evidence collected during an incident.

---

## Chain of Custody Form

**Incident ID:**
**Evidence Item #:**
**Date/Time Collected (UTC):**
**Collected By:**

**Evidence Description:**
(What is it? File, memory dump, disk image, screenshot, log export)

**Source System:**
- Hostname:
- IP Address:
- OS:

**Collection Method:**
(Command run, tool used, manual screenshot)

**SHA256 Hash:**
```
sha256sum <file>
```

**Storage Location:**
(Where is this being stored? Local path, S3 bucket, evidence vault)

**Chain of Custody Log:**

| Date/Time (UTC) | Action | Person | Notes |
|-----------------|--------|--------|-------|
| | Collected | | Original collection |
| | Transferred | | Moved to evidence storage |
| | Accessed | | Accessed for analysis |

---

**Integrity Verification:**
Before analysis, verify hash matches original:
```bash
sha256sum <file>  # must match recorded hash above
```

If hash does not match, do not use this evidence and escalate.
