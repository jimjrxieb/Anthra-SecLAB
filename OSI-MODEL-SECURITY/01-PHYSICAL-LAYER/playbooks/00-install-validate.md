# Layer 1 Physical — Install and Validate

| Field | Value |
|-------|-------|
| NIST Controls | PE-3, PE-14, PE-6, PE-11, PE-13, PE-15 |
| Tools | Badge system admin console, CCTV dashboard, Environmental monitoring dashboard |
| Enterprise Equivalent | Genetec, Lenel, Honeywell Pro-Watch, APC NetBotz |
| Time Estimate | 1 hour preparation |
| Rank | N/A — prerequisite |

## What This Does

Physical layer controls have no software to install. There is no package to deploy, no Helm chart to apply, no container to run. This playbook documents what to prepare before arriving on site. An analyst who shows up without the right credentials and access cannot complete the assessment — this is the pre-flight checklist.

## Why This Matters

Physical security is the foundation that every other layer depends on. If an attacker can walk into the server room, no firewall or EDR matters. NIST SP 800-53 PE controls govern this layer. FedRAMP, HIPAA, and SOC 2 all require documented physical controls. An unprepared assessor wastes the site visit and has to reschedule.

---

## Pre-Visit Preparation

### Access Systems to Request Before Arrival

| System | What You Need | Who Provides It |
|--------|---------------|-----------------|
| Badge system admin console | Read-only access to access logs and current access list | Facilities / Physical Security team |
| CCTV management dashboard | Read-only viewer access | Facilities / IT Security |
| Environmental monitoring dashboard | Read-only access (APC NetBotz, Vertiv, Nagios, etc.) | Data Center Operations |
| UPS management console | Read-only view of load and battery status | Data Center Operations |
| HR active employee list | Current headcount by department | HR (coordinate with engagement sponsor) |

### Credentials Checklist

Before leaving for the site visit, confirm you have working credentials for:

- [ ] Badge system admin console (test login before arriving)
- [ ] CCTV dashboard (verify you can view camera feeds)
- [ ] Environmental monitoring dashboard (verify current temp/humidity visible)
- [ ] UPS management console or PDU metering (verify load data visible)
- [ ] Building management system (BMS) if site uses one
- [ ] Physical access to server room (escort arranged or badge provisioned)

### Documents to Bring

- [ ] `03-templates/pe-assessment-checklist.md` — printed or on tablet
- [ ] Previous audit findings (if this is a reassessment)
- [ ] Engagement letter or scope document (for site security check-in)
- [ ] Camera for photographing physical evidence (entry points, equipment labels)

### Confirm Analyst Access to Assessment Systems

Run this quick validation before starting formal assessment work:

```bash
# Verify evidence directory can be created
mkdir -p /tmp/jsa-evidence/physical-test && echo "Evidence directory OK"

# Verify audit scripts are executable
ls -la 01-auditors/
# Expected: -rwxr-xr-x for both .sh files

# Run a dry-run pass of one audit script to confirm no syntax errors
bash -n 01-auditors/audit-physical-access.sh && echo "Script syntax OK"
bash -n 01-auditors/audit-environmental-controls.sh && echo "Script syntax OK"
```

---

## Ready to Assess

When all credentials are confirmed and scripts validate cleanly, proceed to `01-assess.md`.
