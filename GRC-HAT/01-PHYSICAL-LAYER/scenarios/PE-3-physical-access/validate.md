# PE-3 Physical Access Control — Validate

## Validation Steps

### 1. Re-test Tailgating (after fix)
- Repeat the tabletop exercise 30 days after remediation
- Attempt tailgating at the same entry point
- Expected result: challenged by security or blocked by turnstile/mantrap

### 2. Access Log Verification
- Pull badge reader logs for 7-day period after fix
- Verify: door-open events = badge swipe events (no gaps)
- Verify: visitor log entries match CCTV visitor appearances

### 3. Policy Verification
- Confirm anti-tailgating policy is published and accessible
- Verify training completion records (% of staff trained)
- Verify signage is installed at all controlled entry points

### 4. Hardware Verification (if turnstiles/mantraps installed)
- Test: can two people pass on one badge swipe? Expected: no
- Test: does the system alert on tailgating attempt? Expected: yes
- Test: are alerts routed to security operations? Expected: yes

## Validation Evidence

| Check | Pass Criteria | Evidence |
|-------|-------------|----------|
| Tailgating re-test | Blocked or challenged | Test report with date, tester, result |
| Access log gap analysis | 0 gaps in 7-day window | Log export with analysis |
| Policy published | Document exists, dated, approved | Policy document PDF |
| Training completion | >90% staff trained | LMS completion report |
| Hardware functional | Blocks dual entry | Test video/screenshot |
