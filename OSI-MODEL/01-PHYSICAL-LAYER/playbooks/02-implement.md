# Layer 1 Physical — Implement Controls

## Purpose

Implement physical security controls based on assessment findings. Start with highest-risk gaps from the 01-assess output.

## Implementation Order

Priority by risk and cost-efficiency:

### Priority 1: Policy and Training (Week 1-2, ~$2,500)
1. Write anti-tailgating policy
2. Write visitor management policy
3. Write environmental emergency procedure
4. Deliver security awareness briefing to all staff
5. Post signage at controlled entry points

### Priority 2: Monitoring and Alerting (Week 2-4, ~$1,000)
1. Install temperature sensors in server room (minimum 2)
2. Configure alert thresholds: warning 80°F, critical 85°F, emergency 90°F
3. Route alerts to NOC + facilities + on-call via SMS/email/PagerDuty
4. Verify CCTV covers all badge-controlled entry points
5. Enable access log anomaly alerting (off-hours, failed attempts)

### Priority 3: Hardware Controls (Month 2-3, ~$20,000-$50,000)
1. Install turnstile or mantrap at data center entry
2. Install redundant HVAC with automatic failover
3. Install hot/cold aisle containment if not present

### Priority 4: Advanced Controls (Month 3-6, ~$10,000-$25,000)
1. Biometric second factor at high-security entry points
2. Predictive maintenance sensors on HVAC
3. DCIM integration for environmental monitoring dashboard

## Verification After Each Implementation

After each control is implemented, run the corresponding scenario's `validate.md` to confirm it works. Do not proceed to the next priority without validation.
