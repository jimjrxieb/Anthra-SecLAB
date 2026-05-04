# Fix: PE-14 Environmental Monitoring Gaps

## When This Control Fails

PE-14 failures present as:

- No temperature or humidity monitoring in the server room
- Monitoring exists but alerts are not configured or go to the wrong recipient
- HVAC has no maintenance schedule — failures happen without warning
- Temperature or humidity is chronically outside acceptable ranges
- No water/leak detection under raised floors or near HVAC drain pans
- Fire suppression uses water sprinklers instead of a clean agent (destroys equipment)

NIST SP 800-53 PE-14 requires organizations to maintain temperature and humidity at levels consistent with manufacturer and industry standards. PE-13 covers fire protection. PE-15 covers water damage protection. These controls together protect the physical hardware that everything else depends on.

---

## How to Fix

### Environmental Sensor Deployment

**Acceptable thresholds (ASHRAE A1 class server equipment):**
- Temperature: 64–75°F (18–24°C) — normal operating range
- Temperature warning: 78°F (26°C) — alert before equipment throttling
- Temperature critical: 85°F (29°C) — immediate action required, risk of hardware damage
- Humidity: 40–60% relative humidity — safe operating range
- Humidity warning: <35% or >65% — static or condensation risk

**Enterprise options:**
- APC NetBotz — rack-mount environmental monitors, SNMP integration, email/SMS alerts
- Vertiv Liebert — integrated with PDU and HVAC management
- Geist Watchdog — cost-effective, web interface, SNMP/email alerts

**Open-source option (Nagios + sensor integration):**
1. Deploy a Raspberry Pi or small SBC in the server room.
2. Attach a DHT22 or SHT31 temperature/humidity sensor.
3. Write a Nagios plugin that reads sensor values and returns OK/WARNING/CRITICAL states.
4. Configure Nagios notification contacts for the on-call group.
5. Thresholds: WARNING at 78°F or outside 35–65% RH; CRITICAL at 85°F or outside 20–75% RH.

**Alert routing requirements:**
- Alerts must reach someone who can act — not just email a shared mailbox nobody monitors
- On-call rotation or 24/7 NOC for production data centers
- Test alerts monthly: confirm delivery and confirm the recipient knows the response procedure

### Fire Suppression Testing

1. Confirm suppression agent type. FM-200 (HFC-227ea) and Novec 1230 (FK-5-1-12) are equipment-safe clean agents. CO2 is not safe for occupied spaces. Halon is banned.
2. Schedule an annual inspection with a licensed fire protection contractor.
3. Inspection should include: agent cylinder weight/pressure check, actuation system test (without discharge), detector sensitivity test.
4. Request a written inspection report. Keep it for 3 years minimum.
5. Confirm suppression zones align with current equipment layout — systems installed years ago may not cover new cage additions.

### UPS Load Testing

1. Document all equipment on UPS circuits — servers, network gear, cooling, KVM.
2. Calculate actual load (watts) using PDU metering or smart PDUs.
3. UPS should carry load at no more than 80% capacity (derate for battery degradation).
4. Conduct a scheduled load test: transfer to battery, measure actual runtime under load.
5. Replace batteries on manufacturer schedule — typically every 3–5 years regardless of test results.
6. Test results should be documented: date, load percentage, measured runtime, pass/fail.

### Water Detection

1. Install water detection sensors in:
   - Under raised floor tiles (especially near HVAC unit drain pans)
   - Near any overhead pipes above IT equipment
   - In any area where condensation is possible
2. Connect sensors to the building management system (BMS) or environmental monitoring system.
3. Configure alerts with the same routing as temperature alerts.
4. Test sensors annually: apply a small amount of water to the detection element and confirm alert fires.

---

## Evidence for Auditors

| Evidence Item | What to Provide |
|---------------|-----------------|
| Temperature/humidity logs | 30–90 day historical export from monitoring system |
| Alert configuration | Screenshot or export of alert thresholds and notification contacts |
| HVAC maintenance record | Last service report with contractor name and date |
| Fire suppression inspection | Contractor inspection report (most recent) |
| UPS load test | Test report with load percentage and measured runtime |
| Water sensor test | Test log entry with date and pass/fail |
| Environmental monitoring dashboard | Screenshot showing current readings within range |

All evidence should be saved to:
`/tmp/jsa-evidence/environmental-controls-<TIMESTAMP>/`
