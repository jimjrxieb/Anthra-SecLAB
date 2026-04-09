# PE-14 Environmental Controls — Validate

## Validation Steps

### 1. Sensor Functionality Test
- Verify all sensors report current temperature to the monitoring system
- Place a heat source near a sensor and confirm the reading changes within 60 seconds
- Verify sensor battery/power status

### 2. Alert Threshold Test
- Simulate a threshold breach (adjust threshold temporarily or use heat source)
- Verify: warning alert fires at 80°F threshold
- Verify: critical alert fires at 85°F threshold
- Verify: alerts reach all configured recipients within 2 minutes

### 3. Failover Test (if redundant HVAC installed)
- Shut down primary HVAC unit during a maintenance window
- Verify: backup unit activates within 5 minutes
- Verify: temperature stays within acceptable range during failover
- Verify: alert fires for primary unit failure

### 4. Procedure Test
- Run a tabletop exercise using the emergency procedure document
- Verify: all team members know their role
- Verify: contact information is current
- Verify: shutdown sequence is documented and tested

## Validation Evidence

| Check | Pass Criteria | Evidence |
|-------|-------------|----------|
| Sensors reporting | All sensors show current temp | Monitoring dashboard screenshot |
| Warning alert | Fires within 2 min of threshold | Alert notification screenshot with timestamp |
| Critical alert | Fires within 2 min of threshold | Alert notification screenshot with timestamp |
| HVAC failover | Backup activates within 5 min | Temperature log showing stable temp during failover |
| Procedure test | All roles understood, contacts current | Tabletop exercise report |
