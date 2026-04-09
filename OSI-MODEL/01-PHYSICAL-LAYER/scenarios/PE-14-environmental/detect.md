# PE-14 Environmental Controls — Detect

## Detection Methods

### 1. Temperature Sensor Check
- Verify sensors are installed in the server room
- Check: do they report to a central monitoring system?
- Check: what thresholds trigger alerts? (Should be: warning at 80°F/27°C, critical at 85°F/29°C)
- Check: who receives alerts? (Should be: NOC + facilities + on-call engineer)

### 2. HVAC System Audit
- Document primary HVAC unit: make, model, capacity, age, last maintenance date
- Check: is there a redundant/backup unit?
- Check: is there an automatic failover mechanism?
- Check: what is the rated cooling capacity vs. actual heat load?

### 3. Monitoring Dashboard Review
- Check if environmental metrics are on the NOC dashboard
- Verify alert routing: does an HVAC alert page someone 24/7?
- Test alert: simulate a threshold breach and verify the alert fires

### 4. Maintenance Records
- Review HVAC maintenance log for past 12 months
- Verify: are filters changed quarterly? Refrigerant levels checked? Capacity tested?

## Evidence to Collect

| Evidence | Format | Purpose |
|----------|--------|---------|
| Temperature sensor inventory | Spreadsheet | Proves sensors exist and are positioned correctly |
| HVAC maintenance log | PDF/CSV | Proves regular maintenance |
| Alert configuration screenshot | Image | Proves thresholds and routing are set |
| Alert test result | Screenshot | Proves alerts actually fire and reach the right people |
