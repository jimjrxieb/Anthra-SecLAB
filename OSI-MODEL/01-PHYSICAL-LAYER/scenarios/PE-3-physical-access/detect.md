# PE-3 Physical Access Control — Detect

## Detection Methods

### 1. Access Log Analysis
- Pull badge reader logs for the entry point
- Look for entries where a door-open event occurred without a corresponding badge swipe
- Compare badge swipe count vs. occupancy sensor count (if available)

### 2. CCTV Review
- Review camera footage for the entry point during the exercise window
- Identify instances of multiple people entering on a single badge swipe
- Document timestamp, individuals, and whether challenge occurred

### 3. Visitor Log Audit
- Check visitor sign-in log against CCTV footage
- Identify anyone present in the facility who is not on the log or badge list
- Verify escort policy compliance (were visitors accompanied?)

## Evidence to Collect

| Evidence | Format | Purpose |
|----------|--------|---------|
| Badge reader log export | CSV/PDF | Proves gap between door events and badge swipes |
| CCTV screenshot/clip | Image/Video | Visual proof of tailgating |
| Visitor log scan | PDF | Shows missing entries |
| Occupancy count vs. badge count | Spreadsheet | Quantifies unauthorized entries |

## Expected Finding

If tailgating succeeds: "PE-3 finding — physical access control bypassed via social engineering. Badge-controlled entry point allows unauthorized access without challenge."
