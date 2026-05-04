# T1021.001 RDP Lateral Movement — Hunt Investigation

**ATT&CK:** T1021.001 — Remote Services: RDP / T1021.004 — SSH
**Hunt type:** Hypothesis-driven — looking for attacker moving laterally between internal systems

## Hypothesis

> IF an attacker with initial access is moving laterally, THEN I expect to see new internal-to-internal SSH/RDP connections between hosts that do not normally communicate, at unusual times or with unusual frequency, IN authentication logs.

## Investigation Checklist

### Phase 1: Baseline Comparison

- [ ] What is the normal set of internal source-destination login pairs? (document from last 30 days)
- [ ] Review `internal-login-pairs.txt` — are there any source-destination pairs that are NEW?
- [ ] New pairs that were not seen in the prior 30 days = lateral movement indicator

### Phase 2: Temporal Analysis

- [ ] Review `off-hours-internal.txt` — any internal logins outside business hours?
- [ ] Lateral movement often happens outside business hours to avoid detection
- [ ] Check: is this a scheduled job (expected) or an interactive session (unexpected)?

### Phase 3: Frequency Analysis

- [ ] How many internal logins happened in the last 24 hours vs. normal?
- [ ] Is one account logging into many different hosts in a short window? (hop-to-hop movement)
  ```bash
  grep "Accepted" /var/log/auth.log | grep "from 192.168\|from 10." | awk '{print $9}' | sort | uniq -c | sort -rn | head -10
  ```

### Phase 4: Account Analysis

- [ ] Which accounts are used for internal movement?
- [ ] Are these service accounts, admin accounts, or regular user accounts?
- [ ] Do the accounts have a business reason to access those hosts?
- [ ] Check if the same account has been used from multiple IPs simultaneously

### Phase 5: Session Activity

- [ ] For suspicious sessions: what did the account do after logging in?
- [ ] Pull auth log and syslog for the source host at the same timestamp
- [ ] Is there a chain? (Host A → Host B → Host C) = clear lateral movement

## Escalate If

- New internal login pair with no business justification
- Same account used from multiple hosts within a short window
- Admin account used to hop between multiple hosts rapidly
- Evidence of command execution after internal login
