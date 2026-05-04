# Hunt Execution

## Process

1. **Set a time limit** — hunts should complete in 2-4 hours. If still inconclusive, document and schedule a follow-up.
2. **Start broad, narrow down** — begin with wide queries, then filter on anomalies
3. **Pivot on findings** — every anomaly is a thread to pull; follow it
4. **Document as you go** — write down every query you ran and what it returned

## Pivoting Technique

When you find something interesting:
1. What is the process/user/IP/domain?
2. What else did that entity do? (Expand the time window, look at all activity)
3. What does that entity connect to? (Pivot to network)
4. When did it first appear? (Establish timeline)
5. Is this in other systems too? (Scope the spread)

## Anomaly Indicators to Chase

- **Process:** Unexpected parent-child relationship, unusual path, unusual user context
- **Network:** New external connection, new internal connection, unusual port, unusual volume
- **Auth:** New source IP, new time pattern, new account, new credential type
- **File:** New executable in /tmp or /dev/shm, new cron entry, new SSH key
- **Memory:** ptrace calls on sensitive processes, rwx memory segments, hollowed processes

## Query → Find → Pivot Loop

```
Query: "Show me all processes with outbound connections"
  → Find: python3 process connected to 45.33.32.156:4444
  → Pivot: What is 45.33.32.156? (VirusTotal: Metasploit listener)
  → Pivot: What spawned python3? (parent: bash, parent: cron)
  → Pivot: What cron job runs bash? (found: */5 * * * * bash -c "python3 -c ...")
  → Finding: Cron-based persistence to C2
```

## Stopping Criteria

End the hunt and document when:
- Hypothesis confirmed: escalate to IR
- Hypothesis denied: document the negative with evidence
- Inconclusive: document queries run, data gaps identified, next steps
