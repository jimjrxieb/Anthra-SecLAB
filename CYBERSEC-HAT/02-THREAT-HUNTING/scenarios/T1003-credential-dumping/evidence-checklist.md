# T1003 Credential Dumping — Evidence Checklist

## Hunt Evidence (Document Even for Negative Findings)
- [ ] detect.sh full output (save to evidence/)
- [ ] List of processes accessing /etc/shadow at time of hunt
- [ ] auditd events for /etc/shadow access (ausearch output)
- [ ] RWX memory process list
- [ ] File modification timestamps for /etc/passwd and /etc/shadow

## Positive Finding Evidence (if applicable)
- [ ] PID and full command line of dumping process
- [ ] Parent process chain
- [ ] Memory map of suspicious process (/proc/<PID>/maps)
- [ ] Binary hash of any suspicious executable found
- [ ] VirusTotal result for binary hash

## Remediation Proof
- [ ] auditd credential-access rules in place (auditctl -l output)
- [ ] Credential rotation confirmation (passwd -S output)
- [ ] No new authorized_keys added (find output)
- [ ] No new cron jobs (crontab -l output for all users)

## CA-7 Evidence (Negative Finding)
- [ ] Hunt date and analyst name
- [ ] Hypothesis tested
- [ ] Queries run (list)
- [ ] Data sources available and coverage assessment
- [ ] Conclusion: no evidence of credential dumping found
