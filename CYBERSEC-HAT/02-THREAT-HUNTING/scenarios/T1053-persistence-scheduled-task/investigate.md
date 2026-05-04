# T1053 Scheduled Task Persistence — Hunt Investigation

**ATT&CK:** T1053 — Scheduled Task/Job
**Hunt type:** Hypothesis-driven — looking for persistence via scheduled tasks

## Hypothesis

> IF an attacker has established persistence on a host, THEN I expect to see new or modified cron jobs, systemd timers, or at jobs with unusual commands (reverse shells, downloaders, base64-encoded payloads) created by non-system users, IN cron configuration files and systemd unit directories.

## Investigation Checklist

### Phase 1: Inventory All Scheduled Tasks

- [ ] Collect all crontabs — run detect.sh and review `user-crontabs.txt`
- [ ] Collect system cron dir contents — review `cron-file-contents.txt`
- [ ] Collect systemd timers — review `systemd-timers.txt`
- [ ] This establishes your baseline for this hunt session

### Phase 2: Identify New or Suspicious Entries

- [ ] Review `recently-modified-crons.txt` — anything modified recently without a change ticket?
- [ ] Review `new-systemd-units.txt` — any new service/timer units?
- [ ] Review `suspicious-cron-content.txt` — any curl|bash, wget|bash, base64, or netcat patterns?

### Phase 3: Analyze Suspicious Entries

For any suspicious cron job:
- [ ] What command does it run?
- [ ] What user does it run as?
- [ ] What time/frequency does it run?
- [ ] Decode any base64: `echo "<base64>" | base64 -d`
- [ ] If it downloads a script: what URL? Check VirusTotal
- [ ] If it connects out: what IP/port? Check AbuseIPDB

### Phase 4: Timeline Analysis

- [ ] When was the cron job created? (stat the file)
- [ ] Does this timestamp align with any known initial access event?
- [ ] Is there a correlation with any SIEM alert from around that time?

### Phase 5: Scope Check

- [ ] Is this cron job only on one host, or is it on multiple hosts?
- [ ] Check other hosts in the environment for the same entry

## Escalate If

- Any cron job runs a command that connects to an external host
- Any cron job decodes to a reverse shell or download-and-execute
- A recently modified cron file has no corresponding change ticket
- The cron job runs as root or a privileged service account
