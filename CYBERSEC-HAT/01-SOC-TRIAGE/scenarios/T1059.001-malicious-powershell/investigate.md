# T1059.001 Malicious Scripting — Investigation

**ATT&CK:** T1059.001 — Command and Scripting Interpreter
**Triage time target:** 20 minutes to initial verdict

## Triage Checklist

### Script Analysis

- [ ] What interpreter was used? (bash, python, perl, powershell)
- [ ] Was the command encoded (base64) or obfuscated? Decode it:
  ```bash
  echo "<base64_string>" | base64 -d
  ```
- [ ] What does the decoded command do? Download and execute? Reverse shell? Credential dump?
- [ ] What process spawned the interpreter? (Parent process is key — mail client, browser, document?)

### Process Tree Analysis

- [ ] Pull the process tree for the suspicious interpreter PID
- [ ] What is the parent process? Parent-child relationships tell the story:
  - `office/browser → cmd/powershell` = likely phishing-based execution
  - `cron → bash` = possible persistence-based execution
  - `sshd → bash → python` = possible interactive attacker session
- [ ] Are any child processes of the script still running?

### Network Analysis

- [ ] Did the script make any outbound connections?
- [ ] What domains/IPs did it connect to? Check VirusTotal and Shodan
- [ ] Did it download any files? Check /tmp, /var/tmp, /dev/shm
- [ ] Any DNS lookups to unusual domains (especially long/random looking domains)?

### Persistence Check

- [ ] Did the script add any cron jobs?
- [ ] Did it add any SSH authorized_keys?
- [ ] Did it create any new user accounts?
- [ ] Did it modify any startup scripts or systemd units?

## Key Questions to Answer

1. What did the script do? (Decode it fully)
2. What spawned it?
3. Did it phone home?
4. Did it establish persistence?

## Escalate If

- Script made outbound connection to external/unknown host
- Script decoded to a reverse shell or C2 beacon
- Persistence was established (new cron, new SSH key, new user)
- Parent process is a productivity app (Office, browser, PDF reader)
