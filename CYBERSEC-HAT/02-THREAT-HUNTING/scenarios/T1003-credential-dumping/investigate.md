# T1003 Credential Dumping — Hunt Investigation

**ATT&CK:** T1003 — OS Credential Dumping
**Hunt type:** Hypothesis-driven — looking for credential theft that has not yet generated an alert

## Hypothesis

> IF an attacker has compromised a host and attempted credential dumping, THEN I expect to see unusual process access to /etc/shadow, ptrace syscalls on sensitive processes, or credential dumping tool binaries in non-standard paths, IN auditd logs or process telemetry.

## Investigation Checklist

### Phase 1: File Access Analysis

- [ ] Run detect.sh and review `cred-file-access.txt` — are any unexpected processes listed?
- [ ] Expected processes to access /etc/passwd: `passwd`, `id`, `getent`, `nscd`, `sshd`, `sudo`
- [ ] Expected processes to access /etc/shadow: `passwd`, `sudo`, `PAM stack processes`
- [ ] Any process NOT in the above list accessing shadow = investigate immediately

### Phase 2: Memory Analysis

- [ ] Review `rwx-memory.txt` — which processes have anonymous RWX memory?
- [ ] Expected RWX: JIT compilers (node, java), some Python C extensions
- [ ] Unexpected RWX: bash, python without JIT, any system utility
- [ ] For suspicious PIDs: `cat /proc/<PID>/cmdline | tr '\0' ' '` — what is the command?
- [ ] Check parent process: `grep PPid /proc/<PID>/status`

### Phase 3: Tool Detection

- [ ] Review `dumping-tools.txt` — any known tools found?
- [ ] Check recently created binaries: `find /tmp /var/tmp -newer /proc/1 -executable -type f`
- [ ] Check for unusual Python scripts importing subprocess with shadow references

### Phase 4: Timeline

- [ ] When were credential files last modified? (from `cred-file-stats.txt`)
- [ ] When were suspicious processes first started? (`ps -eo pid,lstart,cmd`)
- [ ] Does the timeline align with any known access events?

## Positive Finding: Escalate If

- Any non-expected process has an open handle to /etc/shadow
- auditd shows ptrace access from an unexpected process
- Known credential dumping tool binary found
- Password hash file was modified recently without a change control ticket
