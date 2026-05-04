# T1055 Process Injection — Hunt Investigation

**ATT&CK:** T1055 — Process Injection
**Hunt type:** Hypothesis-driven — looking for shellcode or injected code in process memory

## Hypothesis

> IF an attacker has injected code into a running process, THEN I expect to see anonymous executable memory segments (not backed by a file on disk) in a legitimate process, IN /proc/[pid]/maps telemetry.

## Investigation Checklist

### Phase 1: RWX Memory Analysis

- [ ] Review `rwx-anon-memory.txt` — which processes have anonymous RWX pages?
- [ ] For each flagged process:
  - What is the process? Is it expected to have JIT-compiled code?
  - Expected RWX: node, java, python (with C extensions), browsers
  - Unexpected RWX: bash, system utilities, anything not doing JIT
- [ ] For suspicious processes: review full memory map
  ```bash
  cat /proc/<PID>/maps | grep rwx
  ```

### Phase 2: Parent-Child Relationship Analysis

- [ ] Review `suspicious-parent-child.txt`
- [ ] Map the full process tree: `ps auxf | grep -A5 -B5 <suspicious_process>`
- [ ] Ask: is it reasonable for this parent to have spawned this child?
  - `sshd → bash → python3` = interactive attacker session (possible)
  - `apache2 → bash` = web shell execution (highly suspicious)
  - `cron → python3 → curl` = scheduled task calling out (investigate)

### Phase 3: Deleted Executable Investigation

- [ ] Review `deleted-exe.txt` — processes running from deleted files indicate an executable was run and then deleted (anti-forensics)
- [ ] For each: what process? When was it started? What is it doing?
- [ ] Check network connections for processes with deleted executables

### Phase 4: Network Correlation

- [ ] Cross-reference `network-connections.txt` with suspicious processes
- [ ] A process with injected code AND an outbound connection = likely C2

## Escalate If

- Any unexpected process has anonymous RWX memory
- A web server, database, or system process spawned a shell
- Any process running with a deleted executable on disk
- Injected process has an outbound network connection
