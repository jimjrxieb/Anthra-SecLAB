# T1055 Process Injection — Evidence Checklist

## Hunt Evidence
- [ ] detect.sh full output
- [ ] RWX anonymous memory list (rwx-anon-memory.txt)
- [ ] Suspicious parent-child list
- [ ] Deleted executable process list
- [ ] Network connections at time of hunt

## Positive Finding Evidence
- [ ] Memory dump of injected process (gcore output)
- [ ] Process maps (/proc/<PID>/maps)
- [ ] Full process tree showing parent-child chain
- [ ] Network connections from injected process
- [ ] VirusTotal result for any dropped binaries

## Remediation Proof
- [ ] Process killed (ps aux confirming gone)
- [ ] ptrace_scope = 1 (sysctl output)
- [ ] Memory dump preserved for forensics
- [ ] No active outbound connections from host

## CA-7 Evidence (Negative Finding)
- [ ] Hunt date and analyst name
- [ ] Hypothesis tested
- [ ] All processes reviewed with no RWX anonymous memory found
- [ ] ptrace_scope value at time of hunt
