# T1059.001 Malicious Scripting — Evidence Checklist

## Script Evidence
- [ ] Copy of the malicious script (preserve as-is)
- [ ] Decoded version of any base64/obfuscated content
- [ ] SHA256 hash of the script file
- [ ] VirusTotal result for the hash

## Process Evidence
- [ ] Process tree at time of execution (ps auxf or EDR screenshot)
- [ ] Parent-child process relationship documented
- [ ] PID, start time, and user context

## Network Evidence
- [ ] Any outbound connections made (IP, port, domain)
- [ ] DNS lookups made during execution
- [ ] VirusTotal or Shodan result for C2 IPs/domains

## Persistence Evidence
- [ ] Crontab before and after (diff)
- [ ] SSH authorized_keys before and after
- [ ] Any new user accounts created
- [ ] Any new systemd units or init scripts

## Remediation Proof
- [ ] Process killed (ps aux confirming it is gone)
- [ ] Dropped files removed
- [ ] C2 IP blocked (iptables output)
- [ ] auditd execve rule in place
