# Credential Theft Response — Evidence Checklist

## Theft Evidence
- [ ] auditd events for /etc/shadow access
- [ ] Process that accessed credential files (PID, cmdline, parent)
- [ ] Any dumping tool binaries found (hash + VirusTotal result)
- [ ] Bash history entries showing extraction commands

## Credential Use Evidence
- [ ] Auth log extract for all compromised accounts
- [ ] Source IPs that used compromised credentials
- [ ] Multi-account same-IP analysis output
- [ ] Timeline of credential use (first use after theft)

## Lateral Movement Evidence
- [ ] Systems touched by compromised accounts after theft
- [ ] Internal-to-internal authentication using compromised credentials
- [ ] New SSH keys or accounts added using compromised credentials

## Remediation Proof
- [ ] Credential rotation confirmation (passwd -S for all affected accounts)
- [ ] Sessions killed (who output after termination)
- [ ] authorized_keys cleaned (before/after diff or current contents)
- [ ] API tokens rotated (screenshot of rotation in each platform)
- [ ] MFA re-enrollment confirmation
