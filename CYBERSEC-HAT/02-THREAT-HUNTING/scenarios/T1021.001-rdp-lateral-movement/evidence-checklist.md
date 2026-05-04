# T1021.001 Lateral Movement — Evidence Checklist

## Hunt Evidence
- [ ] Internal SSH login pairs (internal-login-pairs.txt)
- [ ] Off-hours internal logins (off-hours-internal.txt)
- [ ] Active session list at time of hunt
- [ ] Listening remote services inventory

## Positive Finding Evidence
- [ ] Full auth log for affected account
- [ ] Source-destination hop chain (A → B → C)
- [ ] Timestamps of each hop
- [ ] Commands run on each host (if available from audit logs)
- [ ] List of all hosts touched

## Remediation Proof
- [ ] Account locked (passwd -S output)
- [ ] Sessions terminated (who output after termination)
- [ ] SSH keys rotated (authorized_keys before/after)
- [ ] Network restriction in place (iptables -L or hosts.allow)

## CA-7 Evidence (Negative Finding)
- [ ] Hunt date and analyst name
- [ ] Internal login pairs reviewed — all pairs have business justification
- [ ] No off-hours internal logins found
- [ ] Baseline documented for comparison in future hunts
