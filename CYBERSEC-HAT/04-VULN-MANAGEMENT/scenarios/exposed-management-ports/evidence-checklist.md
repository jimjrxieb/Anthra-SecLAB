# Exposed Management Ports — Evidence Checklist

## Finding Evidence
- [ ] detect.sh output showing exposed ports
- [ ] ss -tlnp output confirming 0.0.0.0 binding
- [ ] Public IP reachability test (nmap from external or cloud console)
- [ ] Failed authentication count (grep auth.log output)

## SSH Configuration Evidence (Before and After)
- [ ] sshd_config before hardening (backup copy)
- [ ] sshd_config after hardening

## Remediation Proof
- [ ] iptables rules restricting SSH to management subnet (iptables -L output)
- [ ] fail2ban status showing active bans (fail2ban-client status sshd)
- [ ] SSH password auth disabled — test result: `ssh -o PasswordAuthentication=yes` fails
- [ ] Root login disabled — test result: `ssh root@host` rejected
- [ ] Telnet removed (apt list --installed | grep telnet returns nothing)

## Re-scan Evidence
- [ ] detect.sh re-run output showing no EXPOSED ports
- [ ] Re-scan date and analyst name
