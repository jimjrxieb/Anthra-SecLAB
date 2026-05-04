# Eradication

## Purpose

Remove all attacker presence. Close every entry point. Destroy all persistence mechanisms.

## Eradication Checklist

### Remove Persistence
```bash
# Cron jobs
for user in $(cut -d: -f1 /etc/passwd); do crontab -l -u "$user" 2>/dev/null; done
# Review each and remove malicious entries

# SSH authorized_keys
find /home /root -name "authorized_keys" -exec cat {} \; | grep -v <known_good_key>

# Systemd units
find /etc/systemd/system/ -newer /proc/1 -ls

# New user accounts
grep -v "nologin\|false" /etc/passwd | tail -10
```

### Remove Attacker Tools
```bash
find /tmp /var/tmp /dev/shm -type f -executable -newer /proc/1 -ls
# Preserve copies before deleting
sha256sum <file> > /tmp/evidence-hash.txt
sudo rm <malicious_file>
```

### Close Initial Access Vector
- Patch the vulnerability that was exploited
- Rotate the credentials that were stolen
- Remove the phishing email and block sender domain
- Update firewall rules to block the attack path

### Validate Eradication
After eradication, re-run the detection scripts from the relevant scenario to confirm no indicators remain.

## Do Not Eradicate Before

- [ ] Full evidence collection completed
- [ ] Attack timeline documented
- [ ] All affected systems identified (blast radius mapped)
- [ ] Stakeholders notified
- [ ] Forensic images taken if needed

Eradicating before scoping means you might miss a persistence mechanism and the attacker comes back.
