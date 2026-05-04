# Exposed Management Ports — Investigation

**Controls:** SC-7 (Boundary Protection), CM-7 (Least Functionality)
**Risk:** This is the #1 ransomware entry vector (Sophos 2024)

## Investigation Checklist

### Confirm the Exposure

- [ ] Run detect.sh — which ports are exposed to 0.0.0.0?
- [ ] Is this system internet-facing or internal only?
  ```bash
  curl -s ifconfig.me  # get public IP
  nmap -sS -p 22,3389,5985 <your_public_ip>  # confirm internet reachability
  ```
- [ ] Is there a firewall or NAT in front? (A private IP listening on 0.0.0.0 may still be protected by cloud security group or NAT)

### Check for Active Exploitation Attempts

- [ ] How many failed authentication attempts in the last 24 hours?
  ```bash
  grep "Failed password" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -rn | head -10
  ```
- [ ] Are any of the attacking IPs known malicious? (Check AbuseIPDB)
- [ ] Has any brute force attempt succeeded?
  ```bash
  # Check if any attacking IP also has a successful login
  grep "Accepted" /var/log/auth.log | awk '{print $11}' > /tmp/success.txt
  grep "Failed password" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -rn | awk '{print $2}' | sort > /tmp/fail.txt
  comm -12 /tmp/success.txt /tmp/fail.txt
  ```

### SSH Configuration Review

- [ ] Is PasswordAuthentication enabled? (Should be no — key-based auth only)
- [ ] Is PermitRootLogin enabled? (Should be no)
- [ ] Are there AllowUsers or AllowGroups restrictions?
- [ ] What is MaxAuthTries set to? (Should be 3 or less)

## Escalate If

- The service is confirmed internet-facing (not just 0.0.0.0 on an internal system)
- There are more than 100 failed authentication attempts per day
- Any brute-force source IP also has a successful login
- Telnet is running anywhere
