# Credential Theft Response — Remediation

## Scope Before Acting

Map every account and every system affected before rotating anything. Rotating credentials piecemeal tips off an attacker who may then escalate.

## Credential Rotation (All Affected Accounts Simultaneously)

```bash
# Linux local accounts
for user in compromised_user1 compromised_user2; do
    sudo passwd "$user"
    sudo usermod -L "$user"   # lock until user confirms receipt of new creds
done

# Rotate SSH keys — remove old authorized_keys on all systems
find /home /root -name "authorized_keys" -exec truncate -s 0 {} \;
# Re-issue keys to legitimate users from clean workstation
```

## Kill All Active Sessions

```bash
# Kill all sessions for compromised users
for user in compromised_user1 compromised_user2; do
    pkill -u "$user" -KILL 2>/dev/null || true
done

# Verify
who -a | grep -E "compromised_user1|compromised_user2"
```

## Revoke Tokens and API Keys

- Rotate all API tokens associated with compromised accounts
- Rotate service account passwords
- Revoke and re-issue any certificates signed with compromised credentials
- Revoke OAuth/SAML tokens

## Remove Any Backdoors Established With Stolen Credentials

```bash
# Check for new accounts created
grep -v "nologin\|false" /etc/passwd | diff - <(cat /tmp/known-good-passwd) 2>/dev/null

# Check SSH keys across all users
for f in $(find /home /root -name "authorized_keys" 2>/dev/null); do
    echo "=== $f ==="; cat "$f"
done
```

## Verification

- [ ] All compromised credentials rotated simultaneously
- [ ] All active sessions terminated — `who` shows no sessions for affected users
- [ ] SSH authorized_keys cleaned on all affected systems
- [ ] API tokens and service account secrets rotated
- [ ] No new logins from previously seen attacker IPs (monitor for 72h)
- [ ] MFA re-enrolled on all affected accounts
