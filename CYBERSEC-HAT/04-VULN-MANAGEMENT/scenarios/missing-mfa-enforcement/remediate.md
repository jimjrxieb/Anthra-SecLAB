# Missing MFA Enforcement — Remediation

## Option 1: TOTP (Google Authenticator / libpam-oath)

```bash
# Install the PAM module
sudo apt install libpam-google-authenticator -y

# Each user enrolls their own TOTP token
su - <username>
google-authenticator
# Answer: y (time-based), y (update .google_authenticator), y (disallow multiple use), n (extend window), y (rate limit)

# Configure PAM for SSH
sudo tee /etc/pam.d/sshd_mfa << 'EOF'
auth required pam_google_authenticator.so nullok
EOF

# Add to /etc/pam.d/sshd:
# auth required pam_google_authenticator.so

# Configure SSH to require both key + TOTP
# /etc/ssh/sshd_config:
# AuthenticationMethods publickey,keyboard-interactive
# ChallengeResponseAuthentication yes
# UsePAM yes

sudo systemctl restart sshd
```

## Option 2: Hardware Keys (FIDO2 / YubiKey)

```bash
# Install FIDO2 PAM module
sudo apt install libpam-u2f -y

# User enrolls their hardware key
pamu2fcfg > ~/.config/Yubico/u2f_keys

# Configure PAM
# /etc/pam.d/sshd: add
# auth required pam_u2f.so
```

## Option 3: Remove NOPASSWD Sudo Rules

```bash
# Review all NOPASSWD rules
grep -r "NOPASSWD" /etc/sudoers /etc/sudoers.d/

# Edit sudoers safely with visudo
sudo visudo
# Remove or comment out NOPASSWD entries

# Or remove the file if it contains only NOPASSWD rules
sudo rm /etc/sudoers.d/<file_with_nopasswd>
```

## Enforce MFA Policy

After enrollment, make MFA non-optional:
- Remove `nullok` from the PAM module line (nullok allows login even without MFA configured)
- Set a deadline for all accounts to enroll before access is revoked
- Document the MFA policy in writing

## Verification

```bash
# Test that MFA is now required for SSH
ssh <user>@localhost
# Should prompt for TOTP code after key authentication

# Verify NOPASSWD removed
sudo -l -U <username>   # should not show NOPASSWD

# Confirm all privileged users have MFA
for user in $(getent group sudo | cut -d: -f4 | tr ',' ' '); do
    home=$(getent passwd "$user" | cut -d: -f6)
    [ -f "${home}/.google_authenticator" ] && echo "[OK] $user" || echo "[MISSING] $user"
done
```
