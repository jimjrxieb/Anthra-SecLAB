# Missing MFA Enforcement — Evidence Checklist

## Finding Evidence
- [ ] detect.sh output showing users without MFA
- [ ] Privileged accounts without MFA list
- [ ] NOPASSWD sudo rules (if any)
- [ ] SSH PasswordAuthentication setting

## Account Risk Evidence
- [ ] Auth log review for no-MFA privileged accounts (any brute force attempts?)
- [ ] Remote access capability for no-MFA accounts (which can SSH externally?)

## Remediation Proof
- [ ] PAM MFA module installed: `dpkg -l libpam-google-authenticator` or equivalent
- [ ] PAM sshd configuration showing MFA required
- [ ] SSH sshd_config showing `AuthenticationMethods publickey,keyboard-interactive`
- [ ] MFA enrollment confirmed for all privileged users (`.google_authenticator` file present)
- [ ] NOPASSWD rules removed (sudoers output showing no NOPASSWD)
- [ ] Test result: SSH prompts for TOTP code

## IA-2 Compliance Artifact
- [ ] Policy document requiring MFA for privileged and remote access (if available)
- [ ] List of all privileged accounts with MFA confirmed
- [ ] Enrollment completion date per account
