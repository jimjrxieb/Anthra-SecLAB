# AC-12 No Session Timeout — Microsoft Entra ID Conditional Access Configuration

## Purpose

Configure session timeout policies in Microsoft Entra ID (formerly Azure AD) using Conditional Access. This is the identity provider-level enforcement that complements application-level session controls configured by fix.sh.

## Prerequisites

- Microsoft Entra ID P1 or P2 license (Conditional Access requires P1 minimum)
- Global Administrator or Conditional Access Administrator role
- Test user accounts for validation (do not test with production admin accounts first)

## Step 1: Navigate to Conditional Access

1. Sign in to the [Microsoft Entra admin center](https://entra.microsoft.com)
2. Navigate to **Protection** > **Conditional Access**
3. Click **+ New policy**
4. Name the policy: `AC-12 Session Timeout - Standard Users`

## Step 2: Configure Assignments

### Users
1. Under **Users**, click **0 users and groups selected**
2. Select **All users**
3. Under **Exclude**, add your break-glass emergency access accounts
   - These accounts must always have access regardless of policy
   - Document excluded accounts in your exception register

### Target Resources
1. Under **Target resources**, click **No target resources selected**
2. Select **All cloud apps**
3. Optionally exclude specific apps that have their own session management (e.g., Azure Portal has its own timeout)

### Conditions (Optional but Recommended)
1. Under **Conditions** > **Client apps**, ensure **Browser** and **Mobile apps and desktop clients** are selected
2. Under **Conditions** > **Locations**, optionally apply stricter timeouts for untrusted locations

## Step 3: Configure Session Controls

1. Under **Session**, click **0 controls selected**
2. Enable **Sign-in frequency**
   - Set to **8 hours** for standard users
   - This enforces the maximum session lifetime (AC-12 max lifetime)
   - After 8 hours, the user must re-authenticate regardless of activity
3. Enable **Persistent browser session**
   - Set to **Never persistent**
   - This ensures the session does not survive browser close
   - Users must re-authenticate after closing and reopening the browser

## Step 4: Create Privileged User Policy

1. Create a second policy: `AC-12 Session Timeout - Privileged Users`
2. Under **Users**, select your privileged role groups:
   - Global Administrators
   - Security Administrators
   - Exchange Administrators
   - Any custom admin roles
3. Under **Session**:
   - **Sign-in frequency**: **1 hour** (stricter for privileged accounts)
   - **Persistent browser session**: **Never persistent**
4. Under **Grant**:
   - Require **multifactor authentication**
   - Require **compliant device** (if using Intune)

## Step 5: Configure Token Lifetime Policies

Token lifetime policies control how long access tokens, refresh tokens, and session tokens are valid.

### Via PowerShell (Microsoft Graph)

```powershell
# Install Microsoft Graph PowerShell module
Install-Module Microsoft.Graph -Scope CurrentUser

# Connect with required permissions
Connect-MgGraph -Scopes "Policy.ReadWrite.ApplicationConfiguration"

# Create token lifetime policy
$params = @{
    definition = @(
        '{"TokenLifetimePolicy":{"Version":1,"AccessTokenLifetime":"00:15:00","MaxInactiveTime":"00:15:00","MaxAgeSessionSingleFactor":"08:00:00","MaxAgeSessionMultiFactor":"08:00:00"}}'
    )
    displayName = "AC-12 Token Lifetime Policy"
    isOrganizationDefault = $true
}

New-MgPolicyTokenLifetimePolicy -BodyParameter $params
```

### Token Lifetime Settings Explained

| Setting | Value | Justification |
|---------|-------|---------------|
| AccessTokenLifetime | 15 minutes | Short-lived access tokens limit damage from token theft |
| MaxInactiveTime | 15 minutes | Idle timeout — session terminated after 15 min inactivity |
| MaxAgeSessionSingleFactor | 8 hours | Max session for single-factor auth |
| MaxAgeSessionMultiFactor | 8 hours | Max session even with MFA (forces daily re-auth) |

## Step 6: Enable Continuous Access Evaluation (CAE)

CAE allows Entra ID to revoke tokens in near real-time when security conditions change (user disabled, password changed, location changed).

1. Navigate to **Protection** > **Conditional Access** > **Continuous access evaluation**
2. Set to **Enabled**
3. This overrides token lifetime for critical events:
   - User account disabled or deleted
   - Password changed or reset
   - MFA enabled for the user
   - Admin explicitly revokes refresh tokens
   - Azure AD Identity Protection detects elevated user risk

## Step 7: Configure Idle Session Timeout for Microsoft 365

1. Navigate to **Settings** > **Org settings** > **Security & privacy** > **Idle session timeout**
2. Enable **Idle session timeout**
3. Set to **15 minutes** for web apps
4. Select **Show a warning before signing out** — users get a countdown notification

## Step 8: Enable the Policies

1. Return to each Conditional Access policy
2. Set **Enable policy** to **On**
   - Use **Report-only** first for 7 days to assess impact
   - Review the sign-in logs for policy matches that would have been enforced
   - After validation, switch to **On**

## Validation

After enabling the policies:

1. Sign in as a test user
2. Verify the session expires after 15 minutes of inactivity
3. Verify the session expires after 8 hours regardless of activity
4. Verify closing and reopening the browser requires re-authentication
5. Verify privileged users are prompted for MFA and have shorter timeouts
6. Check the Conditional Access insights workbook for policy effectiveness

## Rollback

If the policy causes issues:

1. Set the policy to **Report-only** mode (do not delete it)
2. Review sign-in logs for users who were blocked or had issues
3. Adjust exclusions or conditions as needed
4. Re-enable after adjusting

## Common Issues

| Issue | Cause | Fix |
|-------|-------|-----|
| Users prompted too often | Sign-in frequency too short | Increase to 8 hours for standard users |
| Break-glass account locked | Not excluded from policy | Add to exclusion list immediately |
| Legacy apps fail | Do not support modern auth | Add to exclusion list, document risk acceptance |
| Token lifetime policy not applying | Policy not assigned to service principal | Assign via `Add-MgServicePrincipalTokenLifetimePolicy` |
| CAE not working | App does not support CAE | Check Microsoft docs for CAE-capable apps list |

## Evidence for Auditors

Export the following for AC-12 compliance evidence:

1. **Conditional Access policy export:** Entra admin center > Conditional Access > select policy > Export JSON
2. **Sign-in logs:** Entra admin center > Monitoring > Sign-in logs (filter by Conditional Access)
3. **Token lifetime policy:** `Get-MgPolicyTokenLifetimePolicy | Format-List`
4. **CAE status:** Screenshot of Continuous Access Evaluation settings
5. **Idle timeout configuration:** Screenshot of Org settings > Idle session timeout
