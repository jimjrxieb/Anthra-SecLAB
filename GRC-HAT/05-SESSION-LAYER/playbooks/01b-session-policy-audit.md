# 01b-session-policy-audit.md — Session Policy Deep-Dive Audit

| Field | Value |
|---|---|
| **NIST Controls** | AC-12 (session termination), SC-23 (session authenticity), IA-5 (authenticator management) |
| **Tools** | Keycloak admin API, Burp Suite, browser DevTools, jwt.io, curl |
| **Enterprise Equiv** | Qualys Web App Scanning ($80K+/yr), Burp Suite Enterprise ($16K+/yr) |
| **Time** | 2 hours |
| **Rank** | B (requires manual inspection of token contents and cookie attributes) |

---

## Purpose

Deep-dive into session policy controls that automated scripts cannot fully assess: Keycloak realm settings, cookie attribute inspection via DevTools/Burp, JWT validation, and refresh token rotation behavior. Run `audit-session-policy.sh` first for the automated layer.

---

## 1. Keycloak Realm Settings Review

```bash
KC_URL="${KEYCLOAK_URL:-http://localhost:8080}"
KC_REALM="${KEYCLOAK_REALM:-master}"

# Get admin token
KC_TOKEN=$(curl -s -X POST \
  "${KC_URL}/realms/master/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=${KEYCLOAK_ADMIN:-admin}&password=${KEYCLOAK_PASSWORD:-admin}&grant_type=password&client_id=admin-cli" \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['access_token'])")

# Pull realm config and extract session-relevant fields
curl -s "${KC_URL}/admin/realms/${KC_REALM}" \
  -H "Authorization: Bearer ${KC_TOKEN}" \
  | python3 -c "
import json, sys
d = json.load(sys.stdin)

fields = {
    'ssoSessionIdleTimeout': ('Session idle timeout (s)', 1800, 'target ≤1800s'),
    'ssoSessionMaxLifespan': ('Session max lifespan (s)', 36000, 'target ≤36000s'),
    'accessTokenLifespan': ('Access token lifespan (s)', 300, 'target ≤300s'),
    'accessCodeLifespan': ('Auth code lifespan (s)', 60, 'target ≤60s'),
    'rememberMe': ('Remember-me enabled', False, 'should be False'),
    'bruteForceProtected': ('Brute force protection', True, 'should be True'),
    'failureFactor': ('Max login failures', 5, 'target ≤5'),
    'passwordPolicy': ('Password policy', None, 'check for length(12) minimum'),
    'otpPolicyType': ('OTP policy type', 'totp', 'should be totp'),
    'otpPolicyDigits': ('OTP digits', 6, 'standard: 6'),
    'otpPolicyPeriod': ('OTP period (s)', 30, 'standard: 30'),
    'sslRequired': ('SSL required', 'external', 'should be external or all'),
}

print('Keycloak Realm Session Policy Review')
print('=' * 60)
for field, (label, target, note) in fields.items():
    value = d.get(field, 'NOT_SET')
    status = 'OK' if target is None or value == target else 'REVIEW'
    if isinstance(target, int) and isinstance(value, int):
        status = 'OK' if value <= target else 'REVIEW'
    print(f'[{status}] {label}: {value}')
    if status == 'REVIEW':
        print(f'       Note: {note}')
"
```

---

## 2. Cookie Attribute Inspection

### Browser DevTools Method

1. Open the application and log in
2. Open DevTools (F12) → Application tab → Storage → Cookies → select your domain
3. For each session cookie, verify:

| Attribute | Target | Why |
|---|---|---|
| `Secure` | checked | Prevents transmission over HTTP |
| `HttpOnly` | checked | Blocks `document.cookie` XSS access |
| `SameSite` | Strict or Lax | Prevents CSRF token riding |
| `Name prefix` | `__Host-` or `__Secure-` | Origin binding, prevents subdomain injection |
| `Max-Age` | absent (session) or short | Persistent cookies = longer theft window |

### Burp Suite Method

```
1. Proxy → HTTP History → find authenticated request
2. Right-click → Send to Repeater
3. Inspect Response headers → Set-Cookie:
4. Document missing attributes
```

### curl inspection

```bash
TARGET_URL="https://your-app.example.com/login"
# Submit credentials and capture Set-Cookie response headers
curl -s -c /tmp/cookies.txt -D - -X POST "${TARGET_URL}" \
  -d "username=testuser&password=testpass" \
  | grep -i "Set-Cookie"

# Expected output for hardened app:
# Set-Cookie: session=<token>; Path=/; HttpOnly; Secure; SameSite=Strict
# Missing any of those flags = finding
```

---

## 3. JWT Validation

### Manual decode

```bash
# Capture a JWT from an authenticated request
# Paste to jwt.io or decode manually:
JWT="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."

# Decode header and payload (no signature validation — for inspection only)
echo "$JWT" | cut -d'.' -f1 | base64 -d 2>/dev/null | python3 -m json.tool
echo "$JWT" | cut -d'.' -f2 | base64 -d 2>/dev/null | python3 -m json.tool
```

### What to check

```bash
JWT_PAYLOAD=$(echo "$JWT" | cut -d'.' -f2 | base64 -d 2>/dev/null)
echo "$JWT_PAYLOAD" | python3 -c "
import json, sys, datetime
d = json.load(sys.stdin)
now = datetime.datetime.now().timestamp()

checks = {
    'alg (in header - check separately)': 'RS256 or ES256',
    'exp present': d.get('exp') is not None,
    'iat present': d.get('iat') is not None,
    'jti present (for revocation)': d.get('jti') is not None,
    'aud present (audience binding)': d.get('aud') is not None,
    'sub present (subject)': d.get('sub') is not None,
}

if d.get('exp'):
    exp_dt = datetime.datetime.fromtimestamp(d['exp'])
    iat_dt = datetime.datetime.fromtimestamp(d['iat']) if d.get('iat') else None
    lifetime_min = (d['exp'] - d.get('iat', now)) / 60
    checks[f'exp time'] = f'{exp_dt} (lifetime: {lifetime_min:.0f} min)'
    if lifetime_min > 60:
        checks['WARN: access token >60min'] = f'{lifetime_min:.0f}min — should be ≤15min'

for check, value in checks.items():
    print(f'  {check}: {value}')
print()
print('Raw claims:')
for k, v in d.items():
    print(f'  {k}: {v}')
"
```

### JWT Algorithm Check (Critical)

```bash
# Decode header specifically to check algorithm
JWT_HEADER=$(echo "$JWT" | cut -d'.' -f1 | base64 -d 2>/dev/null)
ALG=$(echo "$JWT_HEADER" | python3 -c "import json,sys; print(json.load(sys.stdin).get('alg','unknown'))")
echo "Algorithm: ${ALG}"

case "$ALG" in
    RS256|RS384|RS512|ES256|ES384|ES512|PS256|PS384|PS512)
        echo "PASS: Asymmetric algorithm — public key validation, no secret to steal"
        ;;
    HS256|HS384|HS512)
        echo "WARN: Symmetric algorithm — both sides share the same secret. Acceptable if secret is strong (32+ bytes random), but RS256 preferred."
        ;;
    none|"")
        echo "CRITICAL: alg=none — signature not verified. Any unsigned token accepted. Immediate finding."
        ;;
    *)
        echo "UNKNOWN: Algorithm ${ALG} — investigate"
        ;;
esac
```

---

## 4. Refresh Token Rotation Check

Refresh token rotation: when you exchange a refresh token for a new access token, the old refresh token is invalidated and a new one is issued. If the old token is replayed, the entire token family should be revoked (reuse detection).

### Test with Keycloak

```bash
KC_URL="${KEYCLOAK_URL:-http://localhost:8080}"
KC_REALM="${KEYCLOAK_REALM:-master}"
KC_CLIENT="your-client-id"
KC_CLIENT_SECRET="your-client-secret"

# Step 1: Get initial tokens
TOKENS=$(curl -s -X POST \
  "${KC_URL}/realms/${KC_REALM}/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=${KC_CLIENT}&client_secret=${KC_CLIENT_SECRET}&grant_type=password&username=testuser&password=testpass&scope=openid")

REFRESH_TOKEN_1=$(echo "$TOKENS" | python3 -c "import json,sys; print(json.load(sys.stdin)['refresh_token'])")
echo "Obtained refresh_token_1"

# Step 2: Use refresh token — get new tokens
TOKENS_2=$(curl -s -X POST \
  "${KC_URL}/realms/${KC_REALM}/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=${KC_CLIENT}&client_secret=${KC_CLIENT_SECRET}&grant_type=refresh_token&refresh_token=${REFRESH_TOKEN_1}")

REFRESH_TOKEN_2=$(echo "$TOKENS_2" | python3 -c "import json,sys; print(json.load(sys.stdin).get('refresh_token','ERROR'))")
echo "Got refresh_token_2: ${REFRESH_TOKEN_2:0:20}..."

# Check rotation: refresh_token_2 should differ from refresh_token_1
if [[ "$REFRESH_TOKEN_1" == "$REFRESH_TOKEN_2" ]]; then
    echo "FAIL: Refresh tokens not rotating — same token returned on exchange"
else
    echo "PASS: Refresh tokens rotated"
fi

# Step 3: Replay the ORIGINAL refresh token (should fail with rotation enabled)
REPLAY_RESPONSE=$(curl -s -X POST \
  "${KC_URL}/realms/${KC_REALM}/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=${KC_CLIENT}&client_secret=${KC_CLIENT_SECRET}&grant_type=refresh_token&refresh_token=${REFRESH_TOKEN_1}")

ERROR=$(echo "$REPLAY_RESPONSE" | python3 -c "import json,sys; print(json.load(sys.stdin).get('error','none'))" 2>/dev/null)
if [[ "$ERROR" == "invalid_grant" ]]; then
    echo "PASS: Replayed refresh token correctly rejected (reuse detection working)"
else
    echo "FAIL: Replayed refresh token accepted — reuse detection NOT working"
fi
```

---

## Output

Document in `evidence/`:

| Artifact | Command | Filename |
|---|---|---|
| Keycloak realm config | `curl .../admin/realms/<realm>` | `keycloak-realm-settings.json` |
| Cookie attributes | Browser DevTools screenshot | `cookie-attributes.png` |
| JWT header + payload | `echo $JWT \| cut -d'.' -f1-2` | `jwt-decoded.txt` |
| Refresh token rotation test | Test output above | `refresh-token-rotation-test.txt` |

Feed findings into:
- Session timeout gaps: `02a-fix-AC12-session.md`
- Cookie attribute gaps: address in application code review (L7)
- JWT alg issue: application-level fix + `02b-fix-IA2-mfa.md` for auth platform settings
