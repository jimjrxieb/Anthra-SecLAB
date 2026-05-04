# SC-23 Session Fixation — Break

## Scenario: Session ID Survives Authentication Boundary

A session ID assigned to an unauthenticated visitor persists through the login process. The same session identifier that was issued before authentication continues to be used after the user logs in. An attacker who knows (or sets) the pre-authentication session ID can hijack the authenticated session.

## What This Simulates

- Session fixation attack (CWE-384)
- Failure to regenerate session ID on authentication state change
- Gap between "a session exists" and "a session is authenticated"
- OWASP Testing Guide: OTG-SESS-003 (Testing for Session Fixation)

## Attack Flow

```
1. Attacker visits the application → receives session ID: abc123
2. Attacker sends the victim a crafted link with that session ID:
   https://app.example.com/login?session_id=abc123
   (or sets the cookie via XSS, meta tag injection, or subdomain cookie)
3. Victim clicks the link → browser stores session ID abc123
4. Victim logs in with valid credentials
5. Application authenticates the user but keeps session ID abc123
6. Attacker uses session ID abc123 → now has the victim's authenticated session
```

## Vulnerable Code Pattern

The vulnerability exists when the application does NOT call session regeneration on login:

```python
# VULNERABLE: Session ID survives authentication
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    if verify_credentials(username, password):
        session['user'] = username        # Stores user in existing session
        session['authenticated'] = True   # Same session ID as before login
        return redirect('/dashboard')
    return redirect('/login')
```

Compare with the secure pattern:

```python
# SECURE: Session regenerated on authentication
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    if verify_credentials(username, password):
        old_data = dict(session)          # Preserve non-auth data if needed
        session.clear()                   # Destroy old session
        session.regenerate()              # New session ID issued
        session['user'] = username        # Store in NEW session
        session['authenticated'] = True
        return redirect('/dashboard')
    return redirect('/login')
```

## What Breaks

- **SC-23 (Session Authenticity)** — session token does not represent authentic user state; it was set by the attacker
- **AC-12 (Session Termination)** — the pre-authentication session should terminate at the authentication boundary
- **IA-2 (Identification and Authentication)** — authentication event does not create a new trust anchor

## Frameworks Affected

| Framework | Standard | Requirement |
|-----------|----------|-------------|
| OWASP | ASVS 3.7.1 | Verify the application generates a new session token on authentication |
| OWASP | Top 10 A07:2021 | Identification and Authentication Failures |
| NIST | SP 800-53 SC-23 | Session Authenticity — protect against session hijacking |
| PCI-DSS | 6.2.4 | Software engineering techniques to prevent common attacks |
| CWE | CWE-384 | Session Fixation |

## Real-World Examples

- **2012:** Session fixation in WordPress allowed attackers to hijack admin sessions via crafted login URLs. Affected millions of installations before patch.
- **2014:** PayPal session fixation vulnerability (reported via bug bounty) allowed account takeover by setting session cookies before the victim authenticated.
- **2016:** Uber session fixation in partner portal allowed attackers to access driver dashboards and trip data.
- Session fixation is OWASP's canonical example of "authentication does not equal authorization state" — the session must represent the current trust level, not the initial connection.

## Tabletop Exercise

1. Open the application in a browser — note the session cookie value (Developer Tools > Application > Cookies)
2. Copy the session cookie value
3. Open a second browser (or incognito window) and set the same session cookie manually
4. In the first browser, log in with valid credentials
5. In the second browser, refresh — check if you now have an authenticated session
6. If yes: the application is vulnerable to session fixation

## Detection Indicators

- Session cookie value is the same before and after login (compare in DevTools)
- No `Set-Cookie` header in the login response (session was not regenerated)
- Application accepts externally-set session IDs (e.g., via URL parameter or header injection)
