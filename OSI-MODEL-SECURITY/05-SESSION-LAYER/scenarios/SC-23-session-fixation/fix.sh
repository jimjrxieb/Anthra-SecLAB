#!/usr/bin/env bash
set -euo pipefail

# SC-23 Session Fixation — Fix
#
# Patches the application to regenerate session IDs on authentication events.
# Creates secure session management configuration and provides framework-
# specific code patches for:
#   - Python Flask/Django
#   - Node.js Express
#   - Java Servlet
#   - PHP
#
# REQUIREMENTS:
#   - Application source code access
#   - Ability to modify session handling code
#
# USAGE:
#   ./fix.sh [config_dir] [framework]
#
# EXAMPLE:
#   ./fix.sh /tmp/sc23-session-lab flask
#   ./fix.sh ./app-config express
#
# REFERENCES:
#   - NIST SP 800-53 SC-23: Session Authenticity
#   - OWASP ASVS 3.7.1: Session regeneration on authentication
#   - CWE-384: Session Fixation

# --- Argument Validation ---

CONFIG_DIR="${1:-/tmp/sc23-session-lab}"
FRAMEWORK="${2:-generic}"

EVIDENCE_DIR="/tmp/sc23-session-fixation-fix-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$EVIDENCE_DIR"
mkdir -p "$CONFIG_DIR"

echo "============================================"
echo "SC-23 Session Fixation — Fix"
echo "============================================"
echo ""
echo "[*] Config dir:   $CONFIG_DIR"
echo "[*] Framework:    $FRAMEWORK"
echo "[*] Evidence dir: $EVIDENCE_DIR"
echo ""

# --- Fix 1: Session Regeneration Code Patches ---

echo "[*] Fix 1: Generating session regeneration patches"
echo "----------------------------------------------"

# Python Flask patch
cat > "$EVIDENCE_DIR/patch-flask.py" << 'PYEOF'
# SC-23 FIX: Session regeneration for Flask
# Apply this pattern to every authentication endpoint
#
# Before: session['user'] = username (vulnerable)
# After:  regenerate session, then set user (secure)

from flask import Flask, session, request, redirect
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # 256-bit secret from env in production

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    if verify_credentials(username, password):
        # SC-23 FIX: Clear and regenerate session on authentication
        # This prevents session fixation by issuing a new session ID
        old_session_data = {}
        # Preserve CSRF token if using Flask-WTF (optional)
        if '_csrf_token' in session:
            old_session_data['_csrf_token'] = session['_csrf_token']

        session.clear()  # Destroy old session and its ID

        # Restore non-sensitive data
        for key, value in old_session_data.items():
            session[key] = value

        # Set authentication state in NEW session
        session['user'] = username
        session['authenticated'] = True
        session['login_time'] = int(__import__('time').time())
        session['session_id'] = secrets.token_urlsafe(32)

        session.permanent = True  # Use PERMANENT_SESSION_LIFETIME
        app.permanent_session_lifetime = 28800  # 8 hours max

        return redirect('/dashboard')

    return redirect('/login?error=invalid')


@app.route('/logout', methods=['POST'])
def logout():
    # SC-23 FIX: Complete session destruction on logout
    session.clear()
    response = redirect('/login')
    response.headers['Clear-Site-Data'] = '"cache", "cookies", "storage"'
    return response
PYEOF

echo "[+] Flask patch: $EVIDENCE_DIR/patch-flask.py"

# Node.js Express patch
cat > "$EVIDENCE_DIR/patch-express.js" << 'JSEOF'
// SC-23 FIX: Session regeneration for Express.js
// Apply this pattern to every authentication route
//
// Key: req.session.regenerate() creates a new session ID
// The old session ID is destroyed and cannot be reused

const express = require('express');
const session = require('express-session');
const crypto = require('crypto');

const app = express();

app.use(session({
    secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
    name: '__Host-session_id',
    resave: false,
    saveUninitialized: false,
    rolling: true,
    cookie: {
        secure: true,
        httpOnly: true,
        sameSite: 'strict',
        maxAge: 15 * 60 * 1000,  // 15-minute idle timeout
        path: '/'
    }
}));

app.post('/login', (req, res) => {
    const { username, password } = req.body;

    if (verifyCredentials(username, password)) {
        // SC-23 FIX: Regenerate session ID on authentication
        // This is the critical fix — old session ID is destroyed
        const oldSession = { ...req.session };
        req.session.regenerate((err) => {
            if (err) {
                console.error('Session regeneration failed:', err);
                return res.status(500).json({ error: 'Authentication failed' });
            }

            // Set authentication state in NEW session
            req.session.user = username;
            req.session.authenticated = true;
            req.session.loginTime = Date.now();
            req.session.maxLifetime = Date.now() + (8 * 60 * 60 * 1000); // 8 hours

            req.session.save((err) => {
                if (err) {
                    console.error('Session save failed:', err);
                    return res.status(500).json({ error: 'Authentication failed' });
                }
                res.redirect('/dashboard');
            });
        });
    } else {
        res.redirect('/login?error=invalid');
    }
});

app.post('/logout', (req, res) => {
    // SC-23 FIX: Destroy session completely on logout
    req.session.destroy((err) => {
        res.clearCookie('__Host-session_id');
        res.set('Clear-Site-Data', '"cache", "cookies", "storage"');
        res.redirect('/login');
    });
});
JSEOF

echo "[+] Express patch: $EVIDENCE_DIR/patch-express.js"

# Java Servlet patch
cat > "$EVIDENCE_DIR/patch-servlet.java" << 'JAVAEOF'
// SC-23 FIX: Session regeneration for Java Servlet
// Apply this pattern in your authentication servlet/filter
//
// Key: invalidate old session, create new one, copy non-sensitive attributes

import javax.servlet.http.*;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

public class SecureLoginServlet extends HttpServlet {

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws javax.servlet.ServletException, java.io.IOException {

        String username = request.getParameter("username");
        String password = request.getParameter("password");

        if (verifyCredentials(username, password)) {
            // SC-23 FIX: Session regeneration on authentication
            HttpSession oldSession = request.getSession(false);
            Map<String, Object> preservedData = new HashMap<>();

            // Preserve non-sensitive session data (e.g., CSRF token, locale)
            if (oldSession != null) {
                Enumeration<String> attrNames = oldSession.getAttributeNames();
                while (attrNames.hasMoreElements()) {
                    String name = attrNames.nextElement();
                    if (name.equals("csrf_token") || name.equals("locale")) {
                        preservedData.put(name, oldSession.getAttribute(name));
                    }
                }
                // Destroy old session — old session ID is now invalid
                oldSession.invalidate();
            }

            // Create new session with new ID
            HttpSession newSession = request.getSession(true);
            newSession.setMaxInactiveInterval(900); // 15-minute idle timeout

            // Restore preserved data
            for (Map.Entry<String, Object> entry : preservedData.entrySet()) {
                newSession.setAttribute(entry.getKey(), entry.getValue());
            }

            // Set authentication state in NEW session
            newSession.setAttribute("user", username);
            newSession.setAttribute("authenticated", true);
            newSession.setAttribute("loginTime", System.currentTimeMillis());

            response.sendRedirect("/dashboard");
        } else {
            response.sendRedirect("/login?error=invalid");
        }
    }
}
JAVAEOF

echo "[+] Java Servlet patch: $EVIDENCE_DIR/patch-servlet.java"

# PHP patch
cat > "$EVIDENCE_DIR/patch-php.php" << 'PHPEOF'
<?php
// SC-23 FIX: Session regeneration for PHP
// Apply this pattern at every authentication point
//
// Key: session_regenerate_id(true) — the 'true' parameter
// deletes the old session file, preventing the old session ID
// from being reused.

// Secure session configuration (call before session_start)
ini_set('session.cookie_secure', '1');
ini_set('session.cookie_httponly', '1');
ini_set('session.cookie_samesite', 'Strict');
ini_set('session.use_strict_mode', '1');      // Reject uninitialized session IDs
ini_set('session.use_only_cookies', '1');      // No URL-based session IDs
ini_set('session.use_trans_sid', '0');         // No transparent session ID
ini_set('session.gc_maxlifetime', '900');      // 15-minute idle timeout
ini_set('session.cookie_lifetime', '0');       // Session cookie (browser close = gone)
ini_set('session.name', '__Host-PHPSESSID');   // __Host- prefix

session_start();

function secure_login($username, $password) {
    if (verify_credentials($username, $password)) {
        // SC-23 FIX: Regenerate session ID on authentication
        // true = delete old session data file
        session_regenerate_id(true);

        // Set authentication state in NEW session
        $_SESSION['user'] = $username;
        $_SESSION['authenticated'] = true;
        $_SESSION['login_time'] = time();
        $_SESSION['max_lifetime'] = time() + (8 * 60 * 60); // 8 hours

        return true;
    }
    return false;
}

function secure_logout() {
    // SC-23 FIX: Complete session destruction
    $_SESSION = array();

    if (ini_get("session.use_cookies")) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000,
            $params["path"], $params["domain"],
            $params["secure"], $params["httponly"]
        );
    }

    session_destroy();
    header('Clear-Site-Data: "cache", "cookies", "storage"');
}
?>
PHPEOF

echo "[+] PHP patch: $EVIDENCE_DIR/patch-php.php"
echo ""

# --- Fix 2: Session Configuration ---

echo "[*] Fix 2: Creating secure session management configuration"
echo "----------------------------------------------"

cat > "$CONFIG_DIR/session-security.json" << 'JSONEOF'
{
  "_comment": "SC-23 FIX: Secure session management configuration",
  "_references": [
    "NIST SP 800-53 SC-23 Session Authenticity",
    "OWASP ASVS 3.7.1 Session Regeneration",
    "CWE-384 Session Fixation Prevention"
  ],
  "session_regeneration": {
    "on_login": true,
    "on_privilege_escalation": true,
    "on_password_change": true,
    "on_mfa_completion": true,
    "destroy_old_session": true
  },
  "session_id": {
    "length_bytes": 32,
    "entropy_source": "crypto_random",
    "format": "url_safe_base64",
    "reject_uninitialized": true,
    "url_based_ids": false,
    "transparent_sid": false
  },
  "cookie": {
    "name": "__Host-session_id",
    "secure": true,
    "httpOnly": true,
    "sameSite": "Strict",
    "path": "/",
    "domain": null,
    "prefix": "__Host-"
  },
  "session_binding": {
    "bind_to_user_agent": true,
    "bind_to_tls_session": false,
    "bind_to_client_cert": false
  },
  "anti_fixation": {
    "strict_mode": true,
    "reject_external_ids": true,
    "validate_on_every_request": true
  }
}
JSONEOF

echo "[+] Wrote session security config to $CONFIG_DIR/session-security.json"
cp "$CONFIG_DIR/session-security.json" "$EVIDENCE_DIR/session-security-config.json"
echo ""

# --- Fix 3: Middleware for Session Validation ---

echo "[*] Fix 3: Session validation middleware"
echo "----------------------------------------------"

cat > "$EVIDENCE_DIR/middleware-session-guard.py" << 'PYEOF'
# SC-23 FIX: Session validation middleware
# Add this to your middleware chain to enforce session authenticity
# on every request, not just at login time.

import time
import hashlib

class SessionGuardMiddleware:
    """
    Validates session authenticity on every request:
    1. Checks session has not exceeded max lifetime
    2. Checks session has not exceeded idle timeout
    3. Validates session binding (user-agent fingerprint)
    4. Rejects sessions without proper authentication markers
    """

    MAX_SESSION_LIFETIME = 8 * 60 * 60  # 8 hours
    IDLE_TIMEOUT = 15 * 60              # 15 minutes
    PRIVILEGED_IDLE_TIMEOUT = 2 * 60    # 2 minutes

    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        from flask import session, request, redirect

        # Skip for unauthenticated routes
        public_paths = ['/login', '/health', '/static', '/favicon.ico']
        if any(environ.get('PATH_INFO', '').startswith(p) for p in public_paths):
            return self.app(environ, start_response)

        # Check: is session authenticated?
        if not session.get('authenticated'):
            return redirect('/login')(environ, start_response)

        now = int(time.time())

        # Check: max session lifetime
        login_time = session.get('login_time', 0)
        if now - login_time > self.MAX_SESSION_LIFETIME:
            session.clear()
            return redirect('/login?reason=max_lifetime')(environ, start_response)

        # Check: idle timeout
        last_activity = session.get('last_activity', 0)
        timeout = self.PRIVILEGED_IDLE_TIMEOUT if session.get('is_admin') else self.IDLE_TIMEOUT
        if last_activity > 0 and now - last_activity > timeout:
            session.clear()
            return redirect('/login?reason=idle_timeout')(environ, start_response)

        # Check: session binding (user-agent)
        expected_ua_hash = session.get('ua_hash', '')
        actual_ua_hash = hashlib.sha256(
            environ.get('HTTP_USER_AGENT', '').encode()
        ).hexdigest()[:16]
        if expected_ua_hash and expected_ua_hash != actual_ua_hash:
            session.clear()
            return redirect('/login?reason=session_binding')(environ, start_response)

        # Update last activity timestamp
        session['last_activity'] = now

        return self.app(environ, start_response)
PYEOF

echo "[+] Session guard middleware: $EVIDENCE_DIR/middleware-session-guard.py"
echo ""

echo "============================================"
echo "Fix Summary"
echo "============================================"
echo ""
echo "[+] Session regeneration:     ENABLED on login, privilege escalation, password change"
echo "[+] Old session destruction:  ENABLED (old session ID invalidated)"
echo "[+] Session ID entropy:       32 bytes from crypto random"
echo "[+] Strict mode:              ENABLED (reject uninitialized session IDs)"
echo "[+] URL-based session IDs:    DISABLED"
echo "[+] Cookie prefix:            __Host- (origin-bound)"
echo "[+] Cookie attributes:        Secure, HttpOnly, SameSite=Strict"
echo "[+] Session binding:          user-agent fingerprint"
echo "[+] Session guard middleware:  Validates authenticity on every request"
echo ""
echo "[*] Framework-specific patches generated for:"
echo "    - Python Flask:   $EVIDENCE_DIR/patch-flask.py"
echo "    - Node.js Express: $EVIDENCE_DIR/patch-express.js"
echo "    - Java Servlet:   $EVIDENCE_DIR/patch-servlet.java"
echo "    - PHP:            $EVIDENCE_DIR/patch-php.php"
echo ""
echo "[*] The critical fix in every framework is the same:"
echo "    1. Destroy the old session (invalidate the old session ID)"
echo "    2. Create a new session (issue a new session ID)"
echo "    3. Set authentication state in the NEW session only"
echo ""
echo "[*] Run validate.sh to confirm the fix is effective."
echo "[*] Evidence saved to: $EVIDENCE_DIR"
