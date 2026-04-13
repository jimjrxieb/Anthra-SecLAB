# L7-01 PR.AA-05 — Remediate: Why and How

**CSF:** PROTECT / PR.AA-05 — Access permissions managed
**CIS v8:** 3.3 — Configure Data Access Control Lists
**NIST 800-53:** AC-3 — Access Enforcement

---

## Why This Fix Is Required

### CIS Controls v8 — Control 3.3

> "Configure data access control lists based on a user's need to know. Apply
> data access control lists, also known as access permissions, to local and
> remote file systems, databases, and applications."

The API schema (`/openapi.json`) is data about the system. It describes every
route, every parameter, and every response type. There is no business requirement
for unauthenticated users to read it in a production environment. CIS 3.3 requires
that access be granted based on need-to-know — and anonymous users have no need
to know the internal structure of a production API.

### NIST 800-53 Rev 5 — AC-3 Access Enforcement

> "Enforce approved authorizations for logical access to information and system
> resources in accordance with applicable access control policies."

The access control policy for a production API is: authenticated users access
business endpoints; nobody accesses internal tooling endpoints without justification.
Documentation endpoints are internal tooling. They were never explicitly authorized
for anonymous access — they were simply never turned off.

AC-3 requires the system to enforce approved authorizations. A default that was
never reviewed is not an approved authorization. It is a gap.

### CSF PR.AA-05

Access permissions must be actively managed. A default that enables full API
schema exposure without authentication is an unmanaged permission. It may have
existed since the application was first deployed. That does not make it approved.

---

## The Two Fixes

### Fix 1 — Environment Variable (Applied by fix.sh, D-rank)

`fix.sh` sets `DISABLE_DOCS=true` on the deployment. The application reads this
variable at startup and conditionally disables the documentation endpoints.

This is the correct D-rank response: deterministic, reversible, immediate, and
does not require a code merge or CI pipeline run. It works well in a lab and in
production emergencies.

**Limitation:** It depends on the application code checking the variable correctly.
If the code does not handle `DISABLE_DOCS`, this fix does nothing. Verify with
`verify.sh` after applying.

### Fix 2 — Code Change (Permanent, Required for Production)

The correct long-term fix is in the FastAPI application constructor. This removes
the dependency on the environment variable and makes the secure state the default.

**Before (vulnerable — default FastAPI behavior):**

```python
from fastapi import FastAPI

app = FastAPI(
    title="Portfolio API",
    version="1.0.0",
)
```

**After (hardened — explicit disable):**

```python
import os
from fastapi import FastAPI

# Disable documentation endpoints in all environments unless explicitly enabled.
# CIS v8 3.3: deny by default.
# NIST AC-3: only approved authorizations.
_DOCS_ENABLED = os.getenv("ENABLE_DOCS", "false").lower() == "true"

app = FastAPI(
    title="Portfolio API",
    version="1.0.0",
    docs_url="/docs" if _DOCS_ENABLED else None,
    redoc_url="/redoc" if _DOCS_ENABLED else None,
    openapi_url="/openapi.json" if _DOCS_ENABLED else None,
)
```

**Key design decision:** The default is closed. Documentation is only enabled if
`ENABLE_DOCS=true` is explicitly set. This is the opposite of the original — it
follows CIS 4.8 (uninstall or disable unnecessary services) by making "off" the
default, not "on".

This code change belongs in the main application repository and goes through the
normal PR and CI process. It is not a hotfix — it is a secure default that should
have been set when the application was first created.

---

## Why Disabling Is Better Than Adding Auth to /docs

A common response to this finding is to add authentication to the `/docs` endpoint
rather than disabling it. The reasoning: "developers need it, so let's protect it
rather than remove it."

This reasoning is flawed for two reasons:

**1. CIS 4.8 — Uninstall or Disable Unnecessary Services**

The principle is: if you don't need it in production, remove it. Every enabled
endpoint is an attack surface. Protecting `/docs` with authentication means the
authentication layer becomes an attack surface too. If the auth is misconfigured,
the docs are still exposed. If credentials are leaked, the docs are exposed. The
only way to guarantee that an endpoint cannot be abused is to not have it.

**2. Developers don't need /docs in production**

Documentation endpoints are development tools. Developers run the application
locally or in a dev environment where `ENABLE_DOCS=true`. They do not need to hit
production `/docs` to do their jobs. If they do, that is a process problem — not
a reason to keep a security gap open.

The right split:

| Environment | ENABLE_DOCS | Why                                           |
|-------------|-------------|-----------------------------------------------|
| local       | true        | Developers iterate against live schema        |
| dev         | true        | Integration testing, API exploration          |
| staging     | false       | Matches production behavior, avoid false gaps |
| production  | false       | No business need, reduce attack surface       |

---

## Acceptance Criteria

The fix is complete when:

1. `verify.sh` shows `/docs` returning 404
2. `verify.sh` shows `/redoc` returning 404
3. `verify.sh` shows `/openapi.json` returning 404
4. `verify.sh` shows `/health` still returning 200
5. A code change PR exists (or is tracked in POA&M) to make the disable permanent in code

---

## NEXT STEP: Run `verify.sh`
