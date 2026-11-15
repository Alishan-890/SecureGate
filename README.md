# SecureGate

**SecureGate: Web Application Security Testing and Secure Coding Platform** is a Flask, PostgreSQL, Flask-Login, Werkzeug password hashing, HTML, CSS, and Bootstrap application.

## Run locally with Neon PostgreSQL

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
py -m pip install -r requirements.txt
 $env:DATABASE_URL = "postgresql://user:password@host/dbname?sslmode=require"
 $env:SECRET_KEY = "replace-with-a-long-random-secret"
py app.py
```

Open `http://127.0.0.1:5000`. The application creates the PostgreSQL schema from [migrations/001_initial.sql](migrations/001_initial.sql) on startup.

Run the security regression suite with:

```powershell
py -m unittest discover -s tests -v
```

Test-only sample accounts (created when `TESTING=True`):

| Username | Password | Role |
|---|---|---|
| `admin` | `Admin@123` | Administrator |
| `student` | `Student@123` | Normal user |

Production requires `DATABASE_URL` and `SECRET_KEY`. Neon PostgreSQL is the supported production database. The application does not include public exploit endpoints.

To migrate an existing development SQLite database once:

```powershell
py scripts\migrate_sqlite_to_postgres.py
```

## Security controls demonstrated

- Werkzeug password hashing and Flask-Login sessions.
- Flask-WTF CSRF protection on every POST form with a clear logged 400 response for rejected requests.
- Server-side registration validation and role-based admin routes.
- Five failed logins trigger a 30-second temporary lockout with a countdown.
- Parameterized PostgreSQL product searches.
- Feedback length/content validation, Jinja autoescaping, and a restrictive Content Security Policy.
- Explicit CSP directives for scripts, styles, images, fonts, connections, objects, frames, base URIs, and form actions.
- HttpOnly, SameSite=Lax session cookies. Secure cookies are enabled for Vercel HTTPS deployments and when `SECUREGATE_HTTPS=1` is set.
- Bootstrap assets are served locally from `static/`, with no cross-domain JavaScript dependency.
- Consistent Pakistan Standard Time timestamps (`YYYY-MM-DD HH:MM:SS PKT`) for login history, feedback, tests, reports, evidence, and security logs.
- Five consecutive incorrect passwords lock an account for 30 seconds and show a live remaining-seconds message.
- Database-backed dashboard metrics, user-scoped audit/login history, and persisted security-test results.
- Pending security tests that are marked PASS or FAIL only after execution, with findings, impact, evidence, applied controls, and retest results.
- CSRF-protected administrator block/unblock actions with immediate database updates.
- Security response headers including `X-Frame-Options` and `X-Content-Type-Options`.

The application removes a `Server` response header when the Flask response layer controls it. Flask's built-in development server may add its own identifying header at the WSGI server layer; use a production WSGI server and reverse proxy configuration to control that header in deployment.

## OWASP ZAP remediation status

The localhost scan findings are addressed as follows:

- **Absence of Anti-CSRF Tokens:** Flask-WTF tokens are present in login, registration, and feedback POST forms.
- **CSP directive fallback warning:** The CSP now explicitly defines all requested directives.
- **Subresource Integrity / cross-domain JavaScript:** Bootstrap CSS and JavaScript are served locally.
- **Cookie without SameSite:** Session cookies use `SameSite=Lax` and `HttpOnly`.
- **Server version exposure:** The application removes the header where Flask can control it; the development-server limitation is documented above.
- **Authentication/session informational alerts:** These are expected behavior for a login/session platform and are documented findings, not suppressed controls.
- **User-controllable HTML attribute potential XSS:** Jinja autoescaping, input validation, and CSP remain enabled.

## Vercel deployment

The Vercel entry point is [api/index.py](api/index.py), configured by [vercel.json](vercel.json).

1. Import the project into Vercel.
2. Add `DATABASE_URL` using the Neon pooled or direct connection string with `sslmode=require`.
3. Add a long random `SECRET_KEY`.
4. Optionally add `INITIAL_ADMIN_USERNAME` and `INITIAL_ADMIN_PASSWORD` for first-deploy administrator provisioning.
5. Deploy. The Vercel cold-start entry point applies the PostgreSQL migration before serving requests. Production databases are not seeded with demo users or sample products.

## Pages

Authentication, SQL injection, XSS, access-control, OWASP ZAP results, evidence, reports, product search, feedback, login history, and administrator logs/users are available from the dashboard. Normal users only see their own audit and login records; administrators can review system-wide logs. This is a controlled teaching platform; it should not be exposed to the public internet.
