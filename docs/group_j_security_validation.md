# Group J Security Validation

## Aim and scope

SecureGate is a controlled teaching application for identifying, remediating,
and retesting authentication, injection, cross-site scripting, CSRF, and access
control weaknesses. Testing must be performed only against the local test
instance or the authorised Vercel deployment.

The application stores each executed check in `security_tests` with:

- finding and impact;
- evidence and applied control;
- retest result and PASS/FAIL result;
- execution timestamp in Pakistan Standard Time.

The `/evidence` and `/reports` pages provide the persisted evidence trail.

## Group J validation workflow

For each test, record the following sequence:

1. Normal operation.
2. Controlled failure or attack indicator.
3. Finding and impact.
4. Applied security control.
5. Successful retest.
6. Evidence stored in PostgreSQL.

Execute the relevant test page from the dashboard, then confirm the result in
`/evidence` and `/reports`. Tests start as `Not Run`; they are not marked PASS
until the execution form is submitted.

## Approved test cases and controls

| Test | Controlled indicator | Applied control | Expected retest |
|---|---|---|---|
| Authentication | Inspect stored credentials and session settings | Werkzeug password hashing, HttpOnly/SameSite cookies, lockout, Flask-Login | PASS when hashes, cookie controls, and role boundaries are present |
| SQL injection | `' OR '1'='1`, `UNION SELECT`, and SQL-comment payloads | Bound query parameters through the database adapter | Payloads are treated as data and do not broaden results |
| XSS | `<script>alert('XSS')</script>` and `javascript:` input | Server-side validation, Jinja autoescaping, and CSP | Markup is blocked or rendered as escaped text |
| CSRF | Missing and invalid form tokens | Global Flask-WTF CSRF protection | Requests return HTTP 400 and are logged |
| Access control | Normal user requests an administrator endpoint | Flask-Login plus `admin_required` | Normal users receive HTTP 403; admins can access |
| OWASP ZAP | Imported baseline/retest report | Stored report parsing and risk summary | Alert count, highest risk, and scan availability are displayed |

## Security properties

- **Confidentiality:** user-scoped feedback, login history, audit records, and
  security evidence prevent normal users from viewing other users' records.
- **Integrity:** CSRF tokens, parameterized queries, validation, and role checks
  prevent unauthorized state changes.
- **Availability:** database failures are logged and handled as controlled
  errors; brute-force attempts trigger a 30-second account lockout.
- **Accountability:** login attempts, audit events, findings, controls, retests,
  timestamps, and administrator resets are persisted.

## Local verification

From the project root:

```powershell
py -m unittest discover -s tests -v
py -m py_compile app.py db.py api\index.py
```

The regression suite covers CSRF rejection, password lockout, XSS handling,
SQL injection handling, role authorization, user-scoped records, evidence,
reports, administrator block/unblock, reset behavior, and stale-session
recovery.

## Vercel/Neon verification

Configure `DATABASE_URL` (or a supported Neon alias), `SECRET_KEY`, and
optionally the initial administrator variables in the Vercel environment.
Confirm the first request returns successfully, then execute each dashboard
test and verify the corresponding rows in `/reports` and `/evidence`.

Do not claim live deployment verification without the deployment URL and
runtime logs. The local automated suite verifies application behavior; the
live evidence must be captured from the authorized Vercel deployment.
