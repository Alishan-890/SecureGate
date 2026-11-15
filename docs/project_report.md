# SecureGate Group J Project Report

## Aim

SecureGate is an authorised educational platform for identifying, fixing, and
retesting common web application weaknesses: authentication errors, SQL
injection, XSS, CSRF, and access-control failures.

## Platform and methodology

The platform uses Flask, Flask-Login, Flask-WTF, Werkzeug password hashing,
direct psycopg3 access to Neon PostgreSQL, parameterized queries, Jinja
autoescaping, and server-side role checks. Testing follows this sequence:
normal operation, controlled failure or attack indicator, applied control,
successful retest, and stored evidence.

## Findings and fixes

| Finding | Impact | Applied fix | Retest/evidence |
|---|---|---|---|
| Weak or missing authentication controls | Credential disclosure and account abuse | Werkzeug hashes, lockout, session cookie controls, CSRF | Authentication test records |
| SQL injection input | Query integrity and data disclosure | Bound parameters for login and search | SQL injection test records |
| Stored/script markup input | Browser code execution | Validation, Jinja escaping, CSP | XSS test records |
| Unauthorised administrator/data access | Privilege escalation and IDOR | `admin_required` and user-ID query filters | Access-control test records |
| Missing audit evidence | Poor accountability | User-scoped audit logs and persisted findings | Evidence and reports pages |

## CIA and accountability mapping

Password hashing and user-scoped records protect confidentiality. Parameterized
queries, CSRF protection, escaping, and authorization protect integrity.
Lockout controls availability. Audit events, timestamps, findings, and retests
provide accountability. The in-app CIA Mapping page provides the complete
control list.

## Evidence and limitations

Evidence is synthetic test data only. OWASP ZAP reports remain in `evidence/`.
The local automated suite validates application behavior. Live authenticated
testing requires authorised credentials and working Vercel/Neon runtime access;
it must not be claimed from local tests.
