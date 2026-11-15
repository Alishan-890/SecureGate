# SecureGate Group J Demo Guide

1. **Setup:** configure `DATABASE_URL`, `SECRET_KEY`, and
   `HEALTHZ_TOKEN`; install `requirements.txt`; run the Flask application.
2. **Test attacks:** create a test account, run the authentication, SQL
   injection, XSS, CSRF, and access-control modules with synthetic payloads.
3. **Record findings:** review each finding, impact, evidence, and applied
   control in the Evidence page.
4. **Apply fixes:** demonstrate parameterized queries, validation, escaping,
   CSRF tokens, lockout, and administrator role checks.
5. **Retest:** use the Run button again and confirm PASS/FAIL and execution
   time are stored. Use `/validation` for the four-stage minimum workflow.
6. **Deliver:** export `/reports.csv`, review the CIA Mapping page, and include
   the report, test output, source code, and ZAP evidence.

Use only authorised local or deployment environments and synthetic data. Never
use real passwords or personal information.
