# SecureGate Demonstration Guide

This guide uses synthetic data and the localhost-only SecureGate training application. Do not expose the application to a public network.

## 1. Exact presentation sequence

1. Start the server with `py app.py` and open `http://127.0.0.1:5000`.
2. Show the login page and the validation/help messages beneath the fields.
3. Sign in as `student` and show the dashboard metrics and visible testing-page navigation.
4. Open each testing page in this order: Authentication Testing, SQL Injection Testing, XSS Testing, Access Control Testing, and OWASP ZAP Results.
5. Demonstrate product search, feedback validation, Evidence, and Reports.
6. Demonstrate the normal-user denial response for `/admin/users`.
7. Sign out, sign in as `admin`, and show Users and Security Logs.
8. Run the tests below and capture the requested evidence screenshots.
9. Finish by showing the CSP response header and the final Reports page.

## 2. Credentials

| Account | Username | Password | Role |
|---|---|---|---|
| Student | `student` | `Student@123` | Normal user |
| Administrator | `admin` | `Admin@123` | Admin |

## 3. Normal-operation test

1. Sign in as `student`.
2. Open Dashboard, Product Search, Evidence, and Reports.
3. Search for `OWASP` and submit feedback such as `The controlled test completed successfully.`

**Expected result:** Login succeeds, dashboard metrics render, the OWASP product appears, feedback is stored and displayed as text, and each page returns normally.

## 4. Authentication and access-control test

1. Sign out and submit five incorrect passwords for `student`.
2. Submit the correct password during the lockout period.
3. Wait five minutes, or reset the local database only before a separate repeat demonstration.
4. Sign in as `student` and request `http://127.0.0.1:5000/admin/users`.
5. Sign out and sign in as `admin`; open Admin > Users and Admin > Security Logs.

**Expected result:** Failed attempts are logged, the account is temporarily locked after five failures, the normal user receives HTTP 403 for the admin page, and the admin can view both admin pages.

For the CSRF portion, open a form, copy no token, and submit a POST request with browser developer tools or the test suite. Repeat with an altered token.

**Expected result:** Both requests receive a clear HTTP 400 “Request blocked” page and a `CSRF validation / BLOCKED` event is written to Security Logs. A normal form submission containing its hidden token succeeds.

## 5. SQL injection protection demonstration

1. Sign in as `student` and open Product Search.
2. Search for `OWASP`.
3. Search for the synthetic string `' OR '1'='1`.
4. Open Admin > Security Logs as `admin`.

**Expected result:** The normal search returns the matching product. The injection-like string is treated as ordinary text and returns no unauthorized rows. The application remains responsive because the query uses PostgreSQL parameters.

## 6. XSS protection demonstration

1. Sign in as `student` and open Feedback.
2. Submit `<script>alert('demo')</script>`.
3. Submit `<b>safe text</b>` if you want to show escaped output.
4. Inspect the response headers in browser developer tools.

**Expected result:** Script markup is rejected with a visible validation message; no alert executes. Safe markup is rendered as escaped text, not HTML. The response includes a restrictive `Content-Security-Policy`, `X-Content-Type-Options: nosniff`, and `X-Frame-Options: DENY`.

## 7. OWASP ZAP scan instructions

1. Start SecureGate on `127.0.0.1:5000`.
2. Open OWASP ZAP and choose **Quick Start > Automated Scan**.
3. Set the target to `http://127.0.0.1:5000/login`.
4. Keep the scan inside localhost and use the default passive/baseline settings. Do not send POST requests without the displayed CSRF token if you manually configure authenticated crawling.
5. Review the Sites, Alerts, and Report tabs.
6. Do not scan any public host or attempt active exploitation.
7. Open SecureGate's OWASP ZAP Results page and record the synthetic result alongside the ZAP report.

**Expected result:** ZAP can crawl the local login page and report the response security headers. Anti-CSRF tokens, explicit CSP directives, local Bootstrap assets, SameSite/HttpOnly cookies, and reduced application headers should no longer produce the corresponding active findings. Authentication, session, and possible user-controllable attribute alerts may remain informational and should be recorded rather than suppressed. Any finding should be reviewed as a local teaching result; no public system is contacted.

## 8. Evidence screenshot checklist

- Login page with validation/help text.
- Student dashboard with all four metrics.
- Visible navigation strip containing all five security testing links.
- Authentication Testing page showing PASS results.
- SQL Injection Testing page and parameterized-search result.
- XSS rejection message and escaped feedback output.
- Access Control 403 page for the student account.
- Admin Users page for the admin account.
- Security Logs page with UTC timestamps and test events.
- Browser developer tools showing the CSP header.
- CSRF rejection page for a missing or invalid token, plus the corresponding Security Logs entry.
- Login response showing HttpOnly and SameSite=Lax cookie attributes.
- OWASP ZAP localhost target and baseline results.
- Evidence and Reports pages.

## 9. Expected results summary

| Test | Expected result |
|---|---|
| Normal operation | Student can use dashboard, search, feedback, evidence, and reports. |
| Registration validation | Invalid username/password receives a clear message; valid registration succeeds. |
| Authentication | Correct credentials log in; five failures trigger temporary lockout. |
| Access control | Normal users receive 403 for admin routes; admins can access them. |
| SQL injection | Injection-like input is handled as text and cannot broaden the result set. |
| XSS | Script input is blocked and displayed content is escaped. |
| CSRF | Valid token submissions succeed; missing or invalid tokens receive HTTP 400 and are logged. |
| CSP | Responses include a restrictive localhost-compatible CSP. |
| Cookies | Sessions use HttpOnly and SameSite=Lax; Secure is reserved for HTTPS mode. |
| Local assets | Bootstrap is served from the application and no cross-domain JavaScript is required. |
| Security logs | Authentication, search, feedback, and testing events include UTC timestamps and results. |
| OWASP ZAP | Localhost baseline scan completes without contacting public systems. |
