import re
import sqlite3
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from app import app, init_db


class SecureGateSecurityTests(unittest.TestCase):
    def setUp(self):
        self.database = Path(tempfile.mktemp(prefix="securegate-", suffix=".db"))
        app.config.update(TESTING=True, DATABASE=str(self.database), WTF_CSRF_ENABLED=True)
        init_db()
        self.client = app.test_client()

    def tearDown(self):
        if self.database.exists():
            self.database.unlink()

    def csrf(self, path):
        response = self.client.get(path)
        token = re.search(rb'name="csrf_token" value="([^"]+)"', response.data)
        self.assertIsNotNone(token, f"CSRF token missing from {path}")
        return token.group(1).decode()

    def login(self, username="student", password="Student@123"):
        token = self.csrf("/login")
        return self.client.post(
            "/login",
            data={"username": username, "password": password, "csrf_token": token},
        )

    def test_valid_csrf_submissions(self):
        token = self.csrf("/register")
        response = self.client.post(
            "/register",
            data={"username": "new_student", "password": "NewStudent@123", "csrf_token": token},
        )
        self.assertEqual(response.status_code, 302)

    def test_missing_and_invalid_csrf_are_rejected_and_logged(self):
        missing = self.client.post("/login", data={"username": "student", "password": "Student@123"})
        invalid = self.client.post(
            "/login",
            data={"username": "student", "password": "Student@123", "csrf_token": "invalid"},
        )
        self.assertEqual(missing.status_code, 400)
        self.assertEqual(invalid.status_code, 400)
        db = sqlite3.connect(app.config["DATABASE"])
        self.assertGreaterEqual(
            db.execute("SELECT COUNT(*) FROM security_logs WHERE event = 'CSRF validation'").fetchone()[0],
            2,
        )
        db.close()

    def test_cookie_flags(self):
        response = self.login()
        cookie = response.headers["Set-Cookie"]
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Lax", cookie)
        self.assertNotIn("Secure", cookie)

    def test_secure_cookie_mode_can_be_enabled_for_https(self):
        app.config["SESSION_COOKIE_SECURE"] = True
        try:
            response = self.login()
            self.assertIn("Secure", response.headers["Set-Cookie"])
        finally:
            app.config["SESSION_COOKIE_SECURE"] = False

    def test_security_headers_are_explicit_and_local(self):
        headers = self.client.get("/login").headers
        csp = headers["Content-Security-Policy"]
        for directive in (
            "default-src 'self'",
            "script-src 'self'",
            "style-src 'self'",
            "img-src 'self' data:",
            "font-src 'self'",
            "connect-src 'self'",
            "object-src 'none'",
            "base-uri 'self'",
            "frame-ancestors 'none'",
            "form-action 'self'",
        ):
            self.assertIn(directive, csp)
        self.assertNotIn("cdn.jsdelivr.net", csp)
        self.assertNotIn("Server", headers)

    def test_xss_and_sql_injection_handling(self):
        self.login()
        blocked = self.client.post(
            "/feedback",
            data={"message": "<script>alert(1)</script>", "csrf_token": self.csrf("/feedback")},
        )
        self.assertIn(b"Potentially unsafe markup was blocked.", blocked.data)
        escaped = self.client.post(
            "/feedback",
            data={"message": "<b>safe</b>", "csrf_token": self.csrf("/feedback")},
            follow_redirects=True,
        )
        self.assertIn(b"&lt;b&gt;safe&lt;/b&gt;", escaped.data)
        injection = self.client.get("/search?q=%27%20OR%20%271%27%3D%271")
        self.assertIn(b"No products matched", injection.data)

    def test_lockout_and_authorization(self):
        for _ in range(5):
            token = self.csrf("/login")
            self.client.post(
                "/login",
                data={"username": "student", "password": "wrong", "csrf_token": token},
            )
        token = self.csrf("/login")
        locked = self.client.post(
            "/login",
            data={"username": "student", "password": "Student@123", "csrf_token": token},
        )
        self.assertIn(b"temporarily locked", locked.data)
        self.client.get("/logout")
        self.login("admin", "Admin@123")
        self.assertEqual(self.client.get("/admin/users").status_code, 200)

    def test_user_cannot_access_admin(self):
        self.login()
        self.assertEqual(self.client.get("/admin/users").status_code, 403)

    def test_user_scoped_history_audit_and_pending_tests(self):
        self.login()
        history = self.client.get("/login-history")
        self.assertIn(b"Success", history.data)
        self.assertIn(b"Only your account activity is shown", history.data)
        pending = self.client.get("/testing/authentication")
        self.assertIn(b"Pending", pending.data)
        self.assertNotIn(b"PASSED", pending.data)
        dashboard = self.client.get("/dashboard")
        self.assertIn(b"Recent security events", dashboard.data)

    def test_admin_can_block_and_unblock_users(self):
        self.login("admin", "Admin@123")
        token = self.csrf("/admin/users")
        blocked = self.client.post(
            "/admin/users/2/block",
            data={"csrf_token": token},
            follow_redirects=True,
        )
        self.assertIn(b"student is now blocked", blocked.data)
        self.client.get("/logout")
        blocked_login = self.login()
        self.assertIn(b"account has been blocked", blocked_login.data)
        self.client.get("/logout")
        self.login("admin", "Admin@123")
        token = self.csrf("/admin/users")
        unblocked = self.client.post(
            "/admin/users/2/unblock",
            data={"csrf_token": token},
            follow_redirects=True,
        )
        self.assertIn(b"student is now unblocked", unblocked.data)

    def test_lockout_countdown_is_thirty_seconds(self):
        for _ in range(5):
            token = self.csrf("/login")
            self.client.post(
                "/login",
                data={"username": "student", "password": "wrong", "csrf_token": token},
            )
        token = self.csrf("/login")
        locked = self.client.post(
            "/login",
            data={"username": "student", "password": "Student@123", "csrf_token": token},
        )
        self.assertRegex(locked.data.decode(), r"Account temporarily locked\. Try again in \d+ seconds\.")
        db = sqlite3.connect(app.config["DATABASE"])
        lock_until = datetime.fromisoformat(
            db.execute("SELECT locked_until FROM users WHERE username = 'student'").fetchone()[0]
        )
        remaining = (lock_until - datetime.now(lock_until.tzinfo)).total_seconds()
        self.assertGreaterEqual(remaining, 28)
        self.assertLessEqual(remaining, 30)
        db.close()

    def test_security_evidence_and_report_fields_are_persisted(self):
        self.login()
        token = self.csrf("/testing/sql-injection")
        response = self.client.post(
            "/testing/sql-injection",
            data={"csrf_token": token},
            follow_redirects=True,
        )
        self.assertIn(b"Parameterized queries", response.data)
        self.assertIn(b"PASS", response.data)
        report = self.client.get("/reports")
        for label in (b"Finding", b"Impact", b"Evidence", b"Applied fix", b"Retest result", b"PKT"):
            self.assertIn(label, report.data)

    def test_admin_reset_clears_operational_data_but_preserves_users(self):
        self.login("admin", "Admin@123")
        token = self.csrf("/admin/users")
        response = self.client.post(
            "/admin/reset/dashboard",
            data={"csrf_token": token},
            follow_redirects=True,
        )
        self.assertIn(b"Clear Dashboard Data completed", response.data)
        db = sqlite3.connect(app.config["DATABASE"])
        self.assertEqual(db.execute("SELECT COUNT(*) FROM users").fetchone()[0], 2)
        self.assertEqual(db.execute("SELECT COUNT(*) FROM feedback").fetchone()[0], 0)
        self.assertEqual(
            db.execute(
                "SELECT COUNT(*) FROM security_logs WHERE event LIKE 'Admin reset:%'"
            ).fetchone()[0],
            1,
        )
        db.close()


if __name__ == "__main__":
    unittest.main()
