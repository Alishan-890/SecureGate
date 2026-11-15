import os
import re
import sqlite3
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

from app import DatabaseError, app, init_db
from werkzeug.security import generate_password_hash


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

    def test_register_commit_then_login_and_access_dashboard(self):
        username = "new_registered_user"
        password = "NewRegistered@123"
        token = self.csrf("/register")
        registered = self.client.post(
            "/register",
            data={"username": username, "password": password, "csrf_token": token},
        )
        self.assertEqual(registered.status_code, 302)
        db = sqlite3.connect(app.config["DATABASE"])
        self.assertIsNotNone(
            db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        )
        db.close()
        login = self.login(username, password)
        self.assertEqual(login.status_code, 302)
        self.assertEqual(self.client.get("/dashboard").status_code, 200)

    def test_existing_schema_is_upgraded_and_registration_still_works(self):
        self.database.unlink()
        old_schema = sqlite3.connect(self.database)
        old_schema.executescript(
            """
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user',
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                locked_until TEXT,
                created_at TEXT NOT NULL,
                is_blocked INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE products (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                category TEXT NOT NULL,
                description TEXT NOT NULL,
                price REAL NOT NULL
            );
            CREATE TABLE security_tests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                test_name TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Pending',
                result TEXT,
                details TEXT,
                created_at TEXT NOT NULL
            );
            CREATE TABLE feedback (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                message TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE security_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                username TEXT,
                event TEXT NOT NULL,
                result TEXT NOT NULL,
                ip_address TEXT,
                created_at TEXT NOT NULL
            );
            CREATE TABLE login_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                success INTEGER NOT NULL,
                ip_address TEXT,
                login_at TEXT NOT NULL
            );
            INSERT INTO security_tests (user_id, test_name, status, created_at)
            VALUES (1, 'Legacy test', 'Pending', '2026-01-01T00:00:00+00:00');
            """
        )
        old_schema.commit()
        old_schema.close()
        init_db()
        db = sqlite3.connect(self.database)
        user_columns = {row[1] for row in db.execute("PRAGMA table_info(users)")}
        product_columns = {row[1] for row in db.execute("PRAGMA table_info(products)")}
        status = db.execute("SELECT status FROM security_tests").fetchone()[0]
        db.close()
        self.assertIn("last_login", user_columns)
        self.assertIn("status", product_columns)
        self.assertEqual(status, "Not Run")

    def test_healthz_reports_only_safe_diagnostics(self):
        response = self.client.get("/healthz")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["db"], "ok")
        self.assertTrue(payload["schema_ok"])
        self.assertNotIn(b"password", response.data.lower())
        self.assertNotIn(b"postgresql://", response.data.lower())

    def test_healthz_detailed_error_requires_token(self):
        app.extensions.pop("securegate_database_ready", None)
        original_token = os.environ.get("HEALTHZ_TOKEN")
        os.environ["HEALTHZ_TOKEN"] = "test-health-token"
        try:
            with patch("app.init_db", side_effect=DatabaseError("password=secret")):
                hidden = self.client.get("/healthz")
                detailed = self.client.get("/healthz?token=test-health-token")
            self.assertNotIn(b"db_error_message", hidden.data)
            self.assertIn(b"db_error_message", detailed.data)
            self.assertNotIn(b"password=secret", detailed.data)
            self.assertIn(b"DatabaseError", detailed.data)
        finally:
            if original_token is None:
                os.environ.pop("HEALTHZ_TOKEN", None)
            else:
                os.environ["HEALTHZ_TOKEN"] = original_token

    def test_duplicate_username_has_friendly_error(self):
        token = self.csrf("/register")
        self.client.post(
            "/register",
            data={
                "username": "duplicate_user",
                "password": "Duplicate@123",
                "csrf_token": token,
            },
        )
        token = self.csrf("/register")
        response = self.client.post(
            "/register",
            data={
                "username": "duplicate_user",
                "password": "Duplicate@123",
                "csrf_token": token,
            },
            follow_redirects=True,
        )
        self.assertIn(b"Username already taken", response.data)

    def test_wrong_password_is_recorded_as_boolean_failure(self):
        response = self.login("student", "WrongPassword@123")
        self.assertEqual(response.status_code, 200)
        db = sqlite3.connect(app.config["DATABASE"])
        result = db.execute(
            "SELECT success FROM login_history WHERE user_id = "
            "(SELECT id FROM users WHERE username = 'student') ORDER BY id DESC LIMIT 1"
        ).fetchone()[0]
        db.close()
        self.assertEqual(result, 0)

    def test_invalid_session_user_id_redirects_without_crashing(self):
        with self.client.session_transaction() as session:
            session["_user_id"] = "999999"
            session["_fresh"] = True
        response = self.client.get("/dashboard")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.headers["Location"])

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
        self.assertIn(b"Not Run", pending.data)
        self.assertNotIn(b"PASSED", pending.data)
        dashboard = self.client.get("/dashboard")
        self.assertIn(b"Recent security events", dashboard.data)
        self.assertIn(b"Last login:", dashboard.data)
        self.assertRegex(history.data.decode(), r"\d{2} [A-Z][a-z]{2} \d{4}, \d{2}:\d{2} [AP]M PKT")
        self.assertEqual(self.client.get("/audit").status_code, 200)

    def test_history_and_audit_are_isolated_by_user_id(self):
        db = sqlite3.connect(app.config["DATABASE"])
        db.execute(
            "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, 'user', ?)",
            ("other_user", generate_password_hash("OtherUser@123"), "2026-11-15T12:00:00+05:00"),
        )
        other_id = db.execute(
            "SELECT id FROM users WHERE username = 'other_user'"
        ).fetchone()[0]
        db.execute(
            "INSERT INTO login_history (user_id, success, ip_address, login_at) VALUES (?, ?, ?, ?)",
            (other_id, True, "127.0.0.2", "2026-11-15T12:01:00+05:00"),
        )
        db.execute(
            "INSERT INTO security_logs (user_id, username, event, result, created_at) VALUES (?, ?, ?, ?, ?)",
            (other_id, "other_user", "Other user secret action", "SUCCESS", "2026-11-15T12:01:00+05:00"),
        )
        db.commit()
        db.close()
        self.login()
        self.assertNotIn(b"Other user secret action", self.client.get("/audit").data)
        self.assertEqual(self.client.get("/login-history").data.count(b"127.0.0.2"), 0)

    def test_dashboard_redirects_when_stale_session_has_no_database_schema(self):
        self.database.unlink()
        app.config["DATABASE"] = str(self.database)
        with self.client.session_transaction() as session:
            session["_user_id"] = "1"
            session["_fresh"] = True
        response = self.client.get("/dashboard")
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.headers["Location"].startswith("/login"))

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

    def test_login_history_success_values_are_recorded(self):
        self.login()
        db = sqlite3.connect(app.config["DATABASE"])
        values = [row[0] for row in db.execute("SELECT success FROM login_history").fetchall()]
        db.close()
        self.assertIn(1, values)
        self.assertTrue(all(value in (0, 1) for value in values))

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
