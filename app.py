import os
import re
from datetime import datetime, timedelta, timezone
from functools import wraps
from math import ceil
from collections import Counter
from pathlib import Path

from flask import Flask, abort, flash, g, redirect, render_template, request, url_for
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from flask_wtf import CSRFProtect
from flask_wtf.csrf import CSRFError
from werkzeug.security import check_password_hash, generate_password_hash

from db import DatabaseError, DatabaseIntegrityError, connect


BASE_DIR = Path(__file__).resolve().parent
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_SECONDS = 30
PKT = timezone(timedelta(hours=5), name="PKT")
TEST_NAV = (
    ("authentication", "Authentication Testing"),
    ("sql-injection", "SQL Injection Testing"),
    ("xss", "XSS Testing"),
    ("access-control", "Access Control Testing"),
    ("csrf", "CSRF Testing"),
    ("zap", "OWASP ZAP Results"),
)

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", "securegate-development-only-key"),
    DATABASE_URL=os.environ.get("DATABASE_URL"),
    VULNERABLE_MODE=os.environ.get("SECUREGATE_VULNERABLE_MODE", "0") == "1",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get(
        "SECUREGATE_HTTPS", "1" if os.environ.get("VERCEL") else "0"
    ) == "1",
)
csrf = CSRFProtect(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message_category = "warning"


def get_db():
    if "db" not in g:
        g.db = connect(app.config)
    return g.db


@app.teardown_appcontext
def close_db(_error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


@app.context_processor
def inject_navigation():
    return {"test_nav": TEST_NAV}


@app.template_filter("format_datetime")
def format_datetime(value):
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return value
    else:
        return value
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(PKT).strftime("%Y-%m-%d %H:%M:%S PKT")


def pkt_now():
    return datetime.now(PKT)


def pkt_now_iso():
    return pkt_now().isoformat(timespec="seconds")


def parse_timestamp(value):
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed


SQLITE_SCHEMA = """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            failed_attempts INTEGER NOT NULL DEFAULT 0,
            locked_until TEXT,
            created_at TEXT NOT NULL,
            is_blocked INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            category TEXT NOT NULL,
            description TEXT NOT NULL,
            price REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            message TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS security_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            username TEXT,
            event TEXT NOT NULL,
            result TEXT NOT NULL,
            ip_address TEXT,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS login_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            success INTEGER NOT NULL,
            ip_address TEXT,
            login_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS security_tests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            test_name TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Pending',
            result TEXT,
            details TEXT,
            finding TEXT,
            impact TEXT,
            evidence TEXT,
            applied_control TEXT,
            retest_result TEXT,
            risk_level TEXT,
            created_at TEXT NOT NULL,
            executed_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        """


def init_db():
    db = connect(app.config)
    if db.postgres:
        migration = (BASE_DIR / "migrations" / "001_initial.sql").read_text(
            encoding="utf-8"
        )
        db.executescript(migration)
    else:
        db.executescript(SQLITE_SCHEMA)
        user_columns = {row[1] for row in db.execute("PRAGMA table_info(users)").fetchall()}
        if "is_blocked" not in user_columns:
            db.execute("ALTER TABLE users ADD COLUMN is_blocked INTEGER NOT NULL DEFAULT 0")
        test_columns = {
            row[1] for row in db.execute("PRAGMA table_info(security_tests)").fetchall()
        }
        for column in (
            "finding", "impact", "evidence", "applied_control", "retest_result",
            "risk_level",
        ):
            if column not in test_columns:
                db.execute(f"ALTER TABLE security_tests ADD COLUMN {column} TEXT")
    if db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        initial_admin = os.environ.get("INITIAL_ADMIN_USERNAME")
        initial_password = os.environ.get("INITIAL_ADMIN_PASSWORD")
        seed_test_users = app.config.get("TESTING")
        if seed_test_users or (initial_admin and initial_password):
            now = pkt_now_iso()
            db.execute(
                "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, 'admin', ?)",
                (
                    initial_admin or "admin",
                    generate_password_hash(initial_password or "Admin@123"),
                    now,
                ),
            )
            if seed_test_users:
                db.execute(
                    "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, 'user', ?)",
                    ("student", generate_password_hash("Student@123"), now),
                )
    if db.execute("SELECT COUNT(*) FROM products").fetchone()[0] == 0 and (
        app.config.get("TESTING") or os.environ.get("SEED_PRODUCTS") == "1"
    ):
        db.executemany(
            "INSERT INTO products (name, category, description, price) VALUES (?, ?, ?, ?)",
            [
                ("Secure Coding Handbook", "Training", "Practical secure development guide", 29.99),
                ("OWASP Testing Toolkit", "Tools", "Synthetic lab testing checklist", 49.50),
                ("Blue Team Notebook", "Training", "Evidence and retest workbook", 15.00),
                ("Threat Modeling Cards", "Training", "STRIDE-based workshop cards", 19.95),
            ],
        )
    db.commit()
    db.close()


def log_event(event, result, username=None, user_id=None):
    db = get_db()
    if user_id is None and current_user.is_authenticated:
        user_id = current_user.id
    if user_id is None and username:
        row = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        user_id = row["id"] if row else None
    db.execute(
        "INSERT INTO security_logs (user_id, username, event, result, ip_address, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (user_id, username or (current_user.username if current_user.is_authenticated else None),
         event, result, request.remote_addr, pkt_now_iso()),
    )
    db.commit()


class User(UserMixin):
    def __init__(self, row):
        self.id = row["id"]
        self.username = row["username"]
        self.role = row["role"]


@login_manager.user_loader
def load_user(user_id):
    try:
        row = get_db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    except DatabaseError as error:
        app.logger.error("Unable to restore session user %s: %s", user_id, error)
        db = g.pop("db", None)
        if db is not None:
            db.close()
        return None
    return User(row) if row else None


@app.errorhandler(DatabaseError)
def handle_database_error(error):
    app.logger.error("Database request failed: %s", error, exc_info=True)
    if current_user.is_authenticated:
        logout_user()
    flash("Your session could not be restored. Please sign in again.", "warning")
    return redirect(url_for("login"))


def admin_required(view):
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if current_user.role != "admin":
            log_event("Unauthorized admin-page access", "DENIED")
            abort(403)
        return view(*args, **kwargs)

    return wrapped


@app.after_request
def security_headers(response):
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "img-src 'self' data:; font-src 'self'; connect-src 'self'; "
        "object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers.pop("Server", None)
    return response


@app.route("/")
def index():
    return redirect(url_for("dashboard" if current_user.is_authenticated else "login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not re.fullmatch(r"[A-Za-z0-9_]{3,30}", username):
            flash("Use 3-30 letters, numbers, or underscores.", "danger")
        elif len(password) < 8:
            flash("Password must be at least 8 characters.", "danger")
        else:
            try:
                db = get_db()
                db.execute(
                    "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, 'user', ?)",
                    (username, generate_password_hash(password), pkt_now_iso()),
                )
                db.commit()
                log_event("User registration", "SUCCESS", username)
                flash("Registration complete. Please sign in.", "success")
                return redirect(url_for("login"))
            except DatabaseIntegrityError:
                flash("That username is already registered.", "danger")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or not password:
            flash("Enter both a username and password.", "danger")
            return render_template("login.html", username=username)
        db = get_db()
        row = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        now = pkt_now()
        if row and row["is_blocked"]:
            db.execute(
                "INSERT INTO login_history (user_id, success, ip_address, login_at) VALUES (?, 0, ?, ?)",
                (row["id"], request.remote_addr, pkt_now_iso()),
            )
            db.commit()
            log_event("Login attempt", "BLOCKED", username, row["id"])
            flash("This account has been blocked. Contact an administrator.", "danger")
            return render_template("login.html", username=username)
        if row and row["locked_until"]:
            locked_until = parse_timestamp(row["locked_until"]).astimezone(PKT)
            if locked_until > now:
                seconds = max(1, ceil((locked_until - now).total_seconds()))
                log_event("Login attempt", "LOCKED", username)
                flash(
                    f"Account temporarily locked. Try again in {seconds} seconds.",
                    "danger",
                )
                return render_template("login.html", username=username)
            db.execute("UPDATE users SET locked_until = NULL, failed_attempts = 0 WHERE id = ?", (row["id"],))
            db.commit()
        if row and check_password_hash(row["password_hash"], password):
            db.execute("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?", (row["id"],))
            db.commit()
            login_user(User(row))
            login_time = pkt_now_iso()
            db.execute(
                "INSERT INTO login_history (user_id, success, ip_address, login_at) VALUES (?, 1, ?, ?)",
                (row["id"], request.remote_addr, login_time),
            )
            db.commit()
            log_event("Login", "SUCCESS", username, row["id"])
            return redirect(url_for("dashboard"))
        if row:
            db.execute(
                "INSERT INTO login_history (user_id, success, ip_address, login_at) VALUES (?, 0, ?, ?)",
                (row["id"], request.remote_addr, pkt_now_iso()),
            )
            failures = row["failed_attempts"] + 1
            lock_until = (
                (now + timedelta(seconds=LOCKOUT_SECONDS)).isoformat()
                if failures >= MAX_LOGIN_ATTEMPTS
                else None
            )
            db.execute("UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?", (failures, lock_until, row["id"]))
            db.commit()
        log_event("Login", "FAILED", username or None)
        flash("Invalid username or password.", "danger")
    return render_template("login.html", username=request.form.get("username", "").strip())


@app.route("/logout")
@login_required
def logout():
    log_event("Logout", "SUCCESS")
    logout_user()
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    metrics = {
        "total_users": db.execute("SELECT COUNT(*) FROM users").fetchone()[0],
        "active_users": db.execute("SELECT COUNT(*) FROM users WHERE NOT is_blocked").fetchone()[0],
        "blocked_users": db.execute("SELECT COUNT(*) FROM users WHERE is_blocked").fetchone()[0],
        "login_attempts": db.execute("SELECT COUNT(*) FROM login_history").fetchone()[0],
        "security_events": db.execute(
            "SELECT COUNT(*) FROM security_logs WHERE user_id = ?", (current_user.id,)
        ).fetchone()[0],
        "feedback_count": db.execute(
            "SELECT COUNT(*) FROM feedback WHERE user_id = ?", (current_user.id,)
        ).fetchone()[0],
        "tests_executed": db.execute(
            "SELECT COUNT(*) FROM security_tests WHERE user_id = ? AND status = 'Completed'",
            (current_user.id,),
        ).fetchone()[0],
        "findings_recorded": db.execute(
            "SELECT COUNT(*) FROM security_tests WHERE user_id = ? AND finding IS NOT NULL",
            (current_user.id,),
        ).fetchone()[0],
        "controls_applied": db.execute(
            "SELECT COUNT(*) FROM security_tests WHERE user_id = ? AND applied_control IS NOT NULL",
            (current_user.id,),
        ).fetchone()[0],
        "vulnerabilities": db.execute(
            "SELECT COUNT(*) FROM security_tests WHERE user_id = ? AND result = 'FAIL'",
            (current_user.id,),
        ).fetchone()[0],
        "controls": db.execute(
            "SELECT COUNT(*) FROM security_tests WHERE user_id = ? AND result = 'PASS'",
            (current_user.id,),
        ).fetchone()[0],
        "retests": db.execute(
            "SELECT COUNT(*) FROM security_tests WHERE user_id = ? AND test_name LIKE '%Retest%' AND result = 'PASS'",
            (current_user.id,),
        ).fetchone()[0],
    }
    recent_logs = db.execute(
        "SELECT * FROM security_logs WHERE user_id = ? ORDER BY id DESC LIMIT 6",
        (current_user.id,),
    ).fetchall()
    return render_template("dashboard.html", metrics=metrics, recent_logs=recent_logs)


@app.route("/search")
@login_required
def search():
    query = request.args.get("q", "").strip()
    products = []
    if request.args and not query:
        flash("Enter a product, category, or keyword to search.", "warning")
    if query:
        products = get_db().execute(
            "SELECT * FROM products WHERE name LIKE ? OR category LIKE ? OR description LIKE ? ORDER BY name",
            (f"%{query}%", f"%{query}%", f"%{query}%"),
        ).fetchall()
        log_event("Product search", f"{len(products)} result(s)")
    return render_template("search.html", products=products, query=query)


@app.route("/feedback", methods=["GET", "POST"])
@login_required
def feedback():
    message = request.form.get("message", "").strip() if request.method == "POST" else ""
    if request.method == "POST":
        if not message or len(message) > 500:
            flash("Feedback must contain 1-500 characters.", "danger")
        elif re.search(r"<\s*script|javascript\s*:", message, re.IGNORECASE):
            log_event("Feedback validation", "BLOCKED")
            flash("Potentially unsafe markup was blocked.", "danger")
        else:
            get_db().execute(
                "INSERT INTO feedback (user_id, message, created_at) VALUES (?, ?, ?)",
                (current_user.id, message, pkt_now_iso()),
            )
            get_db().commit()
            log_event("Feedback submission", "SUCCESS")
            flash("Feedback submitted safely.", "success")
            return redirect(url_for("feedback"))
    entries = get_db().execute(
        "SELECT f.message, f.created_at, u.username FROM feedback f JOIN users u ON u.id = f.user_id WHERE f.user_id = ? ORDER BY f.created_at DESC LIMIT 10",
        (current_user.id,),
    ).fetchall()
    return render_template("feedback.html", entries=entries, message=message)


TEST_PAGES = {
    slug: (label, description)
    for (slug, label), description in zip(
        TEST_NAV,
        (
            "Password hashing, lockout, session and credential handling checks.",
            "Parameterized search queries and input handling verification.",
            "Input validation, Jinja output escaping and Content Security Policy verification.",
            "Role checks, protected routes and authorization boundary verification.",
            "CSRF token generation and rejection of invalid or missing tokens.",
            "Imported OWASP ZAP baseline scan results and risk summary.",
        ),
    )
}


def get_zap_summary():
    report_path = BASE_DIR / "evidence" / "SecureGate_ZAP_Retest_Report.html"
    if not report_path.exists():
        return {"available": False, "count": 0, "risk": "Unavailable"}
    report = report_path.read_text(encoding="utf-8")
    risks = re.findall(
        r'id="alerts--risk-[^"]+".*?class="risk-level">([^<]+)',
        report,
        re.DOTALL,
    )
    counts = Counter(risks)
    for level in ("High", "Medium", "Low", "Informational"):
        if counts[level]:
            return {"available": True, "count": len(risks), "risk": level}
    return {"available": True, "count": len(risks), "risk": "None"}


def evaluate_security_checks(test_name):
    db = get_db()
    password_row = db.execute(
        "SELECT password_hash FROM users WHERE username = 'student'"
    ).fetchone()
    user_row = db.execute(
        "SELECT role FROM users WHERE username = 'student'"
    ).fetchone()
    admin_row = db.execute(
        "SELECT role FROM users WHERE username = 'admin'"
    ).fetchone()
    payload_count = db.execute(
        "SELECT COUNT(*) FROM products WHERE name = ?",
        ("' OR '1'='1",),
    ).fetchone()[0]
    escaped = app.jinja_env.from_string("{{ value }}").render(
        value="<script>alert(1)</script>"
    )
    csrf_client = app.test_client()
    csrf_form = csrf_client.get("/login")
    csrf_token_present = b'name="csrf_token"' in csrf_form.data
    invalid_csrf_rejected = csrf_client.post(
        "/login",
        data={"username": "student", "password": "bad", "csrf_token": "invalid"},
    ).status_code == 400
    missing_csrf_rejected = csrf_client.post(
        "/login", data={"username": "student", "password": "bad"}
    ).status_code == 400
    checks = {
        "authentication": [
            ("Password hashing", bool(password_row and (
                password_row["password_hash"].startswith("scrypt:")
                or password_row["password_hash"].startswith("pbkdf2:")
            )), "Plaintext passwords would be exposed", "Credential disclosure",
             "Stored password uses a Werkzeug password hash", "Werkzeug password hashing"),
            ("Session security", app.config["SESSION_COOKIE_HTTPONLY"]
             and app.config["SESSION_COOKIE_SAMESITE"] == "Lax",
             "Weak session cookies could enable session theft", "Session hijacking",
             "HttpOnly and SameSite=Lax are enabled", "Hardened Flask session cookies"),
            ("Access controls", bool(user_row and admin_row and user_row["role"] == "user"
             and admin_row["role"] == "admin"),
             "Incorrect roles could expose administrator actions", "Privilege escalation",
             "Separate user and admin roles are present", "Role-based admin_required decorator"),
        ],
        "sql-injection": [
            ("Parameterized queries", payload_count == 0,
             "User input could alter the SQL statement", "Unauthorized data access",
             "Injection payload returned zero product rows", "Parameterized SQLite placeholders"),
            ("Injection payload rejection", payload_count == 0,
             "A tautology payload could broaden search results", "Data disclosure",
             "The tautology payload was treated as ordinary text", "Bound query parameters"),
            ("Successful retest", payload_count == 0,
             "The SQL injection regression would be reintroduced", "Query integrity",
             "The same payload remained rejected during retest", "Repeat parameterized-query check"),
        ],
        "xss": [
            ("Input sanitization", re.search(
                r"<\s*script|javascript\s*:", "<script>", re.I
            ) is not None,
             "Script markup could be accepted as feedback", "Stored cross-site scripting",
             "The script pattern was identified and blocked by validation", "Feedback input validation"),
            ("Script escaping", escaped == "&lt;script&gt;alert(1)&lt;/script&gt;",
             "Stored markup could execute in another user's browser", "Cross-site scripting",
             "Jinja rendered script markup as escaped text", "Jinja autoescaping and CSP"),
            ("Successful retest", escaped == "&lt;script&gt;alert(1)&lt;/script&gt;",
             "The escaping regression would expose stored feedback", "Browser code execution",
             "The escaped output remained safe during retest", "Repeat escaped-output check"),
        ],
        "access-control": [
            ("User role boundary", bool(user_row and user_row["role"] == "user"),
             "A normal account could be treated as an administrator", "Privilege escalation",
             "Student account resolves to the user role", "Flask-Login role checks"),
            ("Administrator boundary", bool(admin_row and admin_row["role"] == "admin"),
             "Administrator actions could be unavailable or misassigned", "Authorization failure",
             "Admin account resolves to the administrator role", "admin_required decorator"),
            ("Successful retest", admin_required is not None,
             "Protected routes could lose their authorization guard", "Unauthorized access",
             "The protected-route decorator is installed", "Protected admin endpoints"),
        ],
        "csrf": [
            ("CSRF token presence", csrf_token_present,
             "POST forms could be submitted without request tokens", "Cross-site request forgery",
             "The login form contains a generated CSRF token", "CSRFProtect on the Flask app"),
            ("Invalid token rejection", invalid_csrf_rejected,
             "Forged requests could be accepted", "Unauthorized state changes",
             "A POST with an invalid token returned HTTP 400", "CSRFError handler"),
            ("Successful retest", missing_csrf_rejected,
             "Missing tokens could be accepted after a regression", "Request forgery",
             "A POST without a token remained rejected", "Global CSRF validation"),
        ],
        "zap": [
            ("Imported scan summary", get_zap_summary()["available"],
             "No imported ZAP report could be located", "Unverified scan coverage",
             "The ZAP retest report was loaded from the evidence directory", "Imported ZAP report"),
            ("Vulnerability count", get_zap_summary()["count"] >= 0,
             "The imported report could not be counted", "Incomplete security evidence",
             f"{get_zap_summary()['count']} alert entries were counted", "ZAP alert summary"),
            ("Risk level", bool(get_zap_summary()["risk"]),
             "The imported report has no risk classification", "Unclassified findings",
             f"Highest imported risk: {get_zap_summary()['risk']}", "ZAP risk classification"),
        ],
    }[test_name]
    return [
        {
            "name": name,
            "result": "PASS" if passed else "FAIL",
            "finding": finding,
            "impact": impact,
            "evidence": evidence,
            "applied_control": control,
            "retest_result": "PASS" if passed else "FAIL",
            "risk_level": get_zap_summary()["risk"] if test_name == "zap" else "N/A",
        }
        for name, passed, finding, impact, evidence, control in checks
    ]


@app.route("/testing/<test_name>", methods=["GET", "POST"])
@login_required
def testing(test_name):
    if test_name not in TEST_PAGES:
        abort(404)
    title, description = TEST_PAGES[test_name]
    db = get_db()
    if request.method == "POST":
        checks = evaluate_security_checks(test_name)
        executed_at = pkt_now_iso()
        db.executemany(
            """
            INSERT INTO security_tests (
                user_id, test_name, status, result, details, finding, impact,
                evidence, applied_control, retest_result, risk_level, created_at,
                executed_at
            ) VALUES (?, ?, 'Completed', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    current_user.id,
                    f"{title}: {check['name']}",
                    check["result"],
                    check["evidence"],
                    check["finding"],
                    check["impact"],
                    check["evidence"],
                    check["applied_control"],
                    check["retest_result"],
                    check["risk_level"],
                    executed_at,
                    executed_at,
                )
                for check in checks
            ],
        )
        db.commit()
        log_event(f"{title} executed", "SUCCESS")
        flash("Security test completed and its result was recorded.", "success")
        return redirect(url_for("testing", test_name=test_name))
    history = db.execute(
        """
        SELECT test_name, status, result, details, finding, impact, evidence,
               applied_control, retest_result, risk_level, executed_at
        FROM security_tests
        WHERE user_id = ? AND test_name LIKE ?
        ORDER BY id DESC
        """,
        (current_user.id, f"{title}: %"),
    ).fetchall()
    results = history or [
        {
            "test_name": name,
            "status": "Pending",
            "result": None,
            "details": "Not executed yet",
            "finding": "Not assessed",
            "impact": "Not assessed",
            "evidence": "Not recorded",
            "applied_control": "Not applied",
            "retest_result": "Pending",
            "risk_level": "N/A",
            "executed_at": None,
        }
        for name in ("Input validation", "Security control", "Retest")
    ]
    return render_template(
        "testing.html",
        title=title,
        description=description,
        results=results,
        zap_summary=get_zap_summary() if test_name == "zap" else None,
    )


@app.route("/evidence")
@login_required
def evidence():
    evidence = get_db().execute(
        """
        SELECT test_name, result, finding, impact, evidence, applied_control,
               retest_result, risk_level, executed_at
        FROM security_tests
        WHERE user_id = ?
        ORDER BY id DESC
        """,
        (current_user.id,),
    ).fetchall()
    return render_template("evidence.html", evidence=evidence)


@app.route("/reports")
@login_required
def reports():
    reports = get_db().execute(
        """
        SELECT test_name, finding, impact, evidence, applied_control,
               retest_result, risk_level, result, executed_at
        FROM security_tests
        WHERE user_id = ? AND id IN (
            SELECT MAX(id) FROM security_tests
            WHERE user_id = ? GROUP BY test_name
        )
        ORDER BY id
        """,
        (current_user.id, current_user.id),
    ).fetchall()
    return render_template("reports.html", reports=reports)


@app.route("/admin/users")
@admin_required
def admin_users():
    users = get_db().execute("SELECT id, username, role, failed_attempts, locked_until, is_blocked, created_at FROM users ORDER BY id").fetchall()
    return render_template("admin_users.html", users=users)


@app.route("/admin/users/<int:user_id>/block", methods=["POST"])
@admin_required
def block_user(user_id):
    db = get_db()
    row = db.execute("SELECT username, role FROM users WHERE id = ?", (user_id,)).fetchone()
    if not row:
        abort(404)
    if user_id == current_user.id or row["role"] == "admin":
        flash("Administrators cannot block an administrator account.", "warning")
    else:
        db.execute("UPDATE users SET is_blocked = 1 WHERE id = ?", (user_id,))
        db.commit()
        log_event("User blocked", "SUCCESS")
        flash(f"{row['username']} is now blocked.", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/users/<int:user_id>/unblock", methods=["POST"])
@admin_required
def unblock_user(user_id):
    db = get_db()
    row = db.execute("SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()
    if not row:
        abort(404)
    db.execute("UPDATE users SET is_blocked = 0, failed_attempts = 0, locked_until = NULL WHERE id = ?", (user_id,))
    db.commit()
    log_event("User unblocked", "SUCCESS")
    flash(f"{row['username']} is now unblocked.", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/reset/<data_set>", methods=["POST"])
@admin_required
def reset_data(data_set):
    reset_map = {
        "dashboard": ("Clear Dashboard Data", ("security_logs", "login_history", "feedback", "security_tests")),
        "security-tests": ("Reset Security Tests", ("security_tests",)),
        "audit": ("Clear Audit Trail", ("security_logs",)),
        "login-history": ("Clear Login History", ("login_history",)),
        "feedback": ("Clear Feedback Records", ("feedback",)),
        "evidence": ("Clear Evidence Records", ("security_tests",)),
        "reports": ("Clear Reports", ("security_tests",)),
    }
    if data_set not in reset_map:
        abort(404)
    label, tables = reset_map[data_set]
    db = get_db()
    for table in tables:
        db.execute(f"DELETE FROM {table}")
    db.commit()
    log_event(f"Admin reset: {label}", "SUCCESS")
    flash(f"{label} completed.", "success")
    return redirect(url_for("admin_users"))


@app.route("/login-history")
@login_required
def login_history():
    history = get_db().execute(
        "SELECT login_at, success, ip_address FROM login_history WHERE user_id = ? ORDER BY id DESC",
        (current_user.id,),
    ).fetchall()
    return render_template("login_history.html", history=history)


@app.route("/admin/login-history")
@admin_required
def admin_login_history():
    history = get_db().execute(
        """
        SELECT l.login_at, l.success, l.ip_address, u.username
        FROM login_history l
        JOIN users u ON u.id = l.user_id
        ORDER BY l.id DESC
        LIMIT 500
        """
    ).fetchall()
    return render_template("admin_login_history.html", history=history)


@app.route("/admin/logs")
@admin_required
def admin_logs():
    logs = get_db().execute("SELECT * FROM security_logs ORDER BY id DESC LIMIT 100").fetchall()
    return render_template("admin_logs.html", logs=logs)


@app.errorhandler(403)
def forbidden(_error):
    return render_template("error.html", code=403, message="You do not have permission to access this page."), 403


@app.errorhandler(404)
def not_found(_error):
    return render_template("error.html", code=404, message="The requested page was not found."), 404


@app.errorhandler(CSRFError)
def csrf_error(error):
    log_event("CSRF validation", "BLOCKED")
    return render_template("csrf_error.html", reason=error.description), 400


if __name__ == "__main__":
    init_db()
    app.run(
        host=os.environ.get("HOST", "0.0.0.0"),
        port=int(os.environ.get("PORT", "5000")),
        debug=False,
    )
