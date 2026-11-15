import getpass
import os

from app import app, init_db, normalize_username, pkt_now_iso
from db import connect
from werkzeug.security import generate_password_hash


def main():
    username = normalize_username(
        os.environ.get("ADMIN_USERNAME") or input("Admin username: ")
    )
    password = os.environ.get("ADMIN_PASSWORD") or getpass.getpass("Admin password: ")
    if not username or not password:
        raise SystemExit("ADMIN_USERNAME and ADMIN_PASSWORD are required.")

    with app.app_context():
        init_db()
        db = connect(app.config)
        try:
            row = db.execute(
                "SELECT id FROM users WHERE username = ?", (username,)
            ).fetchone()
            if row:
                db.execute(
                    "UPDATE users SET role = 'admin', password_hash = ? WHERE id = ?",
                    (generate_password_hash(password), row["id"]),
                )
            else:
                db.execute(
                    "INSERT INTO users "
                    "(username, password_hash, role, created_at) VALUES (?, ?, 'admin', ?)",
                    (username, generate_password_hash(password), pkt_now_iso()),
                )
            db.commit()
        finally:
            db.close()
    print(f"Admin account ready: {username}")


if __name__ == "__main__":
    main()
