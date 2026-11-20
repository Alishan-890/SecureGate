import os
import sqlite3
from pathlib import Path

import psycopg


ROOT = Path(__file__).resolve().parents[1]
SQLITE_PATH = ROOT / "securegate.db"
TABLES = (
    "users",
    "products",
    "feedback",
    "security_logs",
    "login_history",
    "security_tests",
)
TABLE_COLUMNS = {
    "users": {"id", "username", "password_hash", "role", "failed_attempts", "locked_until", "created_at", "last_login", "is_blocked"},
    "products": {"id", "name", "category", "description", "price", "status"},
    "feedback": {"id", "user_id", "message", "created_at"},
    "security_logs": {"id", "user_id", "username", "event", "result", "ip_address", "created_at"},
    "login_history": {"id", "user_id", "success", "ip_address", "login_at"},
    "security_tests": {"id", "user_id", "test_name", "status", "result", "details", "finding", "impact", "evidence", "applied_control", "retest_result", "risk_level", "created_at", "executed_at"},
}


def main():
    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        raise RuntimeError("DATABASE_URL must contain the Neon PostgreSQL connection string")
    if not SQLITE_PATH.exists():
        raise FileNotFoundError(SQLITE_PATH)

    with sqlite3.connect(SQLITE_PATH) as source, psycopg.connect(database_url) as target:
        target.execute((ROOT / "migrations" / "001_initial.sql").read_text(encoding="utf-8"))
        for table in TABLES:
            columns = [
                row[1]
                for row in source.execute(f"PRAGMA table_info({table})").fetchall()
                if row[1] in TABLE_COLUMNS[table]
            ]
            rows = source.execute(f"SELECT {', '.join(columns)} FROM {table}").fetchall()
            if not rows:
                continue
            if table == "login_history" and "success" in columns:
                success_index = columns.index("success")
                rows = [
                    row[:success_index]
                    + (bool(row[success_index]),)
                    + row[success_index + 1 :]
                    for row in rows
                ]
            placeholders = ", ".join(["%s"] * len(columns))
            target.executemany(
                f"INSERT INTO {table} ({', '.join(columns)}) VALUES ({placeholders}) "
                "ON CONFLICT DO NOTHING",
                rows,
            )
        target.commit()


if __name__ == "__main__":
    main()
