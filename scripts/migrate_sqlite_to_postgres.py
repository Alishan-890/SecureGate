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
            ]
            rows = source.execute(f"SELECT {', '.join(columns)} FROM {table}").fetchall()
            if not rows:
                continue
            placeholders = ", ".join(["%s"] * len(columns))
            target.executemany(
                f"INSERT INTO {table} ({', '.join(columns)}) VALUES ({placeholders}) "
                "ON CONFLICT DO NOTHING",
                rows,
            )
        target.commit()


if __name__ == "__main__":
    main()
