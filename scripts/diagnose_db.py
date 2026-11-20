"""Diagnose Neon connectivity and schema steps without embedding credentials."""

import os
import re
import sys
from pathlib import Path

try:
    import psycopg
except ImportError as error:
    print(f"FAIL import psycopg: {type(error).__name__}: {error}")
    raise SystemExit(1) from error

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from db import normalize_database_url


def masked_message(error):
    masked = re.sub(
        r"(?i)(postgres(?:ql)?://)[^\s]+",
        r"\1[REDACTED]",
        str(error),
    )[:300]
    return re.sub(r"(?i)(password\s*=\s*)[^\s,;]+", r"\1[REDACTED]", masked)


def statements():
    migration = (ROOT / "migrations" / "001_initial.sql").read_text(encoding="utf-8")
    result = [
        (f"migration_{index}", statement)
        for index, statement in enumerate(migration.split(";"), start=1)
        if statement.strip()
    ]
    result.extend(
        [
            ("users_last_login", "ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login TIMESTAMPTZ"),
            ("users_is_blocked", "ALTER TABLE users ADD COLUMN IF NOT EXISTS is_blocked BOOLEAN NOT NULL DEFAULT FALSE"),
            ("products_status", "ALTER TABLE products ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'Active'"),
        ]
    )
    for column, definition in (
        ("status", "VARCHAR(20) NOT NULL DEFAULT 'Not Run'"),
        ("result", "VARCHAR(10)"),
        ("details", "TEXT"),
        ("finding", "TEXT"),
        ("impact", "TEXT"),
        ("evidence", "TEXT"),
        ("applied_control", "TEXT"),
        ("retest_result", "VARCHAR(10)"),
        ("risk_level", "VARCHAR(20)"),
        ("executed_at", "TIMESTAMPTZ"),
    ):
        result.append(
            (
                f"security_tests_{column}",
                f"ALTER TABLE security_tests ADD COLUMN IF NOT EXISTS {column} {definition}",
            )
        )
    result.extend(
        [
            (
                "login_history_success_boolean",
                "ALTER TABLE login_history ALTER COLUMN success TYPE BOOLEAN "
                "USING lower(success::text) IN ('1', 'true', 't')",
            ),
            (
                "normalize_pending_security_tests",
                "UPDATE security_tests SET status = 'Not Run' WHERE status = 'Pending'",
            ),
        ]
    )
    products = (
        ("Web Login Portal", "Authentication", "Secure login, session, and account protection module"),
        ("SQL Injection Test Module", "Injection", "Controlled parameterized-query injection testing module"),
        ("XSS Test Module", "Cross-Site Scripting", "Controlled input validation and output escaping test module"),
        ("Access Control Checker", "Authorization", "Role and protected-route authorization verification module"),
    )
    for product_id, (name, category, description) in enumerate(products, start=1):
        result.append(
            (
                f"seed_product_{product_id}",
                "INSERT INTO products (id, name, category, description, price, status) "
                "VALUES (?, ?, ?, ?, 0.00, 'Active') "
                "ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, "
                "category = EXCLUDED.category, description = EXCLUDED.description, "
                "price = EXCLUDED.price, status = EXCLUDED.status",
                (product_id, name, category, description),
            )
        )
    return result


def main():
    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        print("FAIL configuration: DATABASE_URL is not set")
        return 1

    try:
        connection = psycopg.connect(normalize_database_url(database_url))
    except Exception as error:
        print(f"FAIL connection: {type(error).__name__}: {masked_message(error)}")
        print("Summary: connection failed; schema steps were not attempted.")
        return 1

    failures = []
    try:
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
                cursor.fetchone()
            connection.commit()
            print("PASS connection: SELECT 1")
        except Exception as error:
            connection.rollback()
            print(f"FAIL connection: {type(error).__name__}: {masked_message(error)}")
            return 1

        for step in statements():
            name = step[0]
            statement = step[1]
            parameters = step[2] if len(step) == 3 else ()
            try:
                with connection.transaction():
                    with connection.cursor() as cursor:
                        cursor.execute(statement.replace("?", "%s"), parameters)
                print(f"PASS {name}")
            except Exception as error:
                connection.rollback()
                failures.append(name)
                print(f"FAIL {name}: {type(error).__name__}: {masked_message(error)}")
    finally:
        connection.close()

    if failures:
        print("Summary: failed steps: " + ", ".join(failures))
        return 1
    print("Summary: all connection and schema steps passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
