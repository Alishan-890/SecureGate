import os
import re
import sqlite3
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


class DatabaseError(Exception):
    """Raised when the database cannot serve an application query."""


class DatabaseIntegrityError(DatabaseError):
    """Raised when a database constraint rejects a write."""


class HybridRow(dict):
    def __getitem__(self, key):
        if isinstance(key, int):
            return tuple(self.values())[key]
        return super().__getitem__(key)


class DatabaseCursor:
    def __init__(self, cursor, postgres):
        self.cursor = cursor
        self.postgres = postgres

    def execute(self, query, parameters=()):
        self.cursor.execute(
            _postgres_placeholders(query) if self.postgres else query,
            parameters,
        )
        return self

    def executemany(self, query, parameters):
        self.cursor.executemany(
            _postgres_placeholders(query) if self.postgres else query,
            parameters,
        )
        return self

    def fetchone(self):
        row = self.cursor.fetchone()
        return _row(row, self.cursor.description) if row is not None else None

    def fetchall(self):
        return [_row(row, self.cursor.description) for row in self.cursor.fetchall()]


class DatabaseConnection:
    def __init__(self, connection, postgres):
        self.connection = connection
        self.postgres = postgres

    def execute(self, query, parameters=()):
        try:
            cursor = self.connection.cursor()
            return DatabaseCursor(cursor, self.postgres).execute(query, parameters)
        except (sqlite3.IntegrityError, _postgres_integrity_error()) as error:
            raise DatabaseIntegrityError(str(error)) from error
        except sqlite3.Error as error:
            raise DatabaseError(str(error)) from error
        except Exception as error:
            if self.postgres:
                import psycopg

                if isinstance(error, psycopg.Error):
                    raise DatabaseError(str(error)) from error
            raise

    def executemany(self, query, parameters):
        try:
            cursor = self.connection.cursor()
            return DatabaseCursor(cursor, self.postgres).executemany(query, parameters)
        except (sqlite3.IntegrityError, _postgres_integrity_error()) as error:
            raise DatabaseIntegrityError(str(error)) from error
        except sqlite3.Error as error:
            raise DatabaseError(str(error)) from error
        except Exception as error:
            if self.postgres:
                import psycopg

                if isinstance(error, psycopg.Error):
                    raise DatabaseError(str(error)) from error
            raise

    def executescript(self, script):
        for statement in script.split(";"):
            if statement.strip():
                self.execute(statement)
        return self

    def commit(self):
        try:
            self.connection.commit()
        except sqlite3.Error as error:
            raise DatabaseError(str(error)) from error
        except Exception as error:
            if self.postgres:
                import psycopg

                if isinstance(error, psycopg.Error):
                    raise DatabaseError(str(error)) from error
            raise

    def rollback(self):
        self.connection.rollback()

    def close(self):
        self.connection.close()


def connect(config):
    database_url = (
        os.environ.get("DATABASE_URL")
        or os.environ.get("POSTGRES_URL")
        or os.environ.get("NEON_DATABASE_URL")
        or os.environ.get("DATABASE_URL_UNPOOLED")
        or config.get("DATABASE_URL")
    )
    if config.get("TESTING") and config.get("DATABASE"):
        connection = sqlite3.connect(config["DATABASE"])
        connection.row_factory = sqlite3.Row
        return DatabaseConnection(connection, postgres=False)
    if database_url:
        try:
            import psycopg
        except ImportError as error:
            raise RuntimeError("psycopg is required when DATABASE_URL is configured") from error
        database_url = normalize_database_url(database_url)
        try:
            connection = psycopg.connect(database_url)
        except psycopg.Error as error:
            raise DatabaseError(str(error)) from error
        return DatabaseConnection(connection, postgres=True)
    raise RuntimeError(
        "DATABASE_URL must be configured for production. "
        "Use the Neon PostgreSQL connection string."
    )


def normalize_database_url(database_url):
    """Normalize a Neon URL and require encrypted PostgreSQL connections."""
    database_url = database_url.strip()
    parsed = urlsplit(database_url)
    if parsed.scheme in {"postgres", "postgresql+psycopg"}:
        parsed = parsed._replace(scheme="postgresql")
    if parsed.scheme not in {"postgresql", "postgresql+psycopg"}:
        raise DatabaseError("DATABASE_URL must be a PostgreSQL connection string")
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    query.setdefault("sslmode", "require")
    return urlunsplit(parsed._replace(query=urlencode(query)))


def _postgres_integrity_error():
    try:
        import psycopg
        return psycopg.errors.IntegrityError
    except ImportError:
        return type("_UnavailableIntegrityError", (Exception,), {})


def _postgres_placeholders(query):
    return re.sub(r"\?", "%s", query)


def _row(row, description):
    if isinstance(row, sqlite3.Row):
        return row
    names = [column[0] for column in description or ()]
    return HybridRow(zip(names, row))
