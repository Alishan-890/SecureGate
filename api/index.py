import os

from db import DatabaseError, normalize_database_url

secret_key = os.environ.get("SECRET_KEY") or os.environ.get("SESSION_SECRET")
database_url = (
    os.environ.get("DATABASE_URL")
    or os.environ.get("POSTGRES_URL")
    or os.environ.get("NEON_DATABASE_URL")
    or os.environ.get("DATABASE_URL_UNPOOLED")
)

if not secret_key:
    raise RuntimeError("SECRET_KEY must be configured in Vercel environment variables")
if not database_url:
    raise RuntimeError("DATABASE_URL must be configured with the Neon PostgreSQL URL")

os.environ["SECRET_KEY"] = secret_key
os.environ["DATABASE_URL"] = normalize_database_url(database_url)

from app import app, init_db

try:
    with app.app_context():
        init_db()
except DatabaseError as error:
    app.logger.error("Vercel database initialization failed: %s", error, exc_info=True)
    raise
