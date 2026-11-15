import os

from db import DatabaseError, normalize_database_url

secret_key = os.environ.get("SECRET_KEY") or os.environ.get("SESSION_SECRET")
database_url = (
    os.environ.get("DATABASE_URL")
    or os.environ.get("POSTGRES_URL")
    or os.environ.get("NEON_DATABASE_URL")
    or os.environ.get("DATABASE_URL_UNPOOLED")
)

if secret_key:
    os.environ["SECRET_KEY"] = secret_key
if database_url:
    os.environ["DATABASE_URL"] = normalize_database_url(database_url)

from app import app, init_db

@app.before_request
def initialize_database():
    if app.extensions.get("securegate_database_ready"):
        return None
    if not secret_key:
        app.logger.error("Vercel SECRET_KEY/SESSION_SECRET is not configured")
        return "Application configuration is incomplete.", 503
    if not database_url:
        app.logger.error("Vercel database URL is not configured")
        return "Database configuration is incomplete.", 503
    try:
        with app.app_context():
            init_db()
    except (DatabaseError, RuntimeError) as error:
        app.logger.error("Vercel database initialization failed: %s", error, exc_info=True)
        return "Database initialization is temporarily unavailable.", 503
    app.extensions["securegate_database_ready"] = True
    return None
