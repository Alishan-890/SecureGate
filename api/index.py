import os

from db import normalize_database_url

secret_key = (
    os.environ.get("SECRET_KEY")
    or os.environ.get("SESSION_SECRET")
    or "static-super-secret-key-12345"
)
database_url = (
    os.environ.get("DATABASE_URL")
    or os.environ.get("POSTGRES_URL")
    or os.environ.get("NEON_DATABASE_URL")
    or os.environ.get("DATABASE_URL_UNPOOLED")
)

os.environ["SECRET_KEY"] = secret_key
if database_url:
    os.environ["DATABASE_URL"] = normalize_database_url(database_url)

from app import app
