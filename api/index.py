import os

if not os.environ.get("SECRET_KEY"):
    raise RuntimeError("SECRET_KEY must be configured in Vercel environment variables")
if not os.environ.get("DATABASE_URL"):
    raise RuntimeError("DATABASE_URL must be configured with the Neon PostgreSQL URL")

from app import app, init_db

init_db()
