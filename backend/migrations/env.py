# SPDX-License-Identifier: AGPL-3.0-only
"""Alembic environment. Runs online only, as the owner role (gamut_owner)."""

import os

from alembic import context
from sqlalchemy import create_engine

from app.models import Base

config = context.config
url = config.get_main_option("sqlalchemy.url") or os.environ.get("GAMUT_MIGRATE_DATABASE_URL")
if not url:
    raise SystemExit("set GAMUT_MIGRATE_DATABASE_URL (owner role) to run migrations")

engine = create_engine(url)
with engine.connect() as connection:
    context.configure(connection=connection, target_metadata=Base.metadata)
    with context.begin_transaction():
        context.run_migrations()
engine.dispose()
