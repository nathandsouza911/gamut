# SPDX-License-Identifier: AGPL-3.0-only
"""Shared fixtures.

TEST_DATABASE_URL     connects as the owner role (gamut_owner): migrations and cleanup.
TEST_APP_DATABASE_URL connects as the app role (gamut_app): what the code under test uses.
"""

import os
import uuid
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.orm import Session

from app import db
from app.models import Tenant, TenantStatus, User

BACKEND_DIR = Path(__file__).resolve().parents[1]

TABLES = (
    "audit_events",
    "scheduled_actions",
    "job_steps",
    "jobs",
    "memberships",
    "tenant_credentials",
    "sessions",
    "tenants",
    "users",
)


def _env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        pytest.skip(f"{name} is not set")
    return value


@pytest.fixture(scope="session")
def _migrated_owner_engine() -> Iterator[Engine]:
    """Owner-role engine on a freshly migrated schema (once per test session)."""
    url = _env("TEST_DATABASE_URL")
    engine = create_engine(url)
    with engine.begin() as conn:
        conn.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
        conn.execute(text("CREATE SCHEMA public"))
    cfg = Config(str(BACKEND_DIR / "alembic.ini"))
    cfg.set_main_option("sqlalchemy.url", url.replace("%", "%%"))
    command.upgrade(cfg, "head")
    yield engine
    engine.dispose()


@pytest.fixture(scope="session")
def _app_engine() -> Iterator[Engine]:
    engine = create_engine(_env("TEST_APP_DATABASE_URL"))
    yield engine
    engine.dispose()


@pytest.fixture
def owner_engine(_migrated_owner_engine: Engine) -> Engine:
    """Owner-role engine; every table is emptied (identities reset) before the test."""
    with _migrated_owner_engine.begin() as conn:
        conn.execute(text(f"TRUNCATE {', '.join(TABLES)} RESTART IDENTITY CASCADE"))
    return _migrated_owner_engine


@pytest.fixture
def app_engine(owner_engine: Engine, _app_engine: Engine) -> Iterator[Engine]:
    """App-role engine on a clean database; app.db.session_scope() uses it too."""
    db.configure_engine(_app_engine)
    yield _app_engine
    db.configure_engine(None)


@pytest.fixture
def app_session(app_engine: Engine) -> Iterator[Session]:
    """App-role session. Commit explicitly; uncommitted work is rolled back."""
    with Session(app_engine) as session:
        yield session
        session.rollback()


@pytest.fixture
def make_user(app_session: Session) -> Callable[..., User]:
    """Adds a User to app_session (flushed, not committed)."""

    def _make(**overrides: Any) -> User:
        fields: dict[str, Any] = {
            "email": f"user-{uuid.uuid4().hex[:8]}@example.com",
            "display_name": "Test User",
        }
        fields.update(overrides)
        user = User(**fields)
        app_session.add(user)
        app_session.flush()
        return user

    return _make


@pytest.fixture
def make_tenant(app_session: Session) -> Callable[..., Tenant]:
    """Adds an active Tenant to app_session (flushed, not committed)."""

    def _make(**overrides: Any) -> Tenant:
        suffix = uuid.uuid4().hex[:8]
        domain = overrides.pop("primary_domain", f"t{suffix}.example.com")
        fields: dict[str, Any] = {
            "name": f"Tenant {suffix}",
            "primary_domain": domain,
            "domains": [domain],
            "status": TenantStatus.active,
        }
        fields.update(overrides)
        tenant = Tenant(**fields)
        app_session.add(tenant)
        app_session.flush()
        return tenant

    return _make
