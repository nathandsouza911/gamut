# SPDX-License-Identifier: AGPL-3.0-only
"""Engine, session scope and advisory-lock helper (app role, gamut_app)."""

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import Engine, create_engine, func, select
from sqlalchemy.orm import Session

from app.settings import get_settings

_engine: Engine | None = None


def configure_engine(engine: Engine | None) -> None:
    """Use `engine` for all sessions (tests); None resets to the settings URL on next use."""
    global _engine
    _engine = engine


def get_engine() -> Engine:
    global _engine
    if _engine is None:
        _engine = create_engine(get_settings().database_url, pool_pre_ping=True)
    return _engine


@contextmanager
def session_scope() -> Iterator[Session]:
    """One transaction: commit on success, roll back on any exception.

    Objects stay readable after the block (expire_on_commit=False).
    """
    session = Session(get_engine(), expire_on_commit=False)
    try:
        yield session
        session.commit()
    except BaseException:
        session.rollback()
        raise
    finally:
        session.close()


def advisory_xact_lock(session: Session, key: int) -> None:
    """Block until this transaction holds advisory lock `key`; released at commit/rollback."""
    session.execute(select(func.pg_advisory_xact_lock(key)))
