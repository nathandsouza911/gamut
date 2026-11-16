# SPDX-License-Identifier: AGPL-3.0-only
"""Server-side sessions.

The session cookie carries a random 32-byte id (base64url). The database stores only
sha256(id), so a database read does not yield usable cookies. A session ends 12 hours
after creation (absolute) or after 2 hours without a request (idle), whichever is first.
Each session has its own CSRF token (see app/auth/csrf.py).
"""

import base64
import binascii
import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete
from sqlalchemy.orm import Session
from starlette.responses import Response

from app.auth.csrf import CSRF_COOKIE
from app.models import Session as SessionRow

SESSION_COOKIE = "gamut_session"
ABSOLUTE_LIFETIME = timedelta(hours=12)
IDLE_TIMEOUT = timedelta(hours=2)
# last_seen_at is only rewritten when it is older than this, to avoid a write per request.
_TOUCH_INTERVAL = timedelta(minutes=1)
_ID_BYTES = 32


def _now() -> datetime:
    return datetime.now(UTC)


def _hash(session_id: bytes) -> bytes:
    return hashlib.sha256(session_id).digest()


def _decode(cookie_value: str) -> bytes | None:
    try:
        raw = base64.urlsafe_b64decode(cookie_value + "=" * (-len(cookie_value) % 4))
    except (binascii.Error, ValueError):
        return None
    return raw if len(raw) == _ID_BYTES else None


def create_session(db: Session, user_id: uuid.UUID) -> tuple[str, str]:
    """Insert a session for `user_id`. Returns (cookie value, CSRF token)."""
    session_id = secrets.token_bytes(_ID_BYTES)
    csrf_token = secrets.token_urlsafe(32)
    now = _now()
    db.add(
        SessionRow(
            id_hash=_hash(session_id),
            user_id=user_id,
            csrf_token=csrf_token,
            created_at=now,
            last_seen_at=now,
            expires_at=now + ABSOLUTE_LIFETIME,
        )
    )
    db.flush()
    cookie_value = base64.urlsafe_b64encode(session_id).decode().rstrip("=")
    return cookie_value, csrf_token


def load_session(db: Session, cookie_value: str | None) -> SessionRow | None:
    """The live session for this cookie, or None. Expired sessions are deleted."""
    if not cookie_value:
        return None
    session_id = _decode(cookie_value)
    if session_id is None:
        return None
    row = db.get(SessionRow, _hash(session_id))
    if row is None:
        return None
    now = _now()
    if now >= row.expires_at or now - row.last_seen_at >= IDLE_TIMEOUT:
        db.delete(row)
        db.flush()
        return None
    if now - row.last_seen_at >= _TOUCH_INTERVAL:
        row.last_seen_at = now
        db.flush()
    return row


def delete_session(db: Session, cookie_value: str | None) -> None:
    session_id = _decode(cookie_value or "")
    if session_id is not None:
        db.execute(delete(SessionRow).where(SessionRow.id_hash == _hash(session_id)))


def set_session_cookies(response: Response, cookie_value: str, csrf_token: str) -> None:
    max_age = int(ABSOLUTE_LIFETIME.total_seconds())
    response.set_cookie(
        SESSION_COOKIE, cookie_value, max_age=max_age, path="/",
        secure=True, httponly=True, samesite="lax",
    )
    # Readable by the UI, which echoes it in the X-CSRF-Token header.
    response.set_cookie(
        CSRF_COOKIE, csrf_token, max_age=max_age, path="/",
        secure=True, httponly=False, samesite="lax",
    )


def clear_session_cookies(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE, path="/", secure=True, httponly=True, samesite="lax")
    response.delete_cookie(CSRF_COOKIE, path="/", secure=True, httponly=False, samesite="lax")
