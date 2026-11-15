# SPDX-License-Identifier: AGPL-3.0-only
"""The bootstrap owner: the one local password account (break-glass).

On start, if GAMUT_BOOTSTRAP_ADMIN_EMAIL and GAMUT_BOOTSTRAP_ADMIN_PASSWORD are set and no
user has that email, an owner is created with an argon2id hash of the password. An
existing user is never changed, so a restart does not reset the password. Everyone else
signs in through OIDC.
"""

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.audit.chain import append_event
from app.db import advisory_xact_lock, session_scope
from app.models import User
from app.settings import Settings

BOOTSTRAP_LOCK_KEY = 0x6A4D5542  # serialises bootstrap across web processes
_hasher = PasswordHasher()
# Verified against when the account does not exist, so timing does not reveal that.
_DUMMY_HASH = _hasher.hash("gamut-dummy-password-for-timing")


def normalize_email(email: str) -> str:
    return email.strip().lower()


def ensure_bootstrap_owner(settings: Settings) -> None:
    password = settings.bootstrap_admin_password
    if not settings.bootstrap_admin_email or password is None or not password.get_secret_value():
        return
    email = normalize_email(settings.bootstrap_admin_email)
    with session_scope() as db:
        advisory_xact_lock(db, BOOTSTRAP_LOCK_KEY)
        if db.scalar(select(User.id).where(func.lower(User.email) == email)) is not None:
            return
        user = User(
            email=email,
            display_name="Bootstrap admin",
            is_owner=True,
            password_hash=_hasher.hash(password.get_secret_value()),
        )
        db.add(user)
        db.flush()
        append_event(
            db, actor="system", tenant_id=None, action="auth.bootstrap_owner_created",
            target=email, details={"user_id": str(user.id)},
        )


def verify_password_login(db: Session, email: str, password: str) -> User | None:
    """The password user with this email if the password matches, else None.

    Only accounts with a password hash (the bootstrap owner) can match.
    """
    user = db.scalar(select(User).where(func.lower(User.email) == normalize_email(email)))
    stored = user.password_hash if user is not None else None
    try:
        _hasher.verify(stored or _DUMMY_HASH, password)
    except (VerificationError, InvalidHashError):
        return None
    if user is None or stored is None:
        return None
    if _hasher.check_needs_rehash(stored):
        user.password_hash = _hasher.hash(password)
    return user
