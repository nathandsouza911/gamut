# SPDX-License-Identifier: AGPL-3.0-only
"""Panel users.

GET  /api/me                      the signed-in user and their tenant roles
GET  /api/users                   (owner) every panel user
POST /api/users                   (owner) pre-register a panel user; OIDC sign-in never
                                  creates users
POST /api/users/{user_id}/disable (owner) disable a user: they can no longer sign in and
                                  all their sessions are deleted (audited as user.disable)
"""

import re
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.audit.chain import append_event
from app.auth.bootstrap import normalize_email
from app.auth.deps import current_user, require_owner
from app.db import session_scope
from app.models import Membership, Role, Tenant, User
from app.models import Session as SessionRow

router = APIRouter(prefix="/api", tags=["users"])
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def validate_email(value: str) -> str:
    email = normalize_email(value)
    if not EMAIL_RE.fullmatch(email):
        raise ValueError("not a valid email address")
    return email


class TenantRoleOut(BaseModel):
    tenant_id: uuid.UUID
    tenant_name: str
    role: Role


class MeOut(BaseModel):
    id: uuid.UUID
    email: str
    display_name: str | None
    is_owner: bool
    memberships: list[TenantRoleOut]


class UserCreate(BaseModel):
    email: str = Field(max_length=320)
    display_name: str | None = Field(default=None, max_length=200)

    _email = field_validator("email")(validate_email)


class UserOut(BaseModel):
    id: uuid.UUID
    email: str
    display_name: str | None
    is_owner: bool
    disabled: bool


def user_out(user: User) -> UserOut:
    return UserOut(id=user.id, email=user.email, display_name=user.display_name,
                   is_owner=user.is_owner, disabled=user.disabled)


def me_payload(db: Session, user: User) -> MeOut:
    rows = db.execute(
        select(Membership.tenant_id, Tenant.name, Membership.role)
        .join(Tenant, Tenant.id == Membership.tenant_id)
        .where(Membership.user_id == user.id)
        .order_by(Tenant.name)
    ).all()
    return MeOut(
        id=user.id,
        email=user.email,
        display_name=user.display_name,
        is_owner=user.is_owner,
        memberships=[TenantRoleOut(tenant_id=t, tenant_name=n, role=r) for t, n, r in rows],
    )


@router.get("/me")
def me(user: Annotated[User, Depends(current_user)]) -> MeOut:
    with session_scope() as db:
        return me_payload(db, user)


@router.post("/users", status_code=status.HTTP_201_CREATED)
def create_user(body: UserCreate, owner: Annotated[User, Depends(require_owner)]) -> UserOut:
    conflict = HTTPException(status.HTTP_409_CONFLICT, "a user with this email already exists")
    try:
        with session_scope() as db:
            if db.scalar(select(User.id).where(func.lower(User.email) == body.email)):
                raise conflict
            user = User(email=body.email, display_name=body.display_name, is_owner=False)
            db.add(user)
            db.flush()
            append_event(
                db, actor=owner.email, tenant_id=None, action="user.create",
                target=user.email, details={"user_id": str(user.id)},
            )
            db.refresh(user)
            return user_out(user)
    except IntegrityError:  # created concurrently
        raise conflict from None


@router.get("/users")
def list_users(owner: Annotated[User, Depends(require_owner)]) -> list[UserOut]:
    with session_scope() as db:
        return [user_out(u) for u in db.scalars(select(User).order_by(User.email))]


@router.post("/users/{user_id}/disable")
def disable_user(
    user_id: uuid.UUID, owner: Annotated[User, Depends(require_owner)]
) -> UserOut:
    """Disable a panel user and delete all their sessions (idempotent).

    A disabled user cannot sign in (OIDC or password) and any session they still hold
    is rejected. Memberships are kept, so the audit trail stays readable. An owner
    cannot disable themselves (409), so the panel cannot lose its last way in by mistake.
    """
    if user_id == owner.id:
        raise HTTPException(status.HTTP_409_CONFLICT, "you cannot disable your own account")
    with session_scope() as db:
        user = db.get(User, user_id, with_for_update=True)
        if user is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
        was_disabled = user.disabled
        user.disabled = True
        deleted = db.execute(delete(SessionRow).where(SessionRow.user_id == user.id))
        count = int(getattr(deleted, "rowcount", 0) or 0)
        db.flush()
        append_event(
            db, actor=owner.email, tenant_id=None, action="user.disable", target=user.email,
            details={"user_id": str(user.id), "sessions_deleted": count,
                     "already_disabled": was_disabled},
        )
        return user_out(user)
