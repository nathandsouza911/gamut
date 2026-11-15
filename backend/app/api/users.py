# SPDX-License-Identifier: AGPL-3.0-only
"""Panel users.

GET  /api/me     the signed-in user and their tenant roles
POST /api/users  (owner) pre-register a panel user; OIDC sign-in never creates users
"""

import re
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.audit.chain import append_event
from app.auth.bootstrap import normalize_email
from app.auth.deps import current_user, require_owner
from app.db import session_scope
from app.models import Membership, Role, Tenant, User

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
            return UserOut(
                id=user.id, email=user.email, display_name=user.display_name, is_owner=False
            )
    except IntegrityError:  # created concurrently
        raise conflict from None
