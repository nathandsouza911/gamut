# SPDX-License-Identifier: AGPL-3.0-only
"""Tenants and memberships.

GET  /api/tenants                        tenants the user can see (owners: all)
POST /api/tenants                        (owner) add a tenant, status pending
GET  /api/tenants/{tenant_id}            any role on the tenant
POST /api/tenants/{tenant_id}/members    (owner or tenant admin) set a user's role

All routes here use TenantScopedRoute; see app/auth/tenant_guard.py.
"""

import re
import uuid
from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from app.api.users import validate_email
from app.audit.chain import append_event
from app.auth.deps import current_user, require_owner, require_tenant_role
from app.auth.tenant_guard import TenantScopedRoute
from app.db import session_scope
from app.models import Membership, Role, Tenant, TenantStatus, User

router = APIRouter(prefix="/api/tenants", tags=["tenants"], route_class=TenantScopedRoute)
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def _domain(value: str) -> str:
    domain = value.strip().lower()
    if not DOMAIN_RE.fullmatch(domain):
        raise ValueError("not a valid domain name")
    return domain


class TenantCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    primary_domain: str = Field(max_length=253)
    domains: list[str] = Field(default_factory=list, max_length=100)
    admin_email: str | None = Field(default=None, max_length=320)

    @field_validator("name")
    @classmethod
    def _name(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("name must not be blank")
        return value.strip()

    @field_validator("primary_domain")
    @classmethod
    def _primary(cls, value: str) -> str:
        return _domain(value)

    @field_validator("domains")
    @classmethod
    def _domains(cls, value: list[str]) -> list[str]:
        return [_domain(d) for d in value]

    @field_validator("admin_email")
    @classmethod
    def _admin_email(cls, value: str | None) -> str | None:
        return None if value is None else validate_email(value)


class TenantOut(BaseModel):
    id: uuid.UUID
    name: str
    primary_domain: str
    domains: list[str]
    admin_email: str | None
    status: TenantStatus
    last_health_check_at: datetime | None
    last_health_message: str | None
    created_at: datetime
    role: Role  # the caller's role on this tenant (owner for owners)


class MemberSet(BaseModel):
    email: str = Field(max_length=320)
    role: Literal["admin", "technician", "auditor"]


class MemberOut(BaseModel):
    email: str
    role: Role


def _out(tenant: Tenant, role: Role) -> TenantOut:
    return TenantOut(
        id=tenant.id,
        name=tenant.name,
        primary_domain=tenant.primary_domain,
        domains=list(tenant.domains),
        admin_email=tenant.admin_email,
        status=tenant.status,
        last_health_check_at=tenant.last_health_check_at,
        last_health_message=tenant.last_health_message,
        created_at=tenant.created_at,
        role=role,
    )


@router.get("")
def list_tenants(user: Annotated[User, Depends(current_user)]) -> list[TenantOut]:
    with session_scope() as db:
        if user.is_owner:
            tenants = db.scalars(select(Tenant).order_by(Tenant.name))
            return [_out(t, Role.owner) for t in tenants]
        rows = db.execute(
            select(Tenant, Membership.role)
            .join(Membership, Membership.tenant_id == Tenant.id)
            .where(Membership.user_id == user.id)
            .order_by(Tenant.name)
        ).all()
        return [_out(t, role) for t, role in rows]


@router.post("", status_code=status.HTTP_201_CREATED)
def create_tenant(body: TenantCreate, owner: Annotated[User, Depends(require_owner)]) -> TenantOut:
    domains = list(dict.fromkeys([body.primary_domain, *body.domains]))
    try:
        with session_scope() as db:
            tenant = Tenant(
                name=body.name,
                primary_domain=body.primary_domain,
                domains=domains,
                admin_email=body.admin_email,
                status=TenantStatus.pending,
            )
            db.add(tenant)
            db.flush()
            db.refresh(tenant)
            append_event(
                db, actor=owner.email, tenant_id=tenant.id, action="tenant.create",
                target=tenant.name,
                details={"primary_domain": tenant.primary_domain, "domains": domains},
            )
            return _out(tenant, Role.owner)
    except IntegrityError:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "a tenant with this name or primary domain already exists"
        ) from None


@router.get("/{tenant_id}")
def get_tenant(
    tenant_id: uuid.UUID, membership: Annotated[Membership, Depends(require_tenant_role())]
) -> TenantOut:
    with session_scope() as db:
        tenant = db.get(Tenant, tenant_id)
        if tenant is None:  # deleted since the access check
            raise HTTPException(status.HTTP_404_NOT_FOUND, "tenant not found")
        return _out(tenant, membership.role)


@router.post("/{tenant_id}/members")
def set_member(
    tenant_id: uuid.UUID,
    body: MemberSet,
    response: Response,
    membership: Annotated[Membership, Depends(require_tenant_role(Role.admin))],
    actor: Annotated[User, Depends(current_user)],
) -> MemberOut:
    email = body.email.strip().lower()
    role = Role(body.role)
    with session_scope() as db:
        user = db.scalar(select(User).where(func.lower(User.email) == email))
        if user is None:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_CONTENT,
                "no panel user has that email; an owner must add them first (POST /api/users)",
            )
        if user.is_owner:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_CONTENT, "owners already have access to every tenant"
            )
        existing = db.scalar(
            select(Membership)
            .where(Membership.user_id == user.id, Membership.tenant_id == tenant_id)
            .with_for_update()
        )
        previous = existing.role if existing is not None else None
        if existing is None:
            db.add(Membership(user_id=user.id, tenant_id=tenant_id, role=role))
            response.status_code = status.HTTP_201_CREATED
        else:
            existing.role = role
        db.flush()
        append_event(
            db, actor=actor.email, tenant_id=tenant_id, action="membership.set",
            target=user.email,
            details={
                "user_id": str(user.id),
                "role": role.value,
                "previous_role": None if previous is None else previous.value,
            },
        )
        return MemberOut(email=user.email, role=role)
