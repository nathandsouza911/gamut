# SPDX-License-Identifier: AGPL-3.0-only
"""Audit log reading and chain verification.

GET /api/tenants/{tenant_id}/audit?cursor=&limit=   auditor or above; newest first
    -> {items: [...], next_cursor: int | null}; pass next_cursor back as `cursor`
GET /api/audit/verify                                owner; walks the whole chain
GET /api/meta                                        public: source URL and version
"""

import uuid
from datetime import datetime
from importlib.metadata import PackageNotFoundError, version
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel
from sqlalchemy import select

from app.audit.chain import verify_chain
from app.auth.deps import require_owner, require_tenant_role
from app.auth.tenant_guard import TenantScopedRoute
from app.db import session_scope
from app.models import AuditEvent, Membership, Role, User

router = APIRouter(prefix="/api/tenants", tags=["audit"], route_class=TenantScopedRoute)
global_router = APIRouter(prefix="/api", tags=["audit"])
READERS = (Role.admin, Role.technician, Role.auditor)


class AuditEventOut(BaseModel):
    id: int
    time: datetime
    actor: str
    action: str
    target: str | None
    details: dict[str, Any]


class AuditPage(BaseModel):
    items: list[AuditEventOut]
    next_cursor: int | None


class VerifyOut(BaseModel):
    ok: bool
    checked: int
    first_broken_id: int | None
    reason: str | None


class MetaOut(BaseModel):
    source_url: str
    version: str


@router.get("/{tenant_id}/audit")
def list_audit(
    tenant_id: uuid.UUID,
    membership: Annotated[Membership, Depends(require_tenant_role(*READERS))],
    cursor: Annotated[int | None, Query(ge=1)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> AuditPage:
    with session_scope() as db:
        query = select(AuditEvent).where(AuditEvent.tenant_id == tenant_id)
        if cursor is not None:
            query = query.where(AuditEvent.id < cursor)
        rows = list(db.scalars(query.order_by(AuditEvent.id.desc()).limit(limit + 1)))
        page = rows[:limit]
        return AuditPage(
            items=[AuditEventOut(id=e.id, time=e.time, actor=e.actor, action=e.action,
                                 target=e.target, details=e.details) for e in page],
            next_cursor=page[-1].id if len(rows) > limit else None,
        )


@global_router.get("/audit/verify")
def verify_audit(owner: Annotated[User, Depends(require_owner)]) -> VerifyOut:
    with session_scope() as db:
        result = verify_chain(db)
        return VerifyOut(ok=result.ok, checked=result.checked,
                         first_broken_id=result.first_broken_id, reason=result.reason)


@global_router.get("/meta")
def meta(request: Request) -> MetaOut:
    try:
        ver = version("gamut")
    except PackageNotFoundError:  # pragma: no cover - not installed
        ver = "0.0.0"
    return MetaOut(source_url=request.app.state.settings.source_url, version=ver)
