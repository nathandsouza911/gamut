# SPDX-License-Identifier: AGPL-3.0-only
"""Workflow previews.

POST /api/tenants/{tenant_id}/workflows/offboarding/preview   (technician or admin)
    Body: OffboardParams. Validates the parameters against the tenant and returns the
    ordered steps with their (redacted) GAM commands and a preview token. No side
    effects: no job, no GAM call, no audit event. 409 while the user has an unfinished
    offboarding or a pending deletion in this tenant (app.workflows.offboarding
    .active_offboarding); 422 for the tenant's own admin account.

The preview token is what POST /api/tenants/{tenant_id}/jobs needs to create the job:
`v1.<expiry unix seconds>.<hex HMAC-SHA256>` keyed with GAMUT_SECRET_KEY over the
workflow, tenant id, user id, expiry and the canonical (normalized) parameters. It is
valid for 10 minutes, only for the user who previewed and only with the same
parameters; it is also the job's idempotency key, so a repeated confirm returns the
same job.
"""

import hashlib
import hmac
import shlex
import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.audit.chain import canonical_json
from app.auth.deps import current_user, require_tenant_role
from app.auth.tenant_guard import TenantScopedRoute
from app.db import session_scope
from app.gam.commands import redact_argv
from app.models import Membership, Role, Tenant, TenantStatus, User
from app.settings import Settings
from app.workflows.base import StepKind, StepSpec
from app.workflows.offboarding import (
    OFFBOARDING_WORKFLOW,
    FieldError,
    Offboarding,
    OffboardParams,
    active_offboarding,
)

router = APIRouter(prefix="/api/tenants", tags=["workflows"], route_class=TenantScopedRoute)

PREVIEW_TTL = timedelta(minutes=10)
PREVIEW_SCHEME = "v1"
OPERATORS = (Role.admin, Role.technician)  # owners always pass


class PreviewStep(BaseModel):
    key: str
    title: str
    kind: StepKind
    optional: bool
    args_display: str  # the GAM command, free text redacted


class PreviewOut(BaseModel):
    preview_token: str
    expires_at: datetime
    steps: list[PreviewStep]


class PreviewTokenError(Exception):
    """The token is malformed or does not match (HTTP 400). The message is safe."""


def _now() -> datetime:
    return datetime.now(UTC)


def _mac(settings: Settings, workflow: str, params: BaseModel, tenant_id: uuid.UUID,
         user_id: uuid.UUID, expiry: int) -> str:
    if settings.secret_key is None:  # the web app refuses to start without it
        raise RuntimeError("GAMUT_SECRET_KEY is not set")
    message = "\n".join([
        "gamut-preview", PREVIEW_SCHEME, workflow, str(tenant_id), str(user_id), str(expiry),
        canonical_json(params.model_dump(mode="json")),
    ]).encode("utf-8")
    key = settings.secret_key.get_secret_value().encode("utf-8")
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def issue_preview_token(settings: Settings, workflow: str, params: BaseModel,
                        tenant_id: uuid.UUID, user_id: uuid.UUID) -> tuple[str, datetime]:
    expiry = int((_now() + PREVIEW_TTL).timestamp())
    mac = _mac(settings, workflow, params, tenant_id, user_id, expiry)
    return f"{PREVIEW_SCHEME}.{expiry}.{mac}", datetime.fromtimestamp(expiry, UTC)


def check_preview_token(settings: Settings, token: str, workflow: str, params: BaseModel,
                        tenant_id: uuid.UUID, user_id: uuid.UUID) -> bool:
    """Raise PreviewTokenError unless `token` was issued for exactly these parameters.

    Returns True when the token has expired (the caller still accepts it to return a
    job that was already created with it).
    """
    mismatch = PreviewTokenError(
        "the preview token does not match these parameters; preview the job again")
    parts = token.split(".")
    if len(parts) != 3 or parts[0] != PREVIEW_SCHEME or not parts[1].isdigit():
        raise mismatch
    expiry = int(parts[1])
    expected = _mac(settings, workflow, params, tenant_id, user_id, expiry)
    if not hmac.compare_digest(expected, parts[2]):
        raise mismatch
    return expiry < _now().timestamp()


def args_display(args: list[str]) -> str:
    return " ".join(["gam", *(shlex.quote(a) for a in redact_argv(args))])


def preview_steps(steps: list[StepSpec]) -> list[PreviewStep]:
    return [PreviewStep(key=s.key, title=s.title, kind=s.kind, optional=s.optional,
                        args_display=args_display(s.args)) for s in steps]


def field_error(exc: FieldError, *prefix: str) -> HTTPException:
    """A 422 shaped like FastAPI's validation errors, naming the field."""
    detail: list[dict[str, Any]] = [
        {"loc": ["body", *prefix, exc.field], "msg": str(exc), "type": "value_error"}
    ]
    return HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail)


def usable_tenant(db: Session, tenant_id: uuid.UUID, *, lock: bool = False) -> Tenant:
    """The tenant, 404 if it vanished since the access check, 409 if it is disabled."""
    tenant = db.get(Tenant, tenant_id, with_for_update=lock)
    if tenant is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "tenant not found")
    if tenant.status == TenantStatus.disabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "the tenant is disabled; jobs do not run")
    return tenant


@router.post("/{tenant_id}/workflows/offboarding/preview")
def preview_offboarding(
    tenant_id: uuid.UUID,
    body: OffboardParams,
    request: Request,
    membership: Annotated[Membership, Depends(require_tenant_role(*OPERATORS))],
    user: Annotated[User, Depends(current_user)],
) -> PreviewOut:
    with session_scope() as db:
        tenant = usable_tenant(db, tenant_id)
        try:
            steps = Offboarding().plan(body, tenant)
        except FieldError as exc:
            raise field_error(exc) from None
        conflict = active_offboarding(db, tenant.id, body.user)
        if conflict is not None:
            raise HTTPException(status.HTTP_409_CONFLICT, conflict)
    token, expires_at = issue_preview_token(
        request.app.state.settings, OFFBOARDING_WORKFLOW, body, tenant_id, user.id)
    return PreviewOut(preview_token=token, expires_at=expires_at, steps=preview_steps(steps))
