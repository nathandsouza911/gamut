# SPDX-License-Identifier: AGPL-3.0-only
"""Tenants, memberships, credentials and health checks.

GET    /api/tenants                               tenants the user can see (owners: all)
POST   /api/tenants                               (owner) add a tenant, status pending
GET    /api/tenants/{tenant_id}                   any role on the tenant
PATCH  /api/tenants/{tenant_id}                   (owner) set admin_email and/or domains
DELETE /api/tenants/{tenant_id}                   (owner) delete it; audit events stay
GET    /api/tenants/{tenant_id}/members           (owner or tenant admin) list members
POST   /api/tenants/{tenant_id}/members           (owner or tenant admin) set a user's role
DELETE /api/tenants/{tenant_id}/members/{user_id} (owner or tenant admin) remove a role
PUT    /api/tenants/{tenant_id}/credentials       (owner) upload or replace the GAM files
DELETE /api/tenants/{tenant_id}/credentials       (owner) delete the stored GAM files
POST   /api/tenants/{tenant_id}/health-check      (owner or tenant admin) queue a check
                                                   (or return the one still active)

Credential contents are never returned: responses carry file names only.
All routes here use TenantScopedRoute; see app/auth/tenant_guard.py.
"""

import re
import uuid
from datetime import datetime
from typing import Annotated, Literal

from fastapi import (
    APIRouter,
    Depends,
    File,
    HTTPException,
    Request,
    Response,
    UploadFile,
    status,
)
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.users import validate_email
from app.audit.chain import append_event
from app.auth.deps import current_user, require_owner, require_tenant_role
from app.auth.ratelimit import JOB_CREATE_LIMIT, rate_limit
from app.auth.tenant_guard import TenantScopedRoute
from app.db import session_scope
from app.gam.validate import Email, assert_in_tenant
from app.jobs.queue import create_job, plan_job
from app.models import Job, JobStatus, Membership, Role, Tenant, TenantStatus, User
from app.tenants.service import (
    ALLOWED_FILES,
    MAX_FILE_BYTES,
    CredentialError,
    credential_summaries,
    delete_credentials,
    delete_tenant,
    store_credentials,
)
from app.workflows.health import HEALTH_WORKFLOW

router = APIRouter(prefix="/api/tenants", tags=["tenants"], route_class=TenantScopedRoute)
_ACTIVE_JOB = (JobStatus.queued, JobStatus.running, JobStatus.waiting)
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


class TenantUpdate(BaseModel):
    # The account used for the service account check; must be in the tenant's domains.
    admin_email: str | None = Field(default=None, max_length=320)
    # Replaces the extra domains; the primary domain is always kept.
    domains: list[str] | None = Field(default=None, max_length=100)

    @field_validator("domains")
    @classmethod
    def _domains(cls, value: list[str] | None) -> list[str] | None:
        return None if value is None else [_domain(d) for d in value]

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
    has_credentials: bool
    credential_files: list[str]  # names only; contents are never returned
    credentials_uploaded_at: datetime | None


class MemberSet(BaseModel):
    email: str = Field(max_length=320)
    role: Literal["admin", "technician", "auditor"]


class MemberOut(BaseModel):
    email: str
    role: Role


class CredentialsOut(BaseModel):
    file_names: list[str]
    uploaded_at: datetime
    health_job_id: uuid.UUID | None  # the health check queued after the upload, if any


class JobCreated(BaseModel):
    job_id: uuid.UUID


Credentials = tuple[list[str], datetime] | None


def _out(tenant: Tenant, role: Role, creds: Credentials = None) -> TenantOut:
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
        has_credentials=creds is not None,
        credential_files=list(creds[0]) if creds else [],
        credentials_uploaded_at=creds[1] if creds else None,
    )


def _out_with_credentials(db: Session, tenant: Tenant, role: Role) -> TenantOut:
    return _out(tenant, role, credential_summaries(db, [tenant.id]).get(tenant.id))


def _tenant_or_404(db: Session, tenant_id: uuid.UUID, *, lock: bool = False) -> Tenant:
    tenant = db.get(Tenant, tenant_id, with_for_update=lock)
    if tenant is None:  # deleted since the access check
        raise HTTPException(status.HTTP_404_NOT_FOUND, "tenant not found")
    return tenant


@router.get("")
def list_tenants(user: Annotated[User, Depends(current_user)]) -> list[TenantOut]:
    with session_scope() as db:
        rows: list[tuple[Tenant, Role]]
        if user.is_owner:
            rows = [(t, Role.owner) for t in db.scalars(select(Tenant).order_by(Tenant.name))]
        else:
            rows = [
                (t, role)
                for t, role in db.execute(
                    select(Tenant, Membership.role)
                    .join(Membership, Membership.tenant_id == Tenant.id)
                    .where(Membership.user_id == user.id)
                    .order_by(Tenant.name)
                ).all()
            ]
        creds = credential_summaries(db, [t.id for t, _ in rows])
        return [_out(t, role, creds.get(t.id)) for t, role in rows]


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
        return _out_with_credentials(db, _tenant_or_404(db, tenant_id), membership.role)


@router.patch("/{tenant_id}")
def update_tenant(
    tenant_id: uuid.UUID, body: TenantUpdate, owner: Annotated[User, Depends(require_owner)]
) -> TenantOut:
    with session_scope() as db:
        tenant = _tenant_or_404(db, tenant_id, lock=True)
        changes: dict[str, object] = {}
        if body.domains is not None:
            domains = list(dict.fromkeys([tenant.primary_domain, *body.domains]))
            tenant.domains = domains
            changes["domains"] = domains
        if "admin_email" in body.model_fields_set:
            tenant.admin_email = body.admin_email
            changes["admin_email"] = body.admin_email
        if tenant.admin_email:
            try:
                assert_in_tenant(Email(tenant.admin_email), tenant.domains)
            except ValueError:
                raise HTTPException(
                    status.HTTP_422_UNPROCESSABLE_CONTENT,
                    "admin_email must be in one of the tenant's domains",
                ) from None
        db.flush()
        append_event(
            db, actor=owner.email, tenant_id=tenant.id, action="tenant.update",
            target=tenant.name, details=changes,
        )
        return _out_with_credentials(db, tenant, Role.owner)


@router.delete("/{tenant_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_tenant(tenant_id: uuid.UUID, owner: Annotated[User, Depends(require_owner)]) -> None:
    with session_scope() as db:
        delete_tenant(db, _tenant_or_404(db, tenant_id, lock=True), actor=owner.email)


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
        try:
            db.flush()
        except IntegrityError:
            # A concurrent request created the same membership first.
            raise HTTPException(
                status.HTTP_409_CONFLICT, "the membership changed concurrently; try again"
            ) from None
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


class MemberRow(BaseModel):
    user_id: uuid.UUID
    email: str
    display_name: str | None
    role: Role
    disabled: bool


@router.get("/{tenant_id}/members")
def list_members(
    tenant_id: uuid.UUID,
    membership: Annotated[Membership, Depends(require_tenant_role(Role.admin))],
) -> list[MemberRow]:
    """The tenant's members (owners are not members: they reach every tenant)."""
    with session_scope() as db:
        rows = db.execute(
            select(User, Membership.role)
            .join(Membership, Membership.user_id == User.id)
            .where(Membership.tenant_id == tenant_id)
            .order_by(User.email)
        ).all()
        return [MemberRow(user_id=u.id, email=u.email, display_name=u.display_name, role=r,
                          disabled=u.disabled) for u, r in rows]


@router.delete("/{tenant_id}/members/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_member(
    tenant_id: uuid.UUID,
    user_id: uuid.UUID,
    membership: Annotated[Membership, Depends(require_tenant_role(Role.admin))],
    actor: Annotated[User, Depends(current_user)],
) -> None:
    """Remove a user's role on this tenant (404 if they have none here). Audited as
    membership.remove. The user's sessions stay valid, but every request re-checks the
    membership, so the tenant is a 404 for them from the next request on."""
    with session_scope() as db:
        row = db.scalar(
            select(Membership)
            .where(Membership.user_id == user_id, Membership.tenant_id == tenant_id)
            .with_for_update()
        )
        if row is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "membership not found")
        user = db.get(User, user_id)
        previous = row.role
        db.delete(row)
        db.flush()
        append_event(
            db, actor=actor.email, tenant_id=tenant_id, action="membership.remove",
            target=user.email if user is not None else str(user_id),
            details={"user_id": str(user_id), "previous_role": previous.value},
        )


def _queue_health_check(db: Session, tenant: Tenant, user: User) -> Job:
    """Raises 409 for a disabled tenant and 422 when the check cannot be planned."""
    if tenant.status == TenantStatus.disabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "disabled tenants are not health-checked")
    try:
        planned = plan_job(HEALTH_WORKFLOW, {}, tenant)
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from None
    return create_job(
        db, tenant_id=tenant.id, workflow=planned.workflow, params=planned.params,
        steps=planned.steps, actor=user, idempotency_key=f"health:{uuid.uuid4()}",
    )


@router.put("/{tenant_id}/credentials")
def put_credentials(
    tenant_id: uuid.UUID,
    request: Request,
    files: Annotated[list[UploadFile], File(description="oauth2.txt, oauth2service.json, ...")],
    owner: Annotated[User, Depends(require_owner)],
) -> CredentialsOut:
    if len(files) > len(ALLOWED_FILES):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            f"too many files; upload only {', '.join(ALLOWED_FILES)}",
        )
    contents: dict[str, bytes] = {}
    for upload in files:
        name = upload.filename or ""
        if name in contents:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_CONTENT,
                f"{name if name in ALLOWED_FILES else 'a file'} was uploaded more than once",
            )
        # One byte past the cap is enough to detect an oversize file.
        contents[name] = upload.file.read(MAX_FILE_BYTES + 1)
    public_key = request.app.state.credential_public_key
    with session_scope() as db:
        tenant = _tenant_or_404(db, tenant_id, lock=True)
        try:
            row = store_credentials(
                db, tenant, contents, public_key, actor=owner.email, actor_id=owner.id
            )
        except CredentialError as exc:
            code = (
                status.HTTP_413_CONTENT_TOO_LARGE
                if exc.too_large
                else status.HTTP_422_UNPROCESSABLE_CONTENT
            )
            raise HTTPException(code, str(exc)) from None
        # Import flow: a health check follows every upload (when it can be planned).
        health_job_id: uuid.UUID | None = None
        if tenant.status != TenantStatus.disabled and tenant.admin_email:
            try:
                planned = plan_job(HEALTH_WORKFLOW, {}, tenant)
            except ValueError:
                planned = None
            if planned is not None:
                health_job_id = create_job(
                    db, tenant_id=tenant.id, workflow=planned.workflow, params=planned.params,
                    steps=planned.steps, actor=owner,
                    idempotency_key=f"health-upload:{tenant.id}:{row.uploaded_at.isoformat()}",
                ).id
        return CredentialsOut(
            file_names=list(row.file_names),
            uploaded_at=row.uploaded_at,
            health_job_id=health_job_id,
        )


@router.delete("/{tenant_id}/credentials", status_code=status.HTTP_204_NO_CONTENT)
def remove_credentials(
    tenant_id: uuid.UUID, owner: Annotated[User, Depends(require_owner)]
) -> None:
    with session_scope() as db:
        tenant = _tenant_or_404(db, tenant_id, lock=True)
        if not delete_credentials(db, tenant, actor=owner.email):
            raise HTTPException(status.HTTP_404_NOT_FOUND, "the tenant has no stored credentials")


@router.post(
    "/{tenant_id}/health-check",
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(rate_limit("job_create", *JOB_CREATE_LIMIT, per="user"))],
)
def request_health_check(
    tenant_id: uuid.UUID,
    membership: Annotated[Membership, Depends(require_tenant_role(Role.admin))],
    user: Annotated[User, Depends(current_user)],
) -> JobCreated:
    """A check that is still queued, running or waiting is returned instead of a new one,
    so a double-click queues one check. The tenant row lock serializes the decision."""
    with session_scope() as db:
        tenant = _tenant_or_404(db, tenant_id, lock=True)
        if tenant.status != TenantStatus.disabled:
            active = db.scalar(
                select(Job.id)
                .where(Job.tenant_id == tenant.id, Job.workflow == HEALTH_WORKFLOW,
                       Job.status.in_(_ACTIVE_JOB))
                .order_by(Job.created_at.desc())
                .limit(1)
            )
            if active is not None:
                return JobCreated(job_id=active)
        job = _queue_health_check(db, tenant, user)
        return JobCreated(job_id=job.id)
