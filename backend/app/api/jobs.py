# SPDX-License-Identifier: AGPL-3.0-only
"""Jobs and scheduled actions of a tenant.

POST /api/tenants/{tenant_id}/jobs                                   technician or admin
     {workflow: "offboarding", params, preview_token} -> 201 JobOut (200 with the same
     job when the token was already used: double-click or browser retry)
GET  /api/tenants/{tenant_id}/jobs?limit=&offset=                    any role
GET  /api/tenants/{tenant_id}/jobs/{job_id}                          any role
POST /api/tenants/{tenant_id}/jobs/{job_id}/steps/{step_id}/retry    technician or admin
POST /api/tenants/{tenant_id}/jobs/{job_id}/steps/{step_id}/skip     technician or admin
POST /api/tenants/{tenant_id}/scheduled-actions/{action_id}/cancel   technician or admin

Owners pass every role check. Ids that do not belong to the tenant are 404.
Stored parameters are returned without the sealed part; free text is already redacted.
"""

import uuid
from datetime import datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.workflows import (
    OPERATORS,
    PreviewTokenError,
    check_preview_token,
    field_error,
    usable_tenant,
)
from app.auth.deps import current_user, require_tenant_role
from app.auth.ratelimit import JOB_CREATE_LIMIT, rate_limit
from app.auth.tenant_guard import TenantScopedRoute
from app.db import session_scope
from app.jobs.queue import ConflictError, create_job, plan_job, retry_step, skip_step
from app.jobs.scheduled import ScheduledActionNotFound, cancel_scheduled_action
from app.models import (
    Job,
    JobStatus,
    JobStep,
    Membership,
    Role,
    ScheduledAction,
    ScheduledStatus,
    StepStatus,
    User,
)
from app.workflows.base import SEALED_PARAMS_KEY
from app.workflows.offboarding import FieldError, OffboardParams, stored_params

router = APIRouter(prefix="/api/tenants", tags=["jobs"], route_class=TenantScopedRoute)
READERS = (Role.admin, Role.technician, Role.auditor)


class JobCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    workflow: Literal["offboarding"]
    params: OffboardParams
    preview_token: str = Field(min_length=1, max_length=200)


class StepOut(BaseModel):
    id: uuid.UUID
    position: int
    key: str
    title: str
    kind: str
    optional: bool
    status: StepStatus
    args: list[str]  # redacted
    exit_code: int | None
    output: str | None  # capped and scrubbed
    data: dict[str, Any]
    next_poll_at: datetime | None
    poll_attempts: int
    started_at: datetime | None
    finished_at: datetime | None


class ScheduledActionOut(BaseModel):
    id: uuid.UUID
    job_id: uuid.UUID
    action: str
    target: str | None
    run_at: datetime
    status: ScheduledStatus
    result: str | None
    created_at: datetime


class JobSummary(BaseModel):
    id: uuid.UUID
    workflow: str
    status: JobStatus
    target: str | None
    created_by: str | None  # the creator's email; None for system jobs
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None


class JobOut(JobSummary):
    tenant_id: uuid.UUID
    params: dict[str, Any]
    gam_version: str | None
    steps: list[StepOut]
    scheduled_actions: list[ScheduledActionOut]


def _target(params: Any) -> str | None:
    value = params.get("target") if isinstance(params, dict) else None
    return str(value) if value else None


def _summary(job: Job, creator: str | None) -> JobSummary:
    return JobSummary(
        id=job.id, workflow=job.workflow, status=job.status, target=_target(job.params),
        created_by=creator, created_at=job.created_at, started_at=job.started_at,
        finished_at=job.finished_at,
    )


def _action_out(row: ScheduledAction) -> ScheduledActionOut:
    return ScheduledActionOut(
        id=row.id, job_id=row.job_id, action=row.action, target=_target(row.params),
        run_at=row.run_at, status=row.status, result=row.result, created_at=row.created_at,
    )


def job_out(db: Session, job: Job) -> JobOut:
    db.flush()
    db.refresh(job)
    creator = db.get(User, job.created_by) if job.created_by is not None else None
    steps = db.scalars(
        select(JobStep).where(JobStep.job_id == job.id).order_by(JobStep.position)
        .execution_options(populate_existing=True)
    )
    actions = db.scalars(
        select(ScheduledAction).where(ScheduledAction.job_id == job.id)
        .order_by(ScheduledAction.created_at, ScheduledAction.id)
        .execution_options(populate_existing=True)
    )
    params = {k: v for k, v in (job.params or {}).items() if k != SEALED_PARAMS_KEY}
    return JobOut(
        **_summary(job, creator.email if creator else None).model_dump(),
        tenant_id=job.tenant_id, params=params, gam_version=job.gam_version,
        steps=[StepOut.model_validate(s, from_attributes=True) for s in steps],
        scheduled_actions=[_action_out(a) for a in actions],
    )


def _job_or_404(db: Session, tenant_id: uuid.UUID, job_id: uuid.UUID) -> Job:
    job = db.scalar(select(Job).where(Job.id == job_id, Job.tenant_id == tenant_id))
    if job is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "job not found")
    return job


def _step_or_404(db: Session, job: Job, step_id: uuid.UUID) -> JobStep:
    step = db.scalar(select(JobStep).where(JobStep.id == step_id, JobStep.job_id == job.id))
    if step is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "step not found")
    return step


@router.post(
    "/{tenant_id}/jobs",
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(rate_limit("job_create", *JOB_CREATE_LIMIT, per="user"))],
)
def create_workflow_job(
    tenant_id: uuid.UUID,
    body: JobCreate,
    request: Request,
    response: Response,
    membership: Annotated[Membership, Depends(require_tenant_role(*OPERATORS))],
    user: Annotated[User, Depends(current_user)],
) -> JobOut:
    try:
        expired = check_preview_token(request.app.state.settings, body.preview_token,
                                      body.workflow, body.params, tenant_id, user.id)
    except PreviewTokenError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from None
    key = body.preview_token
    with session_scope() as db:
        existing = db.scalar(select(Job).where(Job.idempotency_key == key,
                                               Job.tenant_id == tenant_id))
        if existing is not None:
            response.status_code = status.HTTP_200_OK
            return job_out(db, existing)
        if expired:
            raise HTTPException(status.HTTP_400_BAD_REQUEST,
                                "the preview has expired; preview the job again")
        tenant = usable_tenant(db, tenant_id)
        params = stored_params(body.params, request.app.state.credential_public_key, tenant.id)
        try:
            planned = plan_job(body.workflow, params, tenant)
        except FieldError as exc:
            raise field_error(exc, "params") from None
        try:
            job = create_job(
                db, tenant_id=tenant.id, workflow=planned.workflow, params=planned.params,
                steps=planned.steps, actor=user, idempotency_key=key,
            )
        except ConflictError as exc:
            raise HTTPException(exc.status_code, str(exc)) from None
        return job_out(db, job)


@router.get("/{tenant_id}/jobs")
def list_jobs(
    tenant_id: uuid.UUID,
    membership: Annotated[Membership, Depends(require_tenant_role(*READERS))],
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[JobSummary]:
    """Newest first."""
    with session_scope() as db:
        rows = db.execute(
            select(Job, User.email)
            .outerjoin(User, User.id == Job.created_by)
            .where(Job.tenant_id == tenant_id)
            .order_by(Job.created_at.desc(), Job.id)
            .limit(limit).offset(offset)
        ).all()
        return [_summary(job, email) for job, email in rows]


@router.get("/{tenant_id}/jobs/{job_id}")
def get_job(
    tenant_id: uuid.UUID,
    job_id: uuid.UUID,
    membership: Annotated[Membership, Depends(require_tenant_role(*READERS))],
) -> JobOut:
    with session_scope() as db:
        return job_out(db, _job_or_404(db, tenant_id, job_id))


@router.post("/{tenant_id}/jobs/{job_id}/steps/{step_id}/retry")
def retry_job_step(
    tenant_id: uuid.UUID,
    job_id: uuid.UUID,
    step_id: uuid.UUID,
    membership: Annotated[Membership, Depends(require_tenant_role(*OPERATORS))],
    user: Annotated[User, Depends(current_user)],
) -> JobOut:
    with session_scope() as db:
        job = _job_or_404(db, tenant_id, job_id)
        try:
            retry_step(db, job, _step_or_404(db, job, step_id), user)
        except ConflictError as exc:
            raise HTTPException(exc.status_code, str(exc)) from None
        return job_out(db, job)


@router.post("/{tenant_id}/jobs/{job_id}/steps/{step_id}/skip")
def skip_job_step(
    tenant_id: uuid.UUID,
    job_id: uuid.UUID,
    step_id: uuid.UUID,
    membership: Annotated[Membership, Depends(require_tenant_role(*OPERATORS))],
    user: Annotated[User, Depends(current_user)],
) -> JobOut:
    with session_scope() as db:
        job = _job_or_404(db, tenant_id, job_id)
        try:
            skip_step(db, job, _step_or_404(db, job, step_id), user)
        except ConflictError as exc:
            raise HTTPException(exc.status_code, str(exc)) from None
        return job_out(db, job)


@router.post("/{tenant_id}/scheduled-actions/{action_id}/cancel")
def cancel_action(
    tenant_id: uuid.UUID,
    action_id: uuid.UUID,
    membership: Annotated[Membership, Depends(require_tenant_role(*OPERATORS))],
    user: Annotated[User, Depends(current_user)],
) -> ScheduledActionOut:
    with session_scope() as db:
        try:
            row = cancel_scheduled_action(db, tenant_id=tenant_id, action_id=action_id,
                                          actor=user.email)
        except ScheduledActionNotFound:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "scheduled action not found") from None
        except ConflictError as exc:
            raise HTTPException(exc.status_code, str(exc)) from None
        return _action_out(row)
