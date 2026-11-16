# SPDX-License-Identifier: AGPL-3.0-only
"""The tenant dashboard: one read-only call with everything the page shows.

GET /api/tenants/{tenant_id}/dashboard    any role

Credential contents are never returned (names and non-secret identifiers only).
"""

import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.jobs import READERS, JobSummary, ScheduledActionOut, _action_out, _summary
from app.api.tenants import TenantOut, _out_with_credentials
from app.auth.deps import require_tenant_role
from app.auth.tenant_guard import TenantScopedRoute
from app.db import session_scope
from app.models import (
    AuthMode,
    Job,
    JobStatus,
    JobStep,
    Membership,
    ScheduledAction,
    ScheduledStatus,
    StepStatus,
    Tenant,
    TenantCredential,
    User,
)
from app.workflows.health import HEALTH_WORKFLOW, SETUP_SECTION

router = APIRouter(prefix="/api/tenants", tags=["dashboard"], route_class=TenantScopedRoute)
ROTATE_AFTER_DAYS = 90
FAILED_LIMIT = 10
RECENT_LIMIT = 10
SCHEDULED_LIMIT = 20


class HealthCheckOut(BaseModel):
    key: str
    title: str
    status: StepStatus
    exit_code: int | None
    section: str | None  # the setup section to open for this check


class HealthOut(BaseModel):
    job_id: uuid.UUID
    finished_at: datetime | None
    ok: bool
    checks: list[HealthCheckOut]


class CredentialOut(BaseModel):
    auth_mode: AuthMode
    file_names: list[str]
    uploaded_at: datetime
    age_days: int
    rotate_soon: bool
    sa_client_email: str | None
    sa_client_id: str | None


class WaitingJob(JobSummary):
    waiting_since: datetime | None


class DashboardOut(BaseModel):
    tenant: TenantOut
    health: HealthOut | None
    credentials: CredentialOut | None
    failed_jobs: list[JobSummary]
    waiting_jobs: list[WaitingJob]
    scheduled: list[ScheduledActionOut]
    recent_jobs: list[JobSummary]


def _jobs_with_creator(db: Session, tenant_id: uuid.UUID, *conditions: object,
                       order: tuple[object, ...], limit: int | None = None
                       ) -> list[tuple[Job, str | None]]:
    stmt = (
        select(Job, User.email)
        .outerjoin(User, User.id == Job.created_by)
        .where(Job.tenant_id == tenant_id, *conditions)  # type: ignore[arg-type]
        .order_by(*order)  # type: ignore[arg-type]
    )
    if limit is not None:
        stmt = stmt.limit(limit)
    return [(job, email) for job, email in db.execute(stmt).all()]


def _health(db: Session, tenant_id: uuid.UUID) -> HealthOut | None:
    job = db.scalar(
        select(Job)
        .where(Job.tenant_id == tenant_id, Job.workflow == HEALTH_WORKFLOW,
               Job.status.in_((JobStatus.succeeded, JobStatus.failed)))
        .order_by(Job.finished_at.desc().nulls_last(), Job.created_at.desc())
        .limit(1)
    )
    if job is None:
        return None
    steps = db.scalars(select(JobStep).where(JobStep.job_id == job.id).order_by(JobStep.position))
    return HealthOut(
        job_id=job.id, finished_at=job.finished_at, ok=job.status == JobStatus.succeeded,
        checks=[HealthCheckOut(key=s.key, title=s.title, status=s.status, exit_code=s.exit_code,
                               section=SETUP_SECTION.get(s.key)) for s in steps],
    )


def _credentials(db: Session, tenant: Tenant) -> CredentialOut | None:
    row = db.get(TenantCredential, tenant.id)
    if row is None:
        return None
    age = max((datetime.now(UTC) - row.uploaded_at).days, 0)
    return CredentialOut(
        auth_mode=tenant.auth_mode, file_names=list(row.file_names),
        uploaded_at=row.uploaded_at, age_days=age, rotate_soon=age >= ROTATE_AFTER_DAYS,
        sa_client_email=row.sa_client_email, sa_client_id=row.sa_client_id,
    )


def _waiting(db: Session, tenant_id: uuid.UUID) -> list[WaitingJob]:
    rows = _jobs_with_creator(db, tenant_id, Job.status == JobStatus.waiting,
                              order=(Job.created_at, Job.id))
    since: dict[uuid.UUID, datetime | None] = {}
    if rows:
        since = {jid: ts for jid, ts in db.execute(
            select(JobStep.job_id, func.min(JobStep.started_at))
            .where(JobStep.job_id.in_([j.id for j, _ in rows]),
                   JobStep.status == StepStatus.waiting, JobStep.started_at.is_not(None))
            .group_by(JobStep.job_id)
        ).all()}
    out = [WaitingJob(**_summary(j, email).model_dump(),
                      waiting_since=since.get(j.id, j.started_at)) for j, email in rows]
    return sorted(out, key=lambda w: (w.waiting_since is None, w.waiting_since))


@router.get("/{tenant_id}/dashboard")
def get_dashboard(
    tenant_id: uuid.UUID,
    membership: Annotated[Membership, Depends(require_tenant_role(*READERS))],
) -> DashboardOut:
    with session_scope() as db:
        tenant = db.get(Tenant, tenant_id)
        if tenant is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "tenant not found")
        failed = _jobs_with_creator(
            db, tenant_id, Job.status == JobStatus.failed, Job.workflow != HEALTH_WORKFLOW,
            order=(Job.created_at.desc(), Job.id), limit=FAILED_LIMIT)
        recent = _jobs_with_creator(db, tenant_id, order=(Job.created_at.desc(), Job.id),
                                    limit=RECENT_LIMIT)
        scheduled = db.scalars(
            select(ScheduledAction)
            .where(ScheduledAction.tenant_id == tenant_id,
                   ScheduledAction.status == ScheduledStatus.scheduled)
            .order_by(ScheduledAction.run_at, ScheduledAction.id).limit(SCHEDULED_LIMIT)
        )
        return DashboardOut(
            tenant=_out_with_credentials(db, tenant, membership.role),
            health=_health(db, tenant_id),
            credentials=_credentials(db, tenant),
            failed_jobs=[_summary(j, e) for j, e in failed],
            waiting_jobs=_waiting(db, tenant_id),
            scheduled=[_action_out(a) for a in scheduled],
            recent_jobs=[_summary(j, e) for j, e in recent],
        )
