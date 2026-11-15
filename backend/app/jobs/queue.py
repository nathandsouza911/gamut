# SPDX-License-Identifier: AGPL-3.0-only
"""The job queue in PostgreSQL: create, claim (leases), run, retry and skip.

Life of a job:
  queued --claim_next--> running --run_steps--> succeeded | failed | waiting
  waiting --(a waiting step is due)--> claim_next --> running ...
  running with an expired lease (worker died) --claim_next--> running (steps re-run)
  failed --retry_step / skip_step--> queued

claim_next uses SELECT ... FOR UPDATE SKIP LOCKED and runs at most one job per tenant
at a time (a tenant with a running job whose lease is live is skipped). While run_job
runs a job, a heartbeat thread extends the lease every HEARTBEAT_S seconds; a worker
that dies stops renewing it and another worker reclaims the job after LEASE_S seconds.
"""

import logging
import threading
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from types import TracebackType
from typing import Any

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from sqlalchemy import and_, exists, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, aliased

from app.audit.chain import append_event, redact
from app.db import advisory_xact_lock, get_engine, session_scope
from app.gam.commands import redact_argv
from app.jobs.execute import backoff_seconds, job_actor, job_target, run_steps
from app.models import Job, JobStatus, JobStep, StepStatus, Tenant, User
from app.workflows.base import SEALED_PARAMS_KEY, StepSpec, get_workflow

__all__ = [
    "CLAIM_LOCK_KEY", "HEARTBEAT_S", "LEASE_S", "MAX_RECLAIMS", "ConflictError",
    "PlannedJob", "audit_params", "backoff_seconds", "claim_next", "create_job",
    "plan_job", "retry_step", "run_job", "skip_step",
]

log = logging.getLogger(__name__)

LEASE_S = 120
HEARTBEAT_S = 30
# A job reclaimed this many times after its worker's lease expired is failed on the
# next expiry instead of being run again (a step that crashes the worker every time).
MAX_RECLAIMS = 5
RECLAIM_LIMIT_MESSAGE = (
    "The worker running this job stopped responding {n} times in a row (its lease "
    "expired each time), so the job was stopped instead of being run again. Check the "
    "worker's logs, then retry the step."
)
# Serializes claims so that "one running job per tenant" holds between workers.
CLAIM_LOCK_KEY = 0x6A4D5143


class ConflictError(Exception):
    """The request conflicts with the current state (HTTP 409). The message is safe."""

    status_code = 409


def _now() -> datetime:
    return datetime.now(UTC)


# --- Creation ------------------------------------------------------------------------

@dataclass(frozen=True)
class PlannedJob:
    workflow: str
    params: dict[str, Any]  # validated, JSON-ready
    steps: list[StepSpec]


def plan_job(workflow_name: str, params: dict[str, Any], tenant: Tenant) -> PlannedJob:
    """Validate `params` and plan the steps (no side effects).

    Raises UnknownWorkflow, pydantic.ValidationError, or ValueError with an
    operator-readable message when the workflow cannot run for this tenant.
    """
    workflow = get_workflow(workflow_name)
    validated = workflow.params_model.model_validate(params)
    return PlannedJob(
        workflow=workflow.name,
        params=validated.model_dump(mode="json"),
        steps=workflow.plan(validated, tenant),
    )


def _existing(session: Session, tenant_id: uuid.UUID, key: str) -> Job | None:
    job = session.scalar(select(Job).where(Job.idempotency_key == key))
    if job is not None and job.tenant_id != tenant_id:
        raise ConflictError("the idempotency key is already used")
    return job


def create_job(
    session: Session,
    *,
    tenant_id: uuid.UUID,
    workflow: str,
    params: dict[str, Any],
    steps: list[StepSpec],
    actor: User | None,
    idempotency_key: str,
) -> Job:
    """Write a queued job, its steps and a `job.created` audit event.

    Everything happens in the caller's transaction (commit it, for example with
    db.session_scope), so the job, its steps and the event exist together or not at
    all. If a job with `idempotency_key` exists for this tenant it is returned instead
    (also when a concurrent request inserts it first); a key used by another tenant
    raises ConflictError. `actor` None means the system (for example the daily health
    check). `params` are re-validated by the workflow's params_model; step args are
    stored redacted.
    """
    found = _existing(session, tenant_id, idempotency_key)
    if found is not None:
        return found
    wf = get_workflow(workflow)
    job = Job(
        tenant_id=tenant_id,
        workflow=wf.name,
        params=wf.params_model.model_validate(params).model_dump(mode="json"),
        status=JobStatus.queued,
        created_by=actor.id if actor is not None else None,
        idempotency_key=idempotency_key,
    )
    try:
        with session.begin_nested():
            session.add(job)
            session.flush()
    except IntegrityError:
        found = _existing(session, tenant_id, idempotency_key)
        if found is None:
            raise
        return found
    for position, spec in enumerate(steps):
        session.add(JobStep(
            job_id=job.id,
            position=position,
            key=spec.key,
            title=spec.title,
            kind=spec.kind,
            args=redact_argv(spec.args),
            optional=spec.optional,
        ))
    session.flush()
    tenant = session.get(Tenant, tenant_id)
    append_event(
        session,
        actor=actor.email if actor is not None else "system",
        tenant_id=tenant_id,
        action="job.created",
        target=job_target(job, tenant) if tenant is not None else str(job.id),
        details={"workflow": wf.name, "job_id": str(job.id), "steps": [s.key for s in steps],
                 "params": audit_params(job.params)},
    )
    return job


def audit_params(params: dict[str, Any]) -> dict[str, Any]:
    """The stored job parameters as audited: without the sealed part, through redact().

    Stored parameters already carry "[redacted]" in place of free text (for example the
    auto-reply); redact() also blanks any secret-like key, and any list of strings is
    passed through redact_argv in case it is an argument list (password values).
    """
    def argv_safe(value: Any) -> Any:
        if isinstance(value, dict):
            return {k: argv_safe(v) for k, v in value.items()}
        if isinstance(value, list):
            if value and all(isinstance(v, str) for v in value):
                return redact_argv(value)
            return [argv_safe(v) for v in value]
        return value

    return redact(argv_safe({k: v for k, v in params.items() if k != SEALED_PARAMS_KEY}))


# --- Claiming and running ------------------------------------------------------------

def claim_next(session: Session, worker_id: str, lease_s: int = LEASE_S) -> Job | None:
    """Claim the oldest runnable job and commit; None when there is nothing to do.

    Runnable: `queued`; `waiting` with a waiting step whose next_poll_at has passed;
    `running` whose lease expired (its worker died). Rows locked by another transaction
    are skipped (FOR UPDATE SKIP LOCKED), and so are tenants that already have a running
    job with a live lease. The claimed job becomes `running` with lease_until = now +
    lease_s and a fresh claim_token (run_job fences its writes with it), and a
    `job.claimed` event records the worker and the previous status.

    A claim after an expired lease counts as a reclaim (jobs.reclaim_count). A job
    whose lease expires again after MAX_RECLAIMS reclaims is failed instead (its
    unfinished steps fail with a message, audited as job.step.failed and job.failed),
    and the next runnable job is claimed. retry_step and skip_step reset the count.
    """
    while True:
        job, again = _claim_once(session, worker_id, lease_s)
        if not again:
            return job


def _fail_crash_looping_job(session: Session, job: Job) -> None:
    """Fail a job whose worker kept dying (no GAM runs). The caller commits."""
    message = RECLAIM_LIMIT_MESSAGE.format(n=job.reclaim_count + 1)
    now = _now()
    tenant = session.get(Tenant, job.tenant_id)
    target = job_target(job, tenant) if tenant is not None else str(job.id)
    actor = job_actor(session, job)
    unfinished = session.scalars(
        select(JobStep)
        .where(JobStep.job_id == job.id,
               JobStep.status.in_((StepStatus.running, StepStatus.waiting)))
        .order_by(JobStep.position)
    )
    for step in unfinished:
        step.status = StepStatus.failed
        step.output = message
        step.next_poll_at = None
        step.finished_at = now
        session.flush()
        append_event(
            session, actor=actor, tenant_id=job.tenant_id, action="job.step.failed",
            target=target,
            details={"job_id": str(job.id), "workflow": job.workflow, "step": step.key,
                     "position": step.position, "argv": list(step.args), "exit_code": None,
                     "gam_version": job.gam_version},
        )
    job.status = JobStatus.failed
    job.finished_at = now
    job.lease_until = None
    job.claim_token = None
    session.flush()
    get_workflow(job.workflow).on_finished(session, job)
    append_event(
        session, actor=actor, tenant_id=job.tenant_id, action="job.failed", target=target,
        details={"job_id": str(job.id), "workflow": job.workflow,
                 "gam_version": job.gam_version, "reason": message},
    )
    log.warning("job %s failed after %d lease expiries", job.id, job.reclaim_count + 1)


def _claim_once(session: Session, worker_id: str, lease_s: int) -> tuple[Job | None, bool]:
    """(claimed job or None, whether to look again: a crash-looping job was failed)."""
    advisory_xact_lock(session, CLAIM_LOCK_KEY)
    now = _now()
    other = aliased(Job)
    poll_due = exists().where(
        JobStep.job_id == Job.id,
        JobStep.status == StepStatus.waiting,
        JobStep.next_poll_at <= now,
    )
    tenant_busy = exists().where(
        other.tenant_id == Job.tenant_id,
        other.id != Job.id,
        other.status == JobStatus.running,
        other.lease_until >= now,
    )
    stmt = (
        select(Job)
        .where(or_(
            Job.status == JobStatus.queued,
            and_(Job.status == JobStatus.waiting, poll_due),
            and_(Job.status == JobStatus.running,
                 or_(Job.lease_until.is_(None), Job.lease_until < now)),
        ))
        .where(~tenant_busy)
        .order_by(Job.created_at, Job.id)
        .limit(1)
        .with_for_update(skip_locked=True, of=Job)
        .execution_options(populate_existing=True)
    )
    job = session.scalar(stmt)
    if job is None:
        session.commit()
        return None, False
    previous = job.status
    if previous == JobStatus.running:  # its worker's lease expired
        if job.reclaim_count >= MAX_RECLAIMS:
            _fail_crash_looping_job(session, job)
            session.commit()
            return None, True
        job.reclaim_count += 1
    job.status = JobStatus.running
    job.lease_until = now + timedelta(seconds=lease_s)
    job.claim_token = uuid.uuid4()
    session.flush()
    tenant = session.get(Tenant, job.tenant_id)
    append_event(
        session,
        actor=job_actor(session, job),
        tenant_id=job.tenant_id,
        action="job.claimed",
        target=job_target(job, tenant) if tenant is not None else str(job.id),
        details={
            "job_id": str(job.id),
            "workflow": job.workflow,
            "worker": worker_id,
            "previous_status": previous.value,
            "lease_expired": previous == JobStatus.running,
        },
    )
    session.commit()
    log.info("worker %s claimed job %s (was %s)", worker_id, job.id, previous.value)
    return job, False


class _Heartbeat:
    """Extends a running job's lease every `interval_s` seconds from its own thread.

    Only while the job still carries `claim_token`: once another worker has claimed it
    (or the job stopped running) the heartbeat sets `lost` and stops.
    """

    def __init__(
        self, job_id: uuid.UUID, claim_token: uuid.UUID | None, lease_s: float,
        interval_s: float,
    ) -> None:
        self.job_id = job_id
        self.claim_token = claim_token
        self.lease_s = lease_s
        self.interval_s = interval_s
        self.lost = threading.Event()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="lease-heartbeat", daemon=True)

    def _run(self) -> None:
        while not self._stop.wait(self.interval_s):
            try:
                with session_scope() as session:
                    result = session.execute(
                        update(Job)
                        .where(Job.id == self.job_id, Job.status == JobStatus.running,
                               Job.claim_token == self.claim_token)
                        .values(lease_until=_now() + timedelta(seconds=self.lease_s))
                    )
                    renewed = getattr(result, "rowcount", 0)
            except Exception as exc:  # the lease is the backstop; keep trying
                log.warning("lease heartbeat failed: %s", type(exc).__name__)
                continue
            if not renewed:
                self.lost.set()
                log.info("job %s: not running under this claim; heartbeat stopped",
                         self.job_id)
                return

    def __enter__(self) -> "_Heartbeat":
        self._thread.start()
        return self

    def __exit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self._stop.set()
        self._thread.join()


def run_job(
    job: Job,
    private_key: X25519PrivateKey,
    *,
    lease_s: float = LEASE_S,
    heartbeat_s: float = HEARTBEAT_S,
) -> None:
    """Run a job returned by claim_next, in its own session, renewing its lease.

    Runs its steps through app.jobs.execute.run_steps (one materialized GAM directory
    for the whole run), fenced by the claim token the job carried when it was claimed:
    if another worker reclaims the job meanwhile, this run stops at its next write
    without writing anything, and the heartbeat stops renewing the lease. Other
    exceptions (for example the database going away) propagate; the job's lease then
    expires and another claim picks it up again.
    """
    job_id, token = job.id, job.claim_token  # as claimed, not as stored now
    with Session(get_engine(), expire_on_commit=False) as session, \
            _Heartbeat(job_id, token, lease_s, heartbeat_s):
        fresh = session.get(Job, job_id)
        if fresh is None:
            return
        run_steps(session, fresh, private_key, claim_token=token)


# --- Retry and skip ------------------------------------------------------------------

def _lock_failed(session: Session, job: Job, step: JobStep) -> tuple[Job, JobStep, Tenant]:
    locked = session.scalar(
        select(Job).where(Job.id == job.id).with_for_update()
        .execution_options(populate_existing=True)
    )
    if locked is None:
        raise ConflictError("the job no longer exists")
    locked_step = session.scalar(
        select(JobStep).where(JobStep.id == step.id, JobStep.job_id == locked.id)
        .with_for_update().execution_options(populate_existing=True)
    )
    if locked_step is None:
        raise ConflictError("the step does not belong to this job")
    if locked.status != JobStatus.failed:
        raise ConflictError("steps can be retried or skipped only when the job has failed")
    if locked_step.status != StepStatus.failed:
        raise ConflictError("only the failed step can be retried or skipped")
    tenant = session.get(Tenant, locked.tenant_id)
    if tenant is None:
        raise ConflictError("the tenant no longer exists")
    return locked, locked_step, tenant


def _requeue(
    session: Session, job: Job, step: JobStep, tenant: Tenant, actor: User, action: str
) -> None:
    job.status = JobStatus.queued
    job.finished_at = None
    job.lease_until = None
    job.reclaim_count = 0
    session.flush()
    append_event(
        session,
        actor=actor.email,
        tenant_id=job.tenant_id,
        action=action,
        target=job_target(job, tenant),
        details={
            "job_id": str(job.id), "workflow": job.workflow, "step": step.key,
            "position": step.position,
        },
    )


def retry_step(session: Session, job: Job, step: JobStep, actor: User) -> None:
    """Set a failed job's failed step back to pending and queue the job again.

    Raises ConflictError (409) unless the job and the step have failed. Audited as
    `job.step.retry`. Does not commit. Role checks are the caller's.
    """
    job, step, tenant = _lock_failed(session, job, step)
    step.status = StepStatus.pending
    step.exit_code = None
    step.output = None
    step.started_at = None
    step.finished_at = None
    step.next_poll_at = None
    step.poll_attempts = 0
    if isinstance(step.data, dict) and "quota_retries" in step.data:
        step.data = {k: v for k, v in step.data.items() if k != "quota_retries"}
    _requeue(session, job, step, tenant, actor, "job.step.retry")


def skip_step(session: Session, job: Job, step: JobStep, actor: User) -> None:
    """Mark a failed job's failed, optional step as skipped and queue the job again.

    Raises ConflictError (409) unless the job and the step have failed, or when the
    step is not optional. Audited as `job.step.skip`. Does not commit.
    """
    job, step, tenant = _lock_failed(session, job, step)
    if not step.optional:
        raise ConflictError("only optional steps can be skipped; retry this step instead")
    step.status = StepStatus.skipped
    step.finished_at = _now()
    _requeue(session, job, step, tenant, actor, "job.step.skip")
