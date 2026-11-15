# SPDX-License-Identifier: AGPL-3.0-only
"""Final-review hardening: NUL bytes in GAM output, the lease-reclaim cap and bounded
retries of scheduled actions on Google quota errors."""

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit.chain import verify_chain
from app.gam.runner import run_gam
from app.jobs.execute import MAX_QUOTA_RETRIES, run_steps, scrub
from app.jobs.queue import MAX_RECLAIMS, claim_next, retry_step
from app.jobs.scheduled import run_due_actions
from app.models import (
    AuditEvent,
    Job,
    JobStatus,
    JobStep,
    ScheduledStatus,
    StepStatus,
    Tenant,
    User,
)
from tests.test_worker import _job, _sa, _schedule, echo_action  # noqa: F401

Keys = tuple[X25519PrivateKey, str]
QUOTA_STDERR = "ERROR: 403: rateLimitExceeded - Rate Limit Exceeded\n"


def _steps(session: Session, job: Job) -> list[JobStep]:
    session.expire_all()
    return list(session.scalars(
        select(JobStep).where(JobStep.job_id == job.id).order_by(JobStep.position)))


def _reload(session: Session, job: Job) -> Job:
    session.expire_all()
    fresh = session.get(Job, job.id)
    assert fresh is not None
    return fresh


def _events(session: Session, action: str) -> list[AuditEvent]:
    session.expire_all()
    return list(session.scalars(
        select(AuditEvent).where(AuditEvent.action == action).order_by(AuditEvent.id)))


# --- NUL bytes ------------------------------------------------------------------------

def test_runner_strips_nul_bytes(fake_gam: Any, job_dir: Path) -> None:
    fake_gam.scenario([{"match": ["info"], "stdout": "a\u0000b", "stderr": "c\u0000d"}])
    result = run_gam(["info", "domain"], job_dir)
    assert result.stdout == "ab" and result.stderr == "cd"


def test_scrub_strips_nul_bytes() -> None:
    assert scrub("x\x00y\x00", []) == "xy"


def test_nul_bytes_in_gam_output_do_not_break_storage(
    app_session: Session, make_ready_tenant: Callable[..., Tenant], fake_gam: Any,
    job_dir: Path, credential_keys: Keys,
) -> None:
    tenant = make_ready_tenant()
    fake_gam.scenario([{"match": ["info"], "stdout": "before\u0000after\n"}])
    job = _job(app_session, tenant, {"key": "a", "args": ["info", "a"]})
    run_steps(app_session, job, credential_keys[0])
    (step,) = _steps(app_session, job)
    assert step.status == StepStatus.succeeded
    assert step.output is not None and "\x00" not in step.output
    assert "beforeafter" in step.output
    assert _reload(app_session, job).status == JobStatus.succeeded


# --- Reclaim cap ----------------------------------------------------------------------

def _expire(session: Session, job: Job, *, reclaims: int) -> None:
    steps = _steps(session, job)
    fresh = _reload(session, job)
    fresh.status = JobStatus.running
    fresh.lease_until = datetime.now(UTC) - timedelta(seconds=5)
    fresh.reclaim_count = reclaims
    for step in steps:
        step.status = StepStatus.running
    session.commit()


def test_reclaims_are_counted(
    app_session: Session, make_ready_tenant: Callable[..., Tenant],
) -> None:
    tenant = make_ready_tenant()
    job = _job(app_session, tenant, {"key": "a"})
    assert claim_next(app_session, "w1") is not None
    assert _reload(app_session, job).reclaim_count == 0  # a first claim is not a reclaim
    _expire(app_session, job, reclaims=2)
    assert claim_next(app_session, "w2") is not None
    assert _reload(app_session, job).reclaim_count == 3


def test_job_fails_after_too_many_reclaims(
    app_session: Session, make_ready_tenant: Callable[..., Tenant], make_user: Callable[..., User],
) -> None:
    tenant = make_ready_tenant()
    job = _job(app_session, tenant, {"key": "a"})
    other = _job(app_session, tenant, {"key": "b"})
    _expire(app_session, job, reclaims=MAX_RECLAIMS)

    claimed = claim_next(app_session, "w9")
    # The crash-looping job is failed instead of being run again; the next job is claimed.
    assert claimed is not None and claimed.id == other.id
    failed = _reload(app_session, job)
    assert failed.status == JobStatus.failed and failed.lease_until is None
    (step,) = _steps(app_session, job)
    assert step.status == StepStatus.failed
    assert step.output is not None and "stopped responding" in step.output
    event = _events(app_session, "job.failed")[-1]
    assert event.details["job_id"] == str(job.id)
    assert "stopped responding" in event.details["reason"]
    assert verify_chain(app_session).ok

    # A manual retry starts a fresh count.
    actor = make_user()
    app_session.commit()
    retry_step(app_session, failed, step, actor)
    app_session.commit()
    assert _reload(app_session, job).reclaim_count == 0


# --- Scheduled actions and Google quotas ----------------------------------------------

def test_scheduled_action_is_rescheduled_on_quota_then_fails(
    app_session: Session, make_ready_tenant: Callable[..., Tenant], fake_gam: Any,
    job_dir: Path, credential_keys: Keys, echo_action: str,
) -> None:
    tenant = make_ready_tenant()
    job = _job(app_session, tenant, {"key": "a"})
    action = _schedule(app_session, tenant, job)
    fake_gam.scenario([{"match": ["info", "user"], "exit": 9, "stderr": QUOTA_STDERR}])

    for attempt in range(1, MAX_QUOTA_RETRIES + 1):
        before = datetime.now(UTC)
        assert run_due_actions(app_session, credential_keys[0]) == 1
        row = _sa(app_session, action)
        assert row.status == ScheduledStatus.scheduled, row.result
        assert row.params["quota_retries"] == attempt
        assert row.params["target"] == "leaver@acme.test"  # the original params are kept
        assert row.run_at > before + timedelta(seconds=20)  # backed off
        assert row.lease_until is None and row.claim_token is None
        assert "quota" in (row.result or "")
        row.run_at = datetime.now(UTC) - timedelta(seconds=1)
        app_session.commit()

    assert run_due_actions(app_session, credential_keys[0]) == 1
    row = _sa(app_session, action)
    assert row.status == ScheduledStatus.failed
    assert "quota" in (row.result or "")
    assert len(_events(app_session, "scheduled_action.rescheduled")) == MAX_QUOTA_RETRIES
    assert len(_events(app_session, "scheduled_action.failed")) == 1
    assert verify_chain(app_session).ok


def test_non_quota_exit_9_is_not_retried(
    app_session: Session, make_ready_tenant: Callable[..., Tenant], fake_gam: Any,
    job_dir: Path, credential_keys: Keys, echo_action: str,
) -> None:
    tenant = make_ready_tenant()
    job = _job(app_session, tenant, {"key": "a"})
    action = _schedule(app_session, tenant, job)
    fake_gam.scenario([{"match": ["info", "user"], "exit": 9,
                        "stderr": "ERROR: 403: storageQuotaExceeded - full\n"}])
    run_due_actions(app_session, credential_keys[0])
    assert _sa(app_session, action).status == ScheduledStatus.failed
