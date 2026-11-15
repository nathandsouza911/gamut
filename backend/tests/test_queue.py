# SPDX-License-Identifier: AGPL-3.0-only
"""Job queue: creation, claiming, leases, step execution, retry and skip."""

import os
import threading
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from sqlalchemy import Engine, select, text, update
from sqlalchemy.orm import Session

from app.audit.chain import verify_chain
from app.jobs.execute import MAX_QUOTA_RETRIES, run_steps
from app.jobs.queue import (
    ConflictError,
    backoff_seconds,
    claim_next,
    create_job,
    plan_job,
    retry_step,
    run_job,
    skip_step,
)
from app.models import (
    AuditEvent,
    Job,
    JobStatus,
    JobStep,
    StepStatus,
    Tenant,
    TenantStatus,
    User,
)
from tests.scripted_workflow import NAME, PROBES, scripted_params

Keys = tuple[X25519PrivateKey, str]

QUOTA_STDERR = "ERROR: 403: rateLimitExceeded - Rate Limit Exceeded\n"


def _job(
    session: Session,
    tenant: Tenant,
    *steps: dict[str, Any],
    actor: User | None = None,
    key: str | None = None,
) -> Job:
    planned = plan_job(NAME, scripted_params(*steps), tenant)
    job = create_job(
        session, tenant_id=tenant.id, workflow=planned.workflow, params=planned.params,
        steps=planned.steps, actor=actor, idempotency_key=key or str(uuid.uuid4()),
    )
    session.commit()
    return job


def _steps(session: Session, job: Job) -> list[JobStep]:
    session.expire_all()
    return list(session.scalars(
        select(JobStep).where(JobStep.job_id == job.id).order_by(JobStep.position)
    ))


def _events(session: Session, prefix: str = "") -> list[AuditEvent]:
    session.expire_all()
    rows = session.scalars(select(AuditEvent).order_by(AuditEvent.id))
    return [e for e in rows if e.action.startswith(prefix)]


def _reload(session: Session, job: Job) -> Job:
    session.expire_all()
    fresh = session.get(Job, job.id)
    assert fresh is not None
    return fresh


# --- create_job ----------------------------------------------------------------------

def test_create_job_writes_job_steps_and_event_and_is_idempotent(
    app_session: Session, make_ready_tenant: Callable[..., Tenant],
    make_user: Callable[..., User],
) -> None:
    tenant = make_ready_tenant()
    user = make_user(email="tech@example.com")
    job = _job(app_session, tenant, {"key": "a"}, {"key": "b", "optional": True},
               actor=user, key="k-1")
    again = _job(app_session, tenant, {"key": "a"}, actor=user, key="k-1")
    assert again.id == job.id
    assert app_session.scalar(select(text("count(*)")).select_from(Job)) == 1
    steps = _steps(app_session, job)
    assert [(s.key, s.optional, s.status) for s in steps] == [
        ("a", False, StepStatus.pending), ("b", True, StepStatus.pending)
    ]
    assert job.status == JobStatus.queued and job.created_by == user.id
    created = _events(app_session, "job.created")
    assert len(created) == 1
    assert created[0].actor == "tech@example.com"
    assert created[0].details["steps"] == ["a", "b"]


def test_idempotency_key_of_another_tenant_is_refused(
    app_session: Session, make_ready_tenant: Callable[..., Tenant],
) -> None:
    one, two = make_ready_tenant(), make_ready_tenant()
    _job(app_session, one, {"key": "a"}, key="shared")
    with pytest.raises(ConflictError):
        _job(app_session, two, {"key": "a"}, key="shared")


def test_create_job_rolls_back_as_one_transaction(
    app_session: Session, make_ready_tenant: Callable[..., Tenant],
) -> None:
    tenant = make_ready_tenant()
    planned = plan_job(NAME, scripted_params({"key": "a"}), tenant)
    create_job(app_session, tenant_id=tenant.id, workflow=planned.workflow,
               params=planned.params, steps=planned.steps, actor=None, idempotency_key="x")
    app_session.rollback()
    assert app_session.scalar(select(text("count(*)")).select_from(Job)) == 0
    assert app_session.scalar(select(text("count(*)")).select_from(JobStep)) == 0
    assert _events(app_session, "job.created") == []


# --- claim_next ----------------------------------------------------------------------

def test_skip_locked_two_workers_one_claim(
    app_session: Session, app_engine: Engine, make_ready_tenant: Callable[..., Tenant],
) -> None:
    tenant = make_ready_tenant()
    job = _job(app_session, tenant, {"key": "a"})
    barrier = threading.Barrier(2)
    claimed: list[Job | None] = []

    def claim(name: str) -> None:
        with Session(app_engine, expire_on_commit=False) as session:
            barrier.wait(timeout=10)
            claimed.append(claim_next(session, name))

    threads = [threading.Thread(target=claim, args=(f"w{i}",)) for i in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=20)
    assert len(claimed) == 2
    winners = [j for j in claimed if j is not None]
    assert [j.id for j in winners] == [job.id]
    fresh = _reload(app_session, job)
    assert fresh.status == JobStatus.running and fresh.lease_until is not None
    assert len(_events(app_session, "job.claimed")) == 1


def test_claim_skips_a_row_locked_by_another_transaction(
    app_session: Session, app_engine: Engine, make_ready_tenant: Callable[..., Tenant],
) -> None:
    tenant = make_ready_tenant()
    job = _job(app_session, tenant, {"key": "a"})
    with app_engine.connect() as holder:
        holder.begin()
        holder.execute(text("SELECT id FROM jobs WHERE id = :i FOR UPDATE"), {"i": job.id})
        with Session(app_engine) as session:
            session.execute(text("SET LOCAL lock_timeout = '2s'"))
            assert claim_next(session, "w1") is None  # skipped, not blocked
        holder.rollback()
    with Session(app_engine) as session:
        claimed = claim_next(session, "w1")
        assert claimed is not None and claimed.id == job.id


def test_expired_lease_is_reclaimed(
    app_session: Session, make_ready_tenant: Callable[..., Tenant], fake_gam: Any,
    job_dir: Path, credential_keys: Keys,
) -> None:
    """A worker died mid-step: its lease expires; another worker re-runs that step."""
    tenant = make_ready_tenant()
    job = _job(app_session, tenant,
               {"key": "a", "args": ["info", "a"]}, {"key": "b", "args": ["info", "b"]})
    steps = _steps(app_session, job)
    steps[0].status = StepStatus.succeeded
    steps[1].status = StepStatus.running  # interrupted
    app_session.flush()
    job = _reload(app_session, job)
    job.status = JobStatus.running
    job.lease_until = datetime.now(UTC) - timedelta(seconds=5)
    app_session.commit()

    claimed = claim_next(app_session, "w2")
    assert claimed is not None and claimed.id == job.id
    reclaim = _events(app_session, "job.claimed")[-1]
    assert reclaim.details["previous_status"] == "running"
    assert reclaim.details["lease_expired"] is True

    run_job(claimed, credential_keys[0])
    assert [c["argv"] for c in fake_gam.calls()] == [["info", "b"]]  # b re-ran, a did not
    assert [s.status for s in _steps(app_session, job)] == [StepStatus.succeeded] * 2
    assert _reload(app_session, job).status == JobStatus.succeeded


def test_live_lease_is_not_reclaimed_and_tenant_runs_one_job_at_a_time(
    app_session: Session, make_ready_tenant: Callable[..., Tenant],
) -> None:
    busy, other = make_ready_tenant(), make_ready_tenant()
    running = _job(app_session, busy, {"key": "a"})
    queued_same = _job(app_session, busy, {"key": "a"})
    queued_other = _job(app_session, other, {"key": "a"})
    first = claim_next(app_session, "w1")
    assert first is not None and first.id == running.id
    second = claim_next(app_session, "w2")
    assert second is not None and second.id == queued_other.id  # busy tenant skipped
    assert claim_next(app_session, "w3") is None
    assert _reload(app_session, queued_same).status == JobStatus.queued


def test_waiting_job_is_claimed_only_when_due(
    app_session: Session, make_ready_tenant: Callable[..., Tenant],
) -> None:
    tenant = make_ready_tenant()
    job = _job(app_session, tenant, {"key": "a", "kind": "async"})
    step = _steps(app_session, job)[0]
    step.status = StepStatus.waiting
    step.next_poll_at = datetime.now(UTC) + timedelta(seconds=60)
    app_session.flush()
    _reload(app_session, job).status = JobStatus.waiting
    app_session.commit()
    assert claim_next(app_session, "w1") is None
    step = _steps(app_session, job)[0]
    step.next_poll_at = datetime.now(UTC) - timedelta(seconds=1)
    app_session.commit()
    claimed = claim_next(app_session, "w1")
    assert claimed is not None and claimed.id == job.id


# --- run_steps / run_job -------------------------------------------------------------

def test_failed_step_stops_job_then_retry_resumes(
    app_session: Session, make_ready_tenant: Callable[..., Tenant],
    make_user: Callable[..., User], fake_gam: Any, job_dir: Path, credential_keys: Keys,
) -> None:
    tenant = make_ready_tenant()
    tech = make_user(email="tech@example.com")
    job = _job(app_session, tenant, {"key": "a", "args": ["info", "a"]},
               {"key": "b", "args": ["info", "b"]}, {"key": "c", "args": ["info", "c"]})
    fake_gam.scenario([{"match": ["info", "b"], "exit": 1, "stderr": "ERROR: boom"}])
    run_steps(app_session, job, credential_keys[0])
    steps = _steps(app_session, job)
    assert [s.status for s in steps] == [StepStatus.succeeded, StepStatus.failed,
                                         StepStatus.pending]
    assert _reload(app_session, job).status == JobStatus.failed

    # A failed step is never re-run by itself (R11), even if run_steps is called again.
    run_steps(app_session, _reload(app_session, job), credential_keys[0])
    assert len(fake_gam.calls()) == 2

    fake_gam.scenario([])
    job = _reload(app_session, job)
    retry_step(app_session, job, _steps(app_session, job)[1], tech)
    app_session.commit()
    job = _reload(app_session, job)
    assert job.status == JobStatus.queued and job.finished_at is None
    assert _steps(app_session, job)[1].status == StepStatus.pending
    event = _events(app_session, "job.step.retry")[0]
    assert event.actor == "tech@example.com" and event.details["step"] == "b"

    claimed = claim_next(app_session, "w1")
    assert claimed is not None
    run_job(claimed, credential_keys[0])
    assert [c["argv"][1] for c in fake_gam.calls()] == ["a", "b", "b", "c"]
    assert _reload(app_session, job).status == JobStatus.succeeded


def test_retry_and_skip_need_a_failed_job_and_a_failed_step(
    app_session: Session, make_ready_tenant: Callable[..., Tenant],
    make_user: Callable[..., User],
) -> None:
    tenant = make_ready_tenant()
    tech = make_user()
    job = _job(app_session, tenant, {"key": "a", "optional": True}, {"key": "b"})
    steps = _steps(app_session, job)
    with pytest.raises(ConflictError) as err:
        retry_step(app_session, job, steps[0], tech)
    assert err.value.status_code == 409
    with pytest.raises(ConflictError):
        skip_step(app_session, job, steps[0], tech)
    job = _reload(app_session, job)
    job.status = JobStatus.failed
    app_session.commit()
    with pytest.raises(ConflictError):  # the step itself did not fail
        retry_step(app_session, job, _steps(app_session, job)[1], tech)
    other = _job(app_session, tenant, {"key": "x"})
    with pytest.raises(ConflictError):  # a step of another job
        retry_step(app_session, job, _steps(app_session, other)[0], tech)


def test_skip_only_optional(
    app_session: Session, make_ready_tenant: Callable[..., Tenant],
    make_user: Callable[..., User], fake_gam: Any, job_dir: Path, credential_keys: Keys,
) -> None:
    tenant = make_ready_tenant()
    tech = make_user(email="tech@example.com")
    job = _job(app_session, tenant, {"key": "req", "args": ["info", "req"]},
               {"key": "opt", "args": ["info", "opt"], "optional": True},
               {"key": "last", "args": ["info", "last"]})
    fake_gam.scenario([{"match": ["info", "req"], "exit": 1},
                       {"match": ["info", "opt"], "exit": 1}])
    run_steps(app_session, job, credential_keys[0])
    job = _reload(app_session, job)
    with pytest.raises(ConflictError) as err:
        skip_step(app_session, job, _steps(app_session, job)[0], tech)
    assert err.value.status_code == 409
    assert "optional" in str(err.value)

    app_session.rollback()
    retry_step(app_session, _reload(app_session, job), _steps(app_session, job)[0], tech)
    app_session.commit()
    fake_gam.scenario([{"match": ["info", "opt"], "exit": 1}])
    run_steps(app_session, _reload(app_session, job), credential_keys[0])
    steps = _steps(app_session, job)
    assert [s.status for s in steps] == [StepStatus.succeeded, StepStatus.failed,
                                         StepStatus.pending]
    skip_step(app_session, _reload(app_session, job), steps[1], tech)
    app_session.commit()
    assert _events(app_session, "job.step.skip")[0].actor == "tech@example.com"
    run_steps(app_session, _reload(app_session, job), credential_keys[0])
    steps = _steps(app_session, job)
    assert [s.status for s in steps] == [StepStatus.succeeded, StepStatus.skipped,
                                         StepStatus.succeeded]
    assert _reload(app_session, job).status == JobStatus.succeeded


def test_backoff_caps_at_900s(
    app_session: Session, make_ready_tenant: Callable[..., Tenant], fake_gam: Any,
    job_dir: Path, credential_keys: Keys,
) -> None:
    assert [backoff_seconds(n) for n in range(7)] == [30, 60, 120, 240, 480, 900, 900]
    assert backoff_seconds(10_000) == 900
    assert backoff_seconds(0, poll_after_s=300) == 300
    assert backoff_seconds(0, poll_after_s=5000) == 900

    tenant = make_ready_tenant()
    job = _job(app_session, tenant, {"key": "t", "kind": "async", "args": ["print", "x"]})
    fake_gam.scenario([{"match": ["print", "x"], "stdout": "inProgress"}])
    delays = []
    for _ in range(7):
        before = datetime.now(UTC)
        run_steps(app_session, _reload(app_session, job), credential_keys[0])
        step = _steps(app_session, job)[0]
        assert step.status == StepStatus.waiting and step.next_poll_at is not None
        delays.append(round((step.next_poll_at - before).total_seconds() / 30) * 30)
        fresh = _reload(app_session, job)
        assert fresh.status == JobStatus.waiting and fresh.lease_until is None
    assert delays == [30, 60, 120, 240, 480, 900, 900]
    assert _steps(app_session, job)[0].poll_attempts == 7


def test_disabled_tenant_job_fails_without_calling_gam(
    app_session: Session, make_ready_tenant: Callable[..., Tenant], fake_gam: Any,
    job_dir: Path, credential_keys: Keys,
) -> None:
    tenant = make_ready_tenant()
    job = _job(app_session, tenant, {"key": "a"})
    tenant.status = TenantStatus.disabled
    app_session.commit()
    claimed = claim_next(app_session, "w1")
    assert claimed is not None
    run_job(claimed, credential_keys[0])
    job = _reload(app_session, job)
    assert job.status == JobStatus.failed and job.lease_until is None
    step = _steps(app_session, job)[0]
    assert step.status == StepStatus.failed
    assert step.output is not None and "disabled" in step.output
    assert fake_gam.calls() == []
    assert _events(app_session, "job.failed")


def test_operator_value_errors_are_shown_and_other_errors_are_not(
    app_session: Session, make_ready_tenant: Callable[..., Tenant], fake_gam: Any,
    job_dir: Path, credential_keys: Keys,
) -> None:
    tenant = make_ready_tenant()
    job = _job(app_session, tenant, {"key": "v", "raise": "value"})
    run_steps(app_session, job, credential_keys[0])
    step = _steps(app_session, job)[0]
    assert step.status == StepStatus.failed
    assert step.output == "v: the manager is not in the tenant"

    job = _job(app_session, tenant, {"key": "r", "raise": "runtime"})
    run_steps(app_session, job, credential_keys[0])
    step = _steps(app_session, job)[0]
    assert step.output == "internal error (RuntimeError)"
    assert _reload(app_session, job).status == JobStatus.failed


@pytest.mark.parametrize("broken", ["gam_version", "materialize"])
def test_setup_errors_fail_the_job_instead_of_leaving_it_running(
    app_session: Session, make_ready_tenant: Callable[..., Tenant], fake_gam: Any,
    job_dir: Path, credential_keys: Keys, monkeypatch: pytest.MonkeyPatch, broken: str,
) -> None:
    import app.jobs.execute as execute

    def boom(*args: Any, **kwargs: Any) -> Any:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(execute, broken, boom)
    tenant = make_ready_tenant()
    job = _job(app_session, tenant, {"key": "a"})
    run_steps(app_session, job, credential_keys[0])
    job = _reload(app_session, job)
    assert job.status == JobStatus.failed and job.lease_until is None
    step = _steps(app_session, job)[0]
    assert step.status == StepStatus.failed
    assert step.output is not None and "OSError" in step.output
    assert fake_gam.calls() == []


def test_no_transaction_is_open_while_a_step_executes(
    app_session: Session, make_ready_tenant: Callable[..., Tenant], fake_gam: Any,
    job_dir: Path, credential_keys: Keys,
) -> None:
    PROBES.clear()
    tenant = make_ready_tenant()
    job = _job(app_session, tenant, {"key": "a"}, {"key": "b"})
    claimed = claim_next(app_session, "w1")
    assert claimed is not None
    run_job(claimed, credential_keys[0])
    assert PROBES == [{"step": "a", "in_transaction": False},
                      {"step": "b", "in_transaction": False}]
    # Also through run_steps with a caller's ordinary session (expire_on_commit=True).
    PROBES.clear()
    job = _job(app_session, tenant, {"key": "c"})
    run_steps(app_session, job, credential_keys[0])
    assert PROBES == [{"step": "c", "in_transaction": False}]
    assert app_session.expire_on_commit is True  # restored


def test_rate_limited_gam_exit_waits_with_backoff_then_gives_up(
    app_session: Session, make_ready_tenant: Callable[..., Tenant], fake_gam: Any,
    job_dir: Path, credential_keys: Keys,
) -> None:
    tenant = make_ready_tenant()
    job = _job(app_session, tenant, {"key": "a", "args": ["info", "a"]})
    fake_gam.scenario([{"match": ["info", "a"], "exit": 9, "stderr": QUOTA_STDERR}])
    for attempt in range(1, MAX_QUOTA_RETRIES + 1):
        run_steps(app_session, _reload(app_session, job), credential_keys[0])
        step = _steps(app_session, job)[0]
        assert step.status == StepStatus.waiting, attempt
        assert step.data["quota_retries"] == attempt
        assert step.output is not None and "rate limit" in step.output.lower()
        assert _reload(app_session, job).status == JobStatus.waiting
    run_steps(app_session, _reload(app_session, job), credential_keys[0])
    step = _steps(app_session, job)[0]
    assert step.status == StepStatus.failed and step.exit_code == 9
    assert _reload(app_session, job).status == JobStatus.failed

    # Exit 9 without a rate-limit reason is an ordinary failure.
    other = _job(app_session, tenant, {"key": "b", "args": ["info", "b"]})
    fake_gam.scenario([{"match": ["info", "b"], "exit": 9,
                        "stderr": "ERROR: 403: storageQuotaExceeded - full\n"}])
    run_steps(app_session, other, credential_keys[0])
    assert _steps(app_session, other)[0].status == StepStatus.failed


def test_rate_limit_wait_keeps_the_step_data(
    app_session: Session, make_ready_tenant: Callable[..., Tenant], fake_gam: Any,
    job_dir: Path, credential_keys: Keys,
) -> None:
    """An async step's saved data (for example a transfer id) survives a quota wait."""
    tenant = make_ready_tenant()
    job = _job(app_session, tenant, {"key": "t", "kind": "async", "args": ["print", "x"]})
    fake_gam.scenario([{"match": ["print", "x"], "stdout": "inProgress"}])
    run_steps(app_session, job, credential_keys[0])
    assert _steps(app_session, job)[0].data == {"polled": 1}
    fake_gam.scenario([{"match": ["print", "x"], "exit": 9, "stderr": QUOTA_STDERR}])
    run_steps(app_session, _reload(app_session, job), credential_keys[0])
    assert _steps(app_session, job)[0].data == {"polled": 1, "quota_retries": 1}


def test_heartbeat_extends_the_lease_while_a_step_runs(
    app_session: Session, make_ready_tenant: Callable[..., Tenant], fake_gam: Any,
    job_dir: Path, credential_keys: Keys,
) -> None:
    tenant = make_ready_tenant()
    job = _job(app_session, tenant, {"key": "slow", "args": ["info", "slow"]})
    fake_gam.scenario([{"match": ["info", "slow"], "sleep": 2.5}])
    claimed = claim_next(app_session, "w1", lease_s=2)
    assert claimed is not None
    seen: list[datetime | None] = []

    def watch() -> None:
        with Session(app_session.get_bind()) as session:
            for _ in range(20):
                lease = session.scalar(select(Job.lease_until).where(Job.id == job.id))
                session.rollback()
                seen.append(lease)
                if lease is None:
                    return
                threading.Event().wait(0.2)

    watcher = threading.Thread(target=watch)
    watcher.start()
    run_job(claimed, credential_keys[0], lease_s=2, heartbeat_s=0.5)
    watcher.join(timeout=10)
    leases = [s for s in seen if s is not None]
    assert len(set(leases)) >= 3  # renewed several times while GAM ran
    assert _reload(app_session, job).status == JobStatus.succeeded


def test_temp_dir_removed_on_success_and_failure(
    app_session: Session, make_ready_tenant: Callable[..., Tenant], fake_gam: Any,
    job_dir: Path, credential_keys: Keys,
) -> None:
    tenant = make_ready_tenant()
    ok = _job(app_session, tenant, {"key": "a", "args": ["info", "ok"]})
    bad = _job(app_session, tenant, {"key": "a", "args": ["info", "bad"]})
    fake_gam.scenario([{"match": ["info", "bad"], "exit": 2}])
    for _ in (ok, bad):
        claimed = claim_next(app_session, "w1")
        assert claimed is not None
        run_job(claimed, credential_keys[0])
    statuses = {_reload(app_session, j).status for j in (ok, bad)}
    assert statuses == {JobStatus.succeeded, JobStatus.failed}
    dirs = [Path(c["env"]["GAMCFGDIR"]) for c in fake_gam.calls()]
    assert len(dirs) == 2 and dirs[0] != dirs[1]
    assert all(d.parent == job_dir and not d.exists() for d in dirs)
    assert os.listdir(job_dir) == []


def test_job_records_gam_version(
    app_session: Session, make_ready_tenant: Callable[..., Tenant], fake_gam: Any,
    job_dir: Path, credential_keys: Keys,
) -> None:
    tenant = make_ready_tenant()
    job = _job(app_session, tenant, {"key": "a"})
    claimed = claim_next(app_session, "w1")
    assert claimed is not None
    run_job(claimed, credential_keys[0])
    assert _reload(app_session, job).gam_version == "GAM 7.x.y - fake"
    assert {e.details["gam_version"] for e in _events(app_session, "job.step.")} == {
        "GAM 7.x.y - fake"
    }
    assert verify_chain(app_session).ok


# --- Claim-token fencing -------------------------------------------------------------

def _steal(session: Session, job_id: uuid.UUID, worker: str) -> Job:
    """Expire the job's lease and claim it as `worker`, in one transaction."""
    session.execute(
        update(Job).where(Job.id == job_id)
        .values(lease_until=datetime.now(UTC) - timedelta(seconds=1))
    )
    claimed = claim_next(session, worker)
    assert claimed is not None and claimed.id == job_id
    return claimed


def test_reclaimed_job_rejects_the_old_workers_writes(
    app_session: Session, app_engine: Engine, make_ready_tenant: Callable[..., Tenant],
    fake_gam: Any, job_dir: Path, credential_keys: Keys,
) -> None:
    tenant = make_ready_tenant()
    job = _job(app_session, tenant, {"key": "a", "args": ["info", "a"]})
    with Session(app_engine, expire_on_commit=False) as first:
        old = claim_next(first, "worker-a")
    assert old is not None
    with Session(app_engine, expire_on_commit=False) as second:
        new = _steal(second, job.id, "worker-b")
    assert new.claim_token != old.claim_token

    run_job(old, credential_keys[0])  # the old worker comes back
    assert fake_gam.calls() == []
    fresh = _reload(app_session, job)
    assert fresh.status == JobStatus.running
    assert fresh.claim_token == new.claim_token and fresh.lease_until == new.lease_until
    assert _steps(app_session, job)[0].status == StepStatus.pending
    assert _events(app_session, "job.step.") == []
    assert os.listdir(job_dir) == []

    run_job(new, credential_keys[0])
    assert _reload(app_session, job).status == JobStatus.succeeded
    assert len(fake_gam.calls()) == 1


def test_lease_lost_during_gam_drops_the_old_result_and_stops_the_heartbeat(
    app_session: Session, app_engine: Engine, make_ready_tenant: Callable[..., Tenant],
    fake_gam: Any, job_dir: Path, credential_keys: Keys,
) -> None:
    tenant = make_ready_tenant()
    job = _job(app_session, tenant, {"key": "slow", "args": ["info", "slow"]},
               {"key": "next", "args": ["info", "next"]})
    fake_gam.scenario([{"match": ["info", "slow"], "sleep": 1.5}])
    with Session(app_engine, expire_on_commit=False) as first:
        old = claim_next(first, "worker-a", lease_s=60)
    assert old is not None
    stolen: list[Job] = []

    def steal_while_gam_runs() -> None:
        for _ in range(100):
            if fake_gam.calls():
                break
            threading.Event().wait(0.05)
        with Session(app_engine, expire_on_commit=False) as second:
            stolen.append(_steal(second, job.id, "worker-b"))

    thief = threading.Thread(target=steal_while_gam_runs)
    thief.start()
    run_job(old, credential_keys[0], lease_s=60, heartbeat_s=0.2)
    thief.join(timeout=10)
    assert len(stolen) == 1
    new = stolen[0]

    fresh = _reload(app_session, job)
    assert fresh.status == JobStatus.running
    assert fresh.claim_token == new.claim_token
    assert fresh.lease_until == new.lease_until  # the old heartbeat stopped renewing
    steps = _steps(app_session, job)
    assert [s.status for s in steps] == [StepStatus.running, StepStatus.pending]
    assert [e.action for e in _events(app_session, "job.step.")] == ["job.step.running"]
    assert [c["argv"] for c in fake_gam.calls()] == [["info", "slow"]]  # stopped there
    assert os.listdir(job_dir) == []

    fake_gam.scenario([])
    run_job(new, credential_keys[0])  # the new owner re-runs the interrupted step
    assert _reload(app_session, job).status == JobStatus.succeeded
    assert [c["argv"][1] for c in fake_gam.calls()] == ["slow", "slow", "next"]
    assert verify_chain(app_session).ok
