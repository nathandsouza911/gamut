# SPDX-License-Identifier: AGPL-3.0-only
"""Worker loop: ticks, waiting steps, scheduled actions, daily health, `gamut worker`."""

import os
import signal
import threading
import uuid
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit.chain import verify_chain
from app.gam.runner import run_gam
from app.jobs import scheduled
from app.jobs.queue import ConflictError, create_job, plan_job
from app.jobs.scheduled import (
    ActionContext,
    ActionResult,
    cancel_scheduled_action,
    create_scheduled_action,
    register_action,
    run_due_actions,
)
from app.models import (
    AuditEvent,
    Job,
    JobStatus,
    JobStep,
    ScheduledAction,
    ScheduledStatus,
    StepStatus,
    Tenant,
    TenantCredential,
    TenantStatus,
    User,
)
from tests.conftest import WorkerDriver
from tests.scripted_workflow import NAME, scripted_params

Keys = tuple[X25519PrivateKey, str]


def _job(session: Session, tenant: Tenant, *steps: dict[str, Any],
         actor: User | None = None, target: str | None = None) -> Job:
    planned = plan_job(NAME, scripted_params(*steps, target=target), tenant)
    job = create_job(
        session, tenant_id=tenant.id, workflow=planned.workflow, params=planned.params,
        steps=planned.steps, actor=actor, idempotency_key=str(uuid.uuid4()),
    )
    session.commit()
    return job


def _get(session: Session, job: Job) -> Job:
    session.expire_all()
    fresh = session.get(Job, job.id)
    assert fresh is not None
    return fresh


def _steps(session: Session, job: Job) -> list[JobStep]:
    session.expire_all()
    return list(session.scalars(
        select(JobStep).where(JobStep.job_id == job.id).order_by(JobStep.position)
    ))


def _events(session: Session) -> list[AuditEvent]:
    session.expire_all()
    return list(session.scalars(select(AuditEvent).order_by(AuditEvent.id)))


# --- Jobs through the loop -----------------------------------------------------------

def test_waiting_step_does_not_block_other_jobs(
    app_session: Session, make_ready_tenant: Callable[..., Tenant], fake_gam: Any,
    worker: WorkerDriver,
) -> None:
    tenant = make_ready_tenant()
    a = _job(app_session, tenant, {"key": "first", "args": ["info", "a"]},
             {"key": "transfer", "kind": "async", "args": ["print", "transfers"]},
             {"key": "after", "args": ["info", "a2"]})
    b = _job(app_session, tenant, {"key": "only", "args": ["info", "b"]})  # same tenant
    fake_gam.scenario([{"match": ["print", "transfers"], "stdout": "inProgress"}])

    assert worker.drain() == 2  # A runs until it waits, then B runs to the end
    assert _get(app_session, a).status == JobStatus.waiting
    assert _get(app_session, b).status == JobStatus.succeeded
    assert [s.status for s in _steps(app_session, a)] == [
        StepStatus.succeeded, StepStatus.waiting, StepStatus.pending
    ]
    assert worker.drain() == 0  # not due yet: nothing to do

    worker.make_due(a.id)  # first poll: still in progress
    assert worker.drain() == 1
    assert _steps(app_session, a)[1].poll_attempts == 2

    fake_gam.scenario([{"match": ["print", "transfers"], "stdout": "done"}])
    worker.make_due(a.id)
    assert worker.drain() == 1
    assert _get(app_session, a).status == JobStatus.succeeded
    argv = [c["argv"] for c in fake_gam.calls()]
    assert argv == [["info", "a"], ["print", "transfers"], ["info", "b"],
                    ["print", "transfers"], ["print", "transfers"], ["info", "a2"]]


def test_every_transition_audited_and_chain_valid(
    app_session: Session, make_ready_tenant: Callable[..., Tenant],
    make_user: Callable[..., User], fake_gam: Any, worker: WorkerDriver,
) -> None:
    from app.jobs.queue import retry_step

    tenant = make_ready_tenant()
    tech = make_user(email="tech@example.com")
    job = _job(app_session, tenant,
               {"key": "pw", "args": ["update", "user", "x@y.test", "password", "S3cret!pw"]},
               {"key": "wait", "kind": "async", "args": ["print", "t"]},
               {"key": "bad", "args": ["info", "bad"]},
               actor=tech, target="leaver@acme.test")
    fake_gam.scenario([{"match": ["print", "t"], "stdout": "inProgress"},
                       {"match": ["info", "bad"], "exit": 3, "stderr": "nope"}])
    worker.drain()
    fake_gam.scenario([{"match": ["print", "t"], "stdout": "done"},
                       {"match": ["info", "bad"], "exit": 3, "stderr": "nope"}])
    worker.make_due(job.id)
    worker.drain()
    assert _get(app_session, job).status == JobStatus.failed
    retry_step(app_session, _get(app_session, job), _steps(app_session, job)[2], tech)
    app_session.commit()
    fake_gam.scenario([])
    worker.drain()
    assert _get(app_session, job).status == JobStatus.succeeded

    events = [e for e in _events(app_session) if e.details.get("job_id") == str(job.id)]
    actions = [e.action for e in events]
    assert actions == [
        "job.created",
        "job.claimed", "job.step.running", "job.step.succeeded",
        "job.step.running", "job.step.waiting",
        "job.claimed", "job.step.running", "job.step.succeeded",
        "job.step.running", "job.step.failed", "job.failed",
        "job.step.retry",
        "job.claimed", "job.step.running", "job.step.succeeded", "job.succeeded",
    ]
    for event in events:
        assert event.tenant_id == tenant.id
        assert event.actor == "tech@example.com"
        assert event.target == "leaver@acme.test"
        if event.action.startswith("job.step.") and event.action != "job.step.retry":
            assert "argv" in event.details and "exit_code" in event.details
    failed = next(e for e in events if e.action == "job.step.failed")
    assert failed.details["exit_code"] == 3 and failed.details["argv"] == ["info", "bad"]
    first = next(e for e in events if e.action == "job.step.succeeded")
    assert first.details["argv"] == ["update", "user", "x@y.test", "password", "[redacted]"]
    assert "S3cret!pw" not in str([e.details for e in _events(app_session)])
    assert verify_chain(app_session).ok


def test_a_crashing_tick_does_not_stop_the_loop(
    app_session: Session, credential_keys: Keys, job_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.worker import loop

    calls: list[int] = []
    stop = threading.Event()

    def flaky_tick(*args: Any, **kwargs: Any) -> bool:
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("database went away")
        if len(calls) >= 3:
            stop.set()
        return True

    monkeypatch.setattr(loop, "tick", flaky_tick)
    runner = threading.Thread(
        target=loop.run_forever, args=(stop, credential_keys[0]),
        kwargs={"worker_id": "t", "idle_sleep_s": 0.01},
    )
    runner.start()
    runner.join(timeout=10)
    assert not runner.is_alive()
    assert len(calls) == 3


def test_run_forever_runs_jobs_and_stops_on_event(
    app_session: Session, make_ready_tenant: Callable[..., Tenant], fake_gam: Any,
    worker: WorkerDriver, credential_keys: Keys,
) -> None:
    from app.worker.loop import run_forever

    tenant = make_ready_tenant()
    job = _job(app_session, tenant, {"key": "a"})
    stop = threading.Event()
    runner = threading.Thread(
        target=run_forever, args=(stop, credential_keys[0]),
        kwargs={"worker_id": "t", "idle_sleep_s": 0.05},
    )
    runner.start()
    try:
        for _ in range(100):
            if _get(app_session, job).status == JobStatus.succeeded:
                break
            stop.wait(0.05)
    finally:
        stop.set()
        runner.join(timeout=10)
    assert not runner.is_alive()
    assert _get(app_session, job).status == JobStatus.succeeded


# --- Scheduled actions ---------------------------------------------------------------

SEEN: list[dict[str, Any]] = []


def _echo_handler(ctx: ActionContext) -> ActionResult:
    """Test handler: runs `gam info user <target>`; refuses when params say so."""
    SEEN.append({"files": sorted(os.listdir(ctx.cfg_dir)), "cfg": str(ctx.cfg_dir),
                 "in_transaction": ctx.session.in_transaction()})
    if ctx.action.params.get("refuse"):
        return ActionResult(status=ScheduledStatus.refused, result="the transfer is not done")
    argv = ["info", "user", ctx.action.params["target"]]
    result = run_gam(argv, ctx.cfg_dir)
    status = ScheduledStatus.done if result.exit_code == 0 else ScheduledStatus.failed
    return ActionResult(status=status, result=result.stdout + result.stderr, argv=argv,
                        exit_code=result.exit_code)


@pytest.fixture
def echo_action() -> Iterator[str]:
    SEEN.clear()
    register_action("test_echo", _echo_handler)
    yield "test_echo"
    scheduled._HANDLERS.pop("test_echo", None)


def _schedule(session: Session, tenant: Tenant, job: Job, *, minutes: int = -1,
              **params: Any) -> ScheduledAction:
    action = create_scheduled_action(
        session, tenant_id=tenant.id, job_id=job.id, action="test_echo",
        run_at=datetime.now(UTC) + timedelta(minutes=minutes),
        params={"target": "leaver@acme.test", **params}, actor="tech@example.com",
    )
    session.commit()
    return action


def _sa(session: Session, action: ScheduledAction) -> ScheduledAction:
    session.expire_all()
    fresh = session.get(ScheduledAction, action.id)
    assert fresh is not None
    return fresh


def test_due_action_runs_once_with_credentials_and_is_audited(
    app_session: Session, make_ready_tenant: Callable[..., Tenant], fake_gam: Any,
    job_dir: Path, credential_keys: Keys, echo_action: str,
) -> None:
    tenant = make_ready_tenant()
    job = _job(app_session, tenant, {"key": "a"})
    due = _schedule(app_session, tenant, job)
    later = _schedule(app_session, tenant, job, minutes=60)
    fake_gam.scenario([{"match": ["info", "user"], "stdout": "User: leaver@acme.test"}])

    assert run_due_actions(app_session, credential_keys[0]) == 1
    assert run_due_actions(app_session, credential_keys[0]) == 0
    done = _sa(app_session, due)
    assert done.status == ScheduledStatus.done
    assert done.result == "User: leaver@acme.test"
    assert _sa(app_session, later).status == ScheduledStatus.scheduled
    assert SEEN == [{"files": ["oauth2.txt", "oauth2service.json"], "cfg": SEEN[0]["cfg"],
                     "in_transaction": False}]
    assert not Path(SEEN[0]["cfg"]).exists()
    assert os.listdir(job_dir) == []
    actions = [e.action for e in _events(app_session) if e.action.startswith("scheduled")]
    assert actions == ["scheduled_action.created", "scheduled_action.created",
                       "scheduled_action.started", "scheduled_action.done"]
    finished = [e for e in _events(app_session) if e.action == "scheduled_action.done"][0]
    assert finished.details["argv"] == ["info", "user", "leaver@acme.test"]
    assert finished.details["exit_code"] == 0
    assert finished.tenant_id == tenant.id and finished.target == "leaver@acme.test"
    assert verify_chain(app_session).ok


def test_cancel_only_while_scheduled(
    app_session: Session, make_ready_tenant: Callable[..., Tenant], fake_gam: Any,
    job_dir: Path, credential_keys: Keys, echo_action: str,
) -> None:
    tenant, other = make_ready_tenant(), make_ready_tenant()
    job = _job(app_session, tenant, {"key": "a"})
    action = _schedule(app_session, tenant, job)
    with pytest.raises(LookupError):  # another tenant's id
        cancel_scheduled_action(app_session, tenant_id=other.id, action_id=action.id,
                                actor="x@example.com")
    cancelled = cancel_scheduled_action(app_session, tenant_id=tenant.id,
                                        action_id=action.id, actor="admin@example.com")
    app_session.commit()
    assert cancelled.status == ScheduledStatus.cancelled
    assert run_due_actions(app_session, credential_keys[0]) == 0
    assert fake_gam.calls() == []
    with pytest.raises(ConflictError) as err:
        cancel_scheduled_action(app_session, tenant_id=tenant.id, action_id=action.id,
                                actor="admin@example.com")
    assert err.value.status_code == 409
    event = [e for e in _events(app_session) if e.action == "scheduled_action.cancelled"]
    assert len(event) == 1 and event[0].actor == "admin@example.com"


def test_refused_failed_and_disabled_tenant_actions(
    app_session: Session, make_ready_tenant: Callable[..., Tenant], fake_gam: Any,
    job_dir: Path, credential_keys: Keys, echo_action: str,
) -> None:
    tenant = make_ready_tenant()
    job = _job(app_session, tenant, {"key": "a"})
    refused = _schedule(app_session, tenant, job, refuse=True)
    run_due_actions(app_session, credential_keys[0])
    assert _sa(app_session, refused).status == ScheduledStatus.refused
    assert _sa(app_session, refused).result == "the transfer is not done"

    fake_gam.scenario([{"match": ["info", "user"], "exit": 56, "stderr": "does not exist"}])
    failed = _schedule(app_session, tenant, job)
    run_due_actions(app_session, credential_keys[0])
    assert _sa(app_session, failed).status == ScheduledStatus.failed

    disabled = make_ready_tenant(status=TenantStatus.disabled)
    djob = _job(app_session, disabled, {"key": "a"})
    blocked = _schedule(app_session, disabled, djob)
    calls_before = len(fake_gam.calls())
    run_due_actions(app_session, credential_keys[0])
    blocked = _sa(app_session, blocked)
    assert blocked.status == ScheduledStatus.refused
    assert blocked.result is not None and "disabled" in blocked.result
    assert len(fake_gam.calls()) == calls_before


def test_unknown_action_and_missing_credentials_fail_cleanly(
    app_session: Session, make_ready_tenant: Callable[..., Tenant], fake_gam: Any,
    job_dir: Path, credential_keys: Keys, echo_action: str,
) -> None:
    with pytest.raises(LookupError):
        tenant = make_ready_tenant()
        job = _job(app_session, tenant, {"key": "a"})
        create_scheduled_action(
            app_session, tenant_id=tenant.id, job_id=job.id, action="no_such_action",
            run_at=datetime.now(UTC), params={}, actor="x",
        )
    app_session.rollback()
    tenant = make_ready_tenant()
    job = _job(app_session, tenant, {"key": "a"})
    action = _schedule(app_session, tenant, job)
    cred = app_session.get(TenantCredential, tenant.id)
    app_session.delete(cred)
    app_session.commit()
    run_due_actions(app_session, credential_keys[0])
    row = _sa(app_session, action)
    assert row.status == ScheduledStatus.failed
    assert row.result is not None and "no stored credentials" in row.result


def test_crashed_running_action_is_reclaimed_after_its_lease(
    app_session: Session, make_ready_tenant: Callable[..., Tenant], fake_gam: Any,
    job_dir: Path, credential_keys: Keys, echo_action: str,
) -> None:
    tenant = make_ready_tenant()
    job = _job(app_session, tenant, {"key": "a"})
    action = _schedule(app_session, tenant, job)
    row = _sa(app_session, action)
    row.status = ScheduledStatus.running
    row.lease_until = datetime.now(UTC) + timedelta(minutes=5)
    app_session.commit()
    assert run_due_actions(app_session, credential_keys[0]) == 0  # live lease
    row = _sa(app_session, action)
    row.lease_until = datetime.now(UTC) - timedelta(seconds=1)
    app_session.commit()
    assert run_due_actions(app_session, credential_keys[0]) == 1
    assert _sa(app_session, action).status == ScheduledStatus.done


def test_tick_runs_due_scheduled_actions(
    app_session: Session, make_ready_tenant: Callable[..., Tenant], fake_gam: Any,
    worker: WorkerDriver, echo_action: str,
) -> None:
    tenant = make_ready_tenant()
    job = _job(app_session, tenant, {"key": "a"})
    action = _schedule(app_session, tenant, job)
    worker.drain()
    assert _sa(app_session, action).status == ScheduledStatus.done


# --- Daily health check --------------------------------------------------------------

def _health_jobs(session: Session) -> list[Job]:
    session.expire_all()
    return list(session.scalars(select(Job).where(Job.workflow == "health_check")))


def test_daily_health_check_enqueued_once_for_due_tenants(
    app_session: Session, make_ready_tenant: Callable[..., Tenant],
    make_tenant: Callable[..., Tenant], fake_gam: Any, worker: WorkerDriver,
) -> None:
    from app.worker.loop import enqueue_due_health_checks

    stale = make_ready_tenant(last_health_check_at=datetime.now(UTC) - timedelta(hours=25))
    never = make_ready_tenant(last_health_check_at=None, status=TenantStatus.pending)
    make_ready_tenant()  # checked recently
    make_ready_tenant(last_health_check_at=None, status=TenantStatus.disabled)
    make_tenant(admin_email="a@x.test")  # no credentials
    app_session.commit()

    assert enqueue_due_health_checks(app_session) == 2
    app_session.commit()
    assert enqueue_due_health_checks(app_session) == 0  # queued ones are not duplicated
    app_session.commit()
    jobs = _health_jobs(app_session)
    assert sorted(str(j.tenant_id) for j in jobs) == sorted([str(stale.id), str(never.id)])
    assert all(j.created_by is None for j in jobs)
    created = [e for e in _events(app_session) if e.action == "job.created"]
    assert {e.actor for e in created} == {"system"}

    worker.drain()  # runs both; their last check becomes "now"
    assert {j.status for j in _health_jobs(app_session)} == {JobStatus.succeeded}
    assert enqueue_due_health_checks(app_session) == 0
    app_session.expire_all()
    fresh = app_session.get(Tenant, never.id)
    assert fresh is not None and fresh.status == TenantStatus.active


# --- `gamut worker` ------------------------------------------------------------------

def test_cli_worker_loads_key_and_stops_on_sigterm(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, credential_keys: Keys,
) -> None:
    from app import cli
    from app.crypto.envelope import write_private_key
    from app.settings import get_settings
    from app.worker import loop

    key_file = tmp_path / "worker.key"
    write_private_key(credential_keys[0], key_file)
    monkeypatch.setenv("GAMUT_ROLE", "worker")
    monkeypatch.setenv("GAMUT_DATABASE_URL", "postgresql+psycopg://x:x@localhost/x")
    monkeypatch.setenv("GAMUT_CREDENTIAL_PRIVATE_KEY_FILE", str(key_file))
    get_settings.cache_clear()
    seen: dict[str, Any] = {}

    def fake_run_forever(stop: threading.Event, private_key: X25519PrivateKey,
                         **kwargs: Any) -> None:
        seen["key"] = private_key
        seen["worker_id"] = kwargs["worker_id"]
        handler = signal.getsignal(signal.SIGTERM)
        assert callable(handler)
        handler(signal.SIGTERM, None)
        seen["stopped"] = stop.is_set()

    before = signal.getsignal(signal.SIGTERM)
    monkeypatch.setattr(loop, "run_forever", fake_run_forever)
    try:
        assert cli.main(["worker"]) == 0
    finally:
        get_settings.cache_clear()
    assert seen["stopped"] is True
    assert seen["worker_id"].endswith(f":{os.getpid()}")
    pub = seen["key"].public_key().public_bytes_raw()
    assert pub == credential_keys[0].public_key().public_bytes_raw()
    assert signal.getsignal(signal.SIGTERM) == before  # restored


def test_cli_worker_refuses_without_key(monkeypatch: pytest.MonkeyPatch) -> None:
    from app import cli
    from app.settings import get_settings

    monkeypatch.setenv("GAMUT_ROLE", "worker")
    monkeypatch.setenv("GAMUT_DATABASE_URL", "postgresql+psycopg://x:x@localhost/x")
    monkeypatch.setenv("GAMUT_CREDENTIAL_PRIVATE_KEY_FILE", "/nonexistent/key")
    get_settings.cache_clear()
    try:
        with pytest.raises(SystemExit) as exc:
            cli.main(["worker"])
    finally:
        get_settings.cache_clear()
    assert exc.value.code == "credential private key missing"
