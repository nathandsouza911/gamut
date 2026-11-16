# SPDX-License-Identifier: AGPL-3.0-only
"""The offboarding workflow, run by the in-process worker loop against the fake gam.

Jobs are created the way the UI creates them: preview, then confirm with the preview
token. Step order (ruling R10, docs/decisions.md): reset_password, signout, deprovision,
auto_reply, suspend, record_groups, remove_groups, drive_transfer, schedule_delete.
"""

import json
import logging
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.audit.chain import verify_chain
from app.models import (
    AuditEvent,
    Job,
    JobStatus,
    JobStep,
    Membership,
    Role,
    ScheduledAction,
    ScheduledStatus,
    StepStatus,
    Tenant,
    User,
)
from tests.conftest import WorkerDriver

Login = Callable[[TestClient, User], str]

TRANSFER_HEADER = (
    "id,requestTime,oldOwnerUserEmail,newOwnerUserEmail,overallTransferStatusCode,"
    "application,applicationId,status\n"
)
GROUPS_CSV = (
    "User,Group,Role,Status,Delivery\n"
    "leaver@{d},staff@{d},MEMBER,ACTIVE,ALL_MAIL\n"
    "leaver@{d},owners@{d},OWNER,ACTIVE,DIGEST\n"
)


class Offboard:
    """A ready tenant, a signed-in technician, and helpers around the API."""

    def __init__(self, client: TestClient, tenant: Tenant, session: Session) -> None:
        self.client = client
        self.tenant = tenant
        self.session = session
        self.domain = tenant.primary_domain
        self.user = f"leaver@{self.domain}"
        self.manager = f"manager@{self.domain}"

    def url(self, path: str) -> str:
        return f"/api/tenants/{self.tenant.id}{path}"

    def preview(self, params: dict[str, Any]) -> Any:
        return self.client.post(self.url("/workflows/offboarding/preview"), json=params)

    def create(self, params: dict[str, Any]) -> dict[str, Any]:
        p = self.preview(params)
        assert p.status_code == 200, p.text
        r = self.client.post(self.url("/jobs"), json={
            "workflow": "offboarding", "params": params,
            "preview_token": p.json()["preview_token"],
        })
        assert r.status_code == 201, r.text
        body: dict[str, Any] = r.json()
        return body

    def job(self, job_id: str) -> Job:
        self.session.expire_all()
        job = self.session.get(Job, uuid.UUID(job_id))
        assert job is not None
        return job

    def steps(self, job_id: str) -> dict[str, JobStep]:
        self.session.expire_all()
        rows = self.session.scalars(
            select(JobStep).where(JobStep.job_id == uuid.UUID(job_id)).order_by(JobStep.position)
        )
        return {s.key: s for s in rows}

    def actions(self, job_id: str) -> list[ScheduledAction]:
        self.session.expire_all()
        return list(self.session.scalars(
            select(ScheduledAction).where(ScheduledAction.job_id == uuid.UUID(job_id))
        ))

    def full_params(self, **overrides: Any) -> dict[str, Any]:
        params: dict[str, Any] = {
            "user": f"  Leaver@{self.domain.upper()} ",
            "auto_reply": {"subject": "Out of office",
                           "message": 'I have left.\nWrite to "manager" $(not run)'},
            "transfer_drive_to": self.manager,
            "delete_after_days": 30,
            "confirm_delete_email": self.user,
        }
        params.update(overrides)
        return params

    def only(self, **overrides: Any) -> dict[str, Any]:
        """Only the mandatory suspend step, plus `overrides`."""
        params: dict[str, Any] = {
            "user": self.user, "reset_password": False, "signout": False,
            "deprovision": False, "remove_groups": False,
        }
        params.update(overrides)
        return params


@pytest.fixture
def off(
    client: TestClient, login_as: Login, make_user: Callable[..., User],
    make_ready_tenant: Callable[..., Tenant], app_session: Session,
) -> Offboard:
    tenant = make_ready_tenant()
    tech = make_user(email=f"tech-{uuid.uuid4().hex[:6]}@example.com")
    app_session.add(Membership(user_id=tech.id, tenant_id=tenant.id, role=Role.technician))
    login_as(client, tech)
    return Offboard(client, tenant, app_session)


def _iso(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _transfer_row(tid: str, status: str, when: datetime, old: str, new: str) -> str:
    return f"{tid},{_iso(when)},{old},{new},{status},Drive and Docs,55656082996,{status}\n"


GOOGLE_ID = "104857600000000000042"


def _not_suspended(user: str) -> dict[str, Any]:
    return {"match": ["info", "user", user],
            "stdout": json.dumps({"id": GOOGLE_ID, "primaryEmail": user,
                                  "suspended": False}) + "\n"}


def _suspended_by_id(user: str) -> dict[str, Any]:
    """`info user uid:<id>` (the scheduled deletion's check): still that user, suspended."""
    return {"match": ["info", "user", f"uid:{GOOGLE_ID}"],
            "stdout": json.dumps({"id": GOOGLE_ID, "primaryEmail": user,
                                  "suspended": True}) + "\n"}


def _argvs(fake_gam: Any) -> list[list[str]]:
    return [c["argv"] for c in fake_gam.calls()]


# --- Full run ------------------------------------------------------------------------

def test_full_run_issues_steps_in_order(
    off: Offboard, fake_gam: Any, worker: WorkerDriver, app_session: Session
) -> None:
    u, m = off.user, off.manager
    soon = datetime.now(UTC) + timedelta(minutes=1)
    fake_gam.scenario([
        _not_suspended(u),
        {"match": ["user", u, "print", "groups"], "stdout": GROUPS_CSV.format(d=off.domain)},
        {"match": ["print", "datatransfers"], "replies": [
            {"stdout": TRANSFER_HEADER},
            {"stdout": TRANSFER_HEADER + _transfer_row("T1", "pending", soon, u, m)},
            {"stdout": TRANSFER_HEADER + _transfer_row("T1", "completed", soon, u, m)},
        ]},
    ])
    created = off.create(off.full_params())
    assert created["status"] == "queued"
    assert [s["key"] for s in created["steps"]] == [
        "reset_password", "signout", "deprovision", "auto_reply", "suspend",
        "record_groups", "remove_groups", "drive_transfer", "schedule_delete",
    ]

    worker.drain()
    assert off.job(created["id"]).status == JobStatus.waiting
    transfer = off.steps(created["id"])["drive_transfer"]
    assert transfer.status == StepStatus.waiting and transfer.data["transfer_id"] == "T1"

    worker.make_due(uuid.UUID(created["id"]))
    worker.drain()
    job = off.job(created["id"])
    assert job.status == JobStatus.succeeded, {k: (s.status, s.output) for k, s in
                                               off.steps(created["id"]).items()}

    subject = "Out of office"
    message = 'I have left.\nWrite to "manager" $(not run)'
    listing = ["print", "datatransfers", "olduser", u, "newuser", m]
    assert _argvs(fake_gam) == [
        ["update", "user", u, "password", "random"],
        ["user", u, "signout"],
        ["user", u, "deprovision"],
        ["user", u, "vacation", "on", "subject", subject, "message", message],
        ["info", "user", u, "quick", "formatjson"],
        ["update", "user", u, "suspended", "on"],
        ["user", u, "print", "groups"],
        ["user", u, "delete", "groups"],
        listing,
        ["create", "datatransfer", u, "gdrive", m],
        listing,
        listing,  # the poll after the wait
    ]
    steps = off.steps(created["id"])
    assert all(s.status == StepStatus.succeeded for s in steps.values())
    assert steps["auto_reply"].args == [
        "user", u, "vacation", "on", "subject", "[redacted]", "message", "[redacted]"
    ]
    (action,) = off.actions(created["id"])
    assert action.action == "delete_user" and action.status == ScheduledStatus.scheduled
    expected = datetime.now(UTC) + timedelta(days=30)
    assert abs((action.run_at - expected).total_seconds()) < 120
    assert steps["schedule_delete"].data["action_id"] == str(action.id)
    assert verify_chain(app_session).ok


def test_unselected_steps_absent(off: Offboard, fake_gam: Any, worker: WorkerDriver) -> None:
    fake_gam.scenario([_not_suspended(off.user)])
    created = off.create(off.only())
    assert [s["key"] for s in created["steps"]] == ["suspend"]
    assert created["steps"][0]["optional"] is False
    worker.drain()
    assert off.job(created["id"]).status == JobStatus.succeeded
    assert _argvs(fake_gam) == [
        ["info", "user", off.user, "quick", "formatjson"],
        ["update", "user", off.user, "suspended", "on"],
    ]
    assert off.actions(created["id"]) == []


def test_rerun_is_idempotent(
    off: Offboard, fake_gam: Any, worker: WorkerDriver, app_session: Session
) -> None:
    u, m = off.user, off.manager
    soon = datetime.now(UTC) + timedelta(minutes=1)
    fake_gam.scenario([
        _not_suspended(u),
        {"match": ["user", u, "print", "groups"], "stdout": GROUPS_CSV.format(d=off.domain)},
        {"match": ["print", "datatransfers"], "replies": [
            {"stdout": TRANSFER_HEADER},
            {"stdout": TRANSFER_HEADER + _transfer_row("T1", "completed", soon, u, m)},
        ]},
    ])
    created = off.create(off.full_params(auto_reply=None))
    worker.drain()
    job_id = uuid.UUID(created["id"])
    assert off.job(created["id"]).status == JobStatus.succeeded
    first = len(fake_gam.calls())

    # Run the whole job again (as a worker crash and reclaim would): every step pending.
    app_session.execute(update(JobStep).where(JobStep.job_id == job_id)
                        .values(status=StepStatus.pending))
    app_session.execute(update(Job).where(Job.id == job_id).values(status=JobStatus.queued))
    app_session.commit()
    fake_gam.scenario([
        {"match": ["info", "user", u],
         "stdout": json.dumps({"primaryEmail": u, "suspended": True}) + "\n"},
        {"match": ["print", "datatransfers"],
         "stdout": TRANSFER_HEADER + _transfer_row("T1", "completed", soon, u, m)},
    ])
    worker.drain()
    assert off.job(created["id"]).status == JobStatus.succeeded
    again = _argvs(fake_gam)[first:]
    assert ["update", "user", u, "suspended", "on"] not in again  # already suspended
    assert ["info", "user", u, "quick", "formatjson"] in again
    assert not [a for a in again if a[:2] == ["create", "datatransfer"]]  # polled instead
    assert ["print", "datatransfers", "olduser", u, "newuser", m] in again
    assert len(off.actions(created["id"])) == 1  # deletion not scheduled twice
    steps = off.steps(created["id"])
    assert steps["drive_transfer"].data["transfer_id"] == "T1"
    assert "already suspended" in (steps["suspend"].output or "").lower()


# --- Secrets -------------------------------------------------------------------------

def test_password_never_stored(
    off: Offboard, fake_gam: Any, worker: WorkerDriver, app_session: Session,
    caplog: pytest.LogCaptureFixture, capfd: pytest.CaptureFixture[str],
) -> None:
    caplog.set_level(logging.DEBUG)
    secret = "S3cr3t!"
    fake_gam.scenario([
        {"match": ["update", "user", off.user, "password"], "stdout": f"password: {secret}\n",
         "stderr": f"note {secret}\n"},
        _not_suspended(off.user),
    ])
    created = off.create(off.only(reset_password=True))
    worker.drain()
    assert off.job(created["id"]).status == JobStatus.succeeded
    steps = off.steps(created["id"])
    assert "not stored" in (steps["reset_password"].output or "")

    detail = off.client.get(off.url(f"/jobs/{created['id']}"))
    assert detail.status_code == 200
    app_session.expire_all()
    stored = [json.dumps([s.output, s.args, s.data]) for s in steps.values()]
    stored.append(json.dumps(off.job(created["id"]).params))
    stored += [json.dumps(e.details) for e in app_session.scalars(select(AuditEvent))]
    stored += [detail.text, caplog.text, *capfd.readouterr()]
    for text in stored:
        assert secret not in text

    # A failed reset does not show GAM's output either.
    fake_gam.scenario([{"match": ["update", "user", off.user, "password"], "exit": 50,
                        "stdout": f"password: {secret}\n"}])
    failed = off.create(off.only(reset_password=True, signout=True))
    worker.drain()
    step = off.steps(failed["id"])["reset_password"]
    assert step.status == StepStatus.failed and step.exit_code == 50
    assert secret not in (step.output or "") and "50" in (step.output or "")


def test_auto_reply_text_is_not_stored_in_clear(
    off: Offboard, fake_gam: Any, worker: WorkerDriver, app_session: Session
) -> None:
    message = "Private farewell text 7f3a"
    fake_gam.scenario([
        {"match": ["user", off.user, "vacation"], "stdout": f"echo {message}\n"},
        _not_suspended(off.user),
    ])
    created = off.create(off.only(auto_reply={"subject": "Gone 9q2", "message": message}))
    worker.drain()
    assert off.job(created["id"]).status == JobStatus.succeeded
    sent = [a for a in _argvs(fake_gam) if "vacation" in a]
    assert sent == [["user", off.user, "vacation", "on", "subject", "Gone 9q2",
                     "message", message]]
    app_session.expire_all()
    job = off.job(created["id"])
    assert job.params["auto_reply"] == {"subject": "[redacted]", "message": "[redacted]"}
    texts = [json.dumps(job.params), off.client.get(off.url(f"/jobs/{created['id']}")).text]
    texts += [json.dumps([s.output, s.args, s.data]) for s in off.steps(created["id"]).values()]
    texts += [json.dumps(e.details) for e in app_session.scalars(select(AuditEvent))]
    for text in texts:
        assert message not in text and "Gone 9q2" not in text


# --- Groups --------------------------------------------------------------------------

def test_groups_recorded_before_removal(
    off: Offboard, fake_gam: Any, worker: WorkerDriver, app_session: Session
) -> None:
    d = off.domain
    both = [
        {"group": f"staff@{d}", "role": "MEMBER", "status": "ACTIVE", "delivery": "ALL_MAIL"},
        {"group": f"owners@{d}", "role": "OWNER", "status": "ACTIVE", "delivery": "DIGEST"},
    ]
    fake_gam.scenario([
        _not_suspended(off.user),
        {"match": ["user", off.user, "print", "groups"], "stdout": GROUPS_CSV.format(d=d)},
        {"match": ["user", off.user, "delete", "groups"], "exit": 50, "stderr": "boom\n"},
    ])
    created = off.create(off.only(remove_groups=True))
    assert [s["key"] for s in created["steps"]] == ["suspend", "record_groups", "remove_groups"]
    worker.drain()
    argvs = _argvs(fake_gam)
    assert argvs.index(["user", off.user, "print", "groups"]) < argvs.index(
        ["user", off.user, "delete", "groups"])
    steps = off.steps(created["id"])
    # The list is committed by its own step, before the removal starts.
    assert steps["record_groups"].status == StepStatus.succeeded
    assert steps["record_groups"].data["groups"] == both
    assert steps["remove_groups"].status == StepStatus.failed
    assert f"staff@{d}" in (steps["remove_groups"].output or "")
    recorded = _events(app_session, "job.step.succeeded")
    assert [e.details["data"]["groups"] for e in recorded
            if e.details["step"] == "record_groups"] == [both]

    # The whole job runs again after a partial removal: GAM now lists one group, and
    # the record still holds both.
    fake_gam.scenario([
        {"match": ["info", "user", off.user],
         "stdout": json.dumps({"primaryEmail": off.user, "suspended": True}) + "\n"},
        {"match": ["user", off.user, "print", "groups"],
         "stdout": "User,Group,Role,Status,Delivery\n"
                   f"{off.user},owners@{d},OWNER,ACTIVE,DIGEST\n"},
    ])
    _requeue(app_session, created["id"])
    worker.drain()
    steps = off.steps(created["id"])
    assert steps["remove_groups"].status == StepStatus.succeeded
    assert steps["record_groups"].data["groups"] == both


def _requeue(session: Session, job_id: str, only: str | None = None) -> None:
    """Make every step (or only the step `only`) pending again and queue the job."""
    jid = uuid.UUID(job_id)
    if only is None:
        session.execute(update(JobStep).where(JobStep.job_id == jid)
                        .values(status=StepStatus.pending))
    else:
        session.execute(update(JobStep).where(JobStep.job_id == jid)
                        .values(status=StepStatus.succeeded))
        session.execute(update(JobStep).where(JobStep.job_id == jid, JobStep.key == only)
                        .values(status=StepStatus.pending))
    session.execute(update(Job).where(Job.id == jid).values(status=JobStatus.queued))
    session.commit()


def test_failing_rerun_keeps_recorded_step_data(
    off: Offboard, fake_gam: Any, worker: WorkerDriver, app_session: Session
) -> None:
    """An exception in a re-run must not wipe what earlier runs recorded."""
    u, m, d = off.user, off.manager, off.domain
    soon = datetime.now(UTC) + timedelta(minutes=1)
    fake_gam.scenario([
        _not_suspended(u),
        {"match": ["user", u, "print", "groups"], "stdout": GROUPS_CSV.format(d=d)},
        {"match": ["print", "datatransfers"], "replies": [
            {"stdout": TRANSFER_HEADER},
            {"stdout": TRANSFER_HEADER + _transfer_row("T7", "failed", soon, u, m)},
            {"stdout": TRANSFER_HEADER + _transfer_row("T7", "failed", soon, u, m)},
            {"stdout": TRANSFER_HEADER + _transfer_row("T7", "failed", soon, u, m)
             + _transfer_row("T8", "pending", soon, u, m)},
        ]},
    ])
    created = off.create(off.only(remove_groups=True, transfer_drive_to=m))
    worker.drain()  # T7 fails
    steps = off.steps(created["id"])
    assert steps["drive_transfer"].data["failed_transfer_ids"] == ["T7"]
    retry = f"/jobs/{created['id']}/steps/{steps['drive_transfer'].id}/retry"
    assert off.client.post(off.url(retry)).status_code == 200
    worker.drain()  # a new transfer, T8, is waiting
    steps = off.steps(created["id"])
    assert steps["drive_transfer"].data["transfer_id"] == "T8"
    groups = steps["record_groups"].data["groups"]
    assert len(groups) == 2

    # GAM now answers both reads with output that cannot be parsed (ValueError).
    fake_gam.scenario([
        _not_suspended(u),
        {"match": ["user", u, "print", "groups"], "stdout": "ERROR: something odd\n"},
        {"match": ["print", "datatransfers"], "stdout": "ERROR: something odd\n"},
    ])
    _requeue(app_session, created["id"], only="record_groups")
    worker.drain()
    step = off.steps(created["id"])["record_groups"]
    assert step.status == StepStatus.failed
    assert "unexpected output" in (step.output or "")
    assert step.data["groups"] == groups  # kept

    _requeue(app_session, created["id"], only="drive_transfer")
    worker.drain()
    step = off.steps(created["id"])["drive_transfer"]
    assert step.status == StepStatus.failed
    assert step.data["transfer_id"] == "T8"
    assert step.data["failed_transfer_ids"] == ["T7"]


# --- Drive transfer ------------------------------------------------------------------

def test_drive_transfer_waits_then_completes(
    off: Offboard, fake_gam: Any, worker: WorkerDriver
) -> None:
    u, m = off.user, off.manager
    soon = datetime.now(UTC) + timedelta(minutes=1)
    # A completed transfer from an earlier offboarding of the same pair must not block.
    stale = _transfer_row("OLD", "completed", datetime.now(UTC) - timedelta(days=200), u, m)
    fake_gam.scenario([
        _not_suspended(u),
        {"match": ["print", "datatransfers"], "replies": [
            {"stdout": TRANSFER_HEADER + stale},
            {"stdout": TRANSFER_HEADER + stale + _transfer_row("T2", "pending", soon, u, m)},
            {"stdout": TRANSFER_HEADER + stale + _transfer_row("T2", "inProgress", soon, u, m)},
            {"stdout": TRANSFER_HEADER + stale + _transfer_row("T2", "completed", soon, u, m)},
        ]},
    ])
    created = off.create(off.only(transfer_drive_to=m))
    job_id = uuid.UUID(created["id"])
    worker.drain()
    step = off.steps(created["id"])["drive_transfer"]
    assert step.status == StepStatus.waiting and step.poll_attempts == 1
    assert step.data["transfer_id"] == "T2" and step.next_poll_at is not None
    assert off.job(created["id"]).status == JobStatus.waiting

    worker.make_due(job_id)
    worker.drain()
    step = off.steps(created["id"])["drive_transfer"]
    assert step.status == StepStatus.waiting and step.poll_attempts == 2

    worker.make_due(job_id)
    worker.drain()
    step = off.steps(created["id"])["drive_transfer"]
    assert step.status == StepStatus.succeeded and "completed" in (step.output or "")
    assert off.job(created["id"]).status == JobStatus.succeeded
    creates = [a for a in _argvs(fake_gam) if a[:2] == ["create", "datatransfer"]]
    assert creates == [["create", "datatransfer", u, "gdrive", m]]


def test_drive_transfer_adopts_a_transfer_started_for_this_job(
    off: Offboard, fake_gam: Any, worker: WorkerDriver
) -> None:
    """A worker that died after creating the transfer: the next run adopts it."""
    u, m = off.user, off.manager
    soon = datetime.now(UTC) + timedelta(minutes=1)
    fake_gam.scenario([
        _not_suspended(u),
        {"match": ["print", "datatransfers"],
         "stdout": TRANSFER_HEADER + _transfer_row("T3", "inProgress", soon, u, m)},
    ])
    created = off.create(off.only(transfer_drive_to=m))
    worker.drain()
    step = off.steps(created["id"])["drive_transfer"]
    assert step.status == StepStatus.waiting and step.data["transfer_id"] == "T3"
    assert not [a for a in _argvs(fake_gam) if a[:2] == ["create", "datatransfer"]]


def test_failed_transfer_fails_the_step_and_retry_creates_a_new_one(
    off: Offboard, fake_gam: Any, worker: WorkerDriver
) -> None:
    u, m = off.user, off.manager
    soon = datetime.now(UTC) + timedelta(minutes=1)
    failed_row = _transfer_row("T4", "failed", soon, u, m)
    fake_gam.scenario([
        _not_suspended(u),
        {"match": ["print", "datatransfers"], "replies": [
            {"stdout": TRANSFER_HEADER},
            {"stdout": TRANSFER_HEADER + failed_row},
            {"stdout": TRANSFER_HEADER + failed_row},
            {"stdout": TRANSFER_HEADER + failed_row + _transfer_row("T5", "completed", soon, u, m)},
        ]},
    ])
    created = off.create(off.only(transfer_drive_to=m))
    worker.drain()
    step = off.steps(created["id"])["drive_transfer"]
    assert step.status == StepStatus.failed and "T4" in (step.output or "")
    assert off.job(created["id"]).status == JobStatus.failed

    r = off.client.post(off.url(f"/jobs/{created['id']}/steps/{step.id}/retry"))
    assert r.status_code == 200, r.text
    worker.drain()
    step = off.steps(created["id"])["drive_transfer"]
    assert step.status == StepStatus.succeeded and step.data["transfer_id"] == "T5"
    assert len([a for a in _argvs(fake_gam) if a[:2] == ["create", "datatransfer"]]) == 2


# --- Scheduled deletion ---------------------------------------------------------------

def _make_actions_due(session: Session, job_id: str) -> None:
    session.execute(update(ScheduledAction)
                    .where(ScheduledAction.job_id == uuid.UUID(job_id))
                    .values(run_at=datetime.now(UTC) - timedelta(seconds=1)))
    session.commit()


def _events(session: Session, action: str) -> list[AuditEvent]:
    session.expire_all()
    return list(session.scalars(
        select(AuditEvent).where(AuditEvent.action == action).order_by(AuditEvent.id)
    ))


def test_delete_refused_if_transfer_incomplete(
    off: Offboard, fake_gam: Any, worker: WorkerDriver, app_session: Session
) -> None:
    u, m = off.user, off.manager
    soon = datetime.now(UTC) + timedelta(minutes=1)
    fake_gam.scenario([
        _not_suspended(u),
        {"match": ["print", "datatransfers"], "replies": [
            {"stdout": TRANSFER_HEADER},
            {"stdout": TRANSFER_HEADER + _transfer_row("T6", "failed", soon, u, m)},
        ]},
    ])
    created = off.create(off.only(transfer_drive_to=m, delete_after_days=7,
                                  confirm_delete_email=u))
    worker.drain()
    step = off.steps(created["id"])["drive_transfer"]
    assert step.status == StepStatus.failed
    # The technician skips the failed transfer; the deletion is still scheduled...
    r = off.client.post(off.url(f"/jobs/{created['id']}/steps/{step.id}/skip"))
    assert r.status_code == 200, r.text
    worker.drain()
    assert off.job(created["id"]).status == JobStatus.succeeded
    (action,) = off.actions(created["id"])
    assert action.status == ScheduledStatus.scheduled

    # ...but refuses to run, because the Drive transfer did not complete.
    _make_actions_due(app_session, created["id"])
    worker.drain()
    (action,) = off.actions(created["id"])
    assert action.status == ScheduledStatus.refused
    assert "Drive transfer" in (action.result or "")
    assert not [a for a in _argvs(fake_gam) if a[:2] == ["delete", "user"]]
    refused = _events(app_session, "scheduled_action.refused")
    assert len(refused) == 1 and refused[0].target == u


def test_job_and_action_directories_are_prepared_before_gam_runs(
    off: Offboard, fake_gam: Any, worker: WorkerDriver, app_session: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Each job run and each scheduled action lets GAM initialise its fresh config
    directory once (app.gam.runner.prepare_config_dir) before any step's command."""
    import app.jobs.execute as execute
    import app.jobs.scheduled as scheduled

    prepared: list[tuple[str, int]] = []

    def record(where: str) -> Callable[[Any], None]:
        def _prepare(cfg_dir: Any) -> None:
            assert (cfg_dir / "oauth2.txt").exists()
            prepared.append((where, len(fake_gam.calls())))
        return _prepare

    monkeypatch.setattr(execute, "prepare_config_dir", record("job"))
    monkeypatch.setattr(scheduled, "prepare_config_dir", record("action"))
    u = off.user
    fake_gam.scenario([_not_suspended(u), _suspended_by_id(u)])
    created = off.create(off.only(delete_after_days=1, confirm_delete_email=u))
    worker.drain()
    assert prepared == [("job", 0)]  # before the job's first GAM command
    before = len(fake_gam.calls())
    _make_actions_due(app_session, created["id"])
    worker.drain()
    assert prepared == [("job", 0), ("action", before)]


def test_scheduled_delete_runs_and_is_idempotent(
    off: Offboard, fake_gam: Any, worker: WorkerDriver, app_session: Session
) -> None:
    u = off.user
    uid = f"uid:{GOOGLE_ID}"
    fake_gam.scenario([_not_suspended(u), _suspended_by_id(u)])
    created = off.create(off.only(delete_after_days=1, confirm_delete_email=u))
    worker.drain()
    _make_actions_due(app_session, created["id"])
    worker.drain()
    (action,) = off.actions(created["id"])
    assert action.status == ScheduledStatus.done, action.result
    # The account is deleted by its Google id, never by the address.
    assert ["delete", "user", uid] in _argvs(fake_gam)
    assert ["delete", "user", u] not in _argvs(fake_gam)
    assert _events(app_session, "scheduled_action.done")[0].details["argv"] == [
        "delete", "user", uid]

    # The account is already gone (GAM exit 56, ENTITY_DOES_NOT_EXIST_RC): done, no delete.
    second = off.create(off.only(delete_after_days=2, confirm_delete_email=u))
    worker.drain()
    before = len(fake_gam.calls())
    fake_gam.scenario([{"match": ["info", "user", uid], "exit": 56,
                        "stderr": f"User: {GOOGLE_ID}, Does not exist\n"}])
    _make_actions_due(app_session, second["id"])
    worker.drain()
    (action,) = off.actions(second["id"])
    assert action.status == ScheduledStatus.done
    assert "already" in (action.result or "")
    assert _argvs(fake_gam)[before:] == [["info", "user", uid, "quick", "formatjson"]]


def test_delete_cancellable_until_run(
    off: Offboard, fake_gam: Any, worker: WorkerDriver, app_session: Session
) -> None:
    u = off.user
    fake_gam.scenario([_not_suspended(u)])
    created = off.create(off.only(delete_after_days=30, confirm_delete_email=u))
    worker.drain()
    (action,) = off.actions(created["id"])
    detail = off.client.get(off.url(f"/jobs/{created['id']}")).json()
    assert [a["id"] for a in detail["scheduled_actions"]] == [str(action.id)]
    assert detail["scheduled_actions"][0]["status"] == "scheduled"

    r = off.client.post(off.url(f"/scheduled-actions/{action.id}/cancel"))
    assert r.status_code == 200 and r.json()["status"] == "cancelled"
    _make_actions_due(app_session, created["id"])
    worker.drain()
    (action,) = off.actions(created["id"])
    assert action.status == ScheduledStatus.cancelled
    assert not [a for a in _argvs(fake_gam) if a[:2] == ["delete", "user"]]
    assert off.client.post(off.url(f"/scheduled-actions/{action.id}/cancel")).status_code == 409

    # Once it has run, it can no longer be cancelled.
    fake_gam.scenario([_not_suspended(u), _suspended_by_id(u)])
    ran = off.create(off.only(delete_after_days=1, confirm_delete_email=u))
    worker.drain()
    _make_actions_due(app_session, ran["id"])
    worker.drain()
    (done,) = off.actions(ran["id"])
    assert done.status == ScheduledStatus.done
    assert off.client.post(off.url(f"/scheduled-actions/{done.id}/cancel")).status_code == 409
    assert off.client.post(off.url(f"/scheduled-actions/{uuid.uuid4()}/cancel")).status_code == 404


def test_delete_requires_second_confirmation(off: Offboard) -> None:
    u = off.user
    for confirm in (None, f"other@{off.domain}"):
        r = off.preview(off.only(delete_after_days=30, confirm_delete_email=confirm))
        assert r.status_code == 422, r.text
        assert any("confirm_delete_email" in e["loc"] for e in r.json()["detail"])
    for days in (0, 366):
        r = off.preview(off.only(delete_after_days=days, confirm_delete_email=u))
        assert r.status_code == 422
    # The confirmation is compared after normalization.
    r = off.preview(off.only(delete_after_days=30, confirm_delete_email=f" {u.upper()}"))
    assert r.status_code == 200, r.text
    assert r.json()["steps"][-1]["key"] == "schedule_delete"
