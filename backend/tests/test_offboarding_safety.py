# SPDX-License-Identifier: AGPL-3.0-only
"""Offboarding safety rules from the final review.

- The scheduled deletion deletes the Google account by its id, and only while that
  account still has the offboarded address and is suspended.
- A failed job whose suspend step has not succeeded says so (account_suspended).
- job.created carries the (redacted) parameters.
- A second active offboarding of the same user is refused (409).
- The tenant's own admin account cannot be offboarded.
"""

import json
import uuid
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.models import AuditEvent, JobStatus, ScheduledAction, ScheduledStatus, StepStatus
from tests.conftest import WorkerDriver
from tests.test_offboarding import (  # noqa: F401
    Offboard,
    _argvs,
    _events,
    _make_actions_due,
    off,
)

GID = "104857600000000000001"


def _info(user: str, *, suspended: bool, gid: str = GID, uid_match: str | None = None,
          email: str | None = None) -> dict[str, Any]:
    """A fake `info user` reply, matched by address (or by uid:<uid_match>)."""
    key = f"uid:{uid_match}" if uid_match else user
    return {"match": ["info", "user", key],
            "stdout": json.dumps({"id": gid, "primaryEmail": email or user,
                                  "suspended": suspended}) + "\n"}


def _deletion_job(off: Offboard, fake_gam: Any, worker: WorkerDriver) -> dict[str, Any]:
    fake_gam.scenario([_info(off.user, suspended=False)])
    created = off.create(off.only(delete_after_days=1, confirm_delete_email=off.user))
    worker.drain()
    assert off.job(created["id"]).status == JobStatus.succeeded
    return created


# --- Scheduled deletion by Google id --------------------------------------------------

def test_suspend_records_the_google_user_id(
    off: Offboard, fake_gam: Any, worker: WorkerDriver
) -> None:
    created = _deletion_job(off, fake_gam, worker)
    steps = off.steps(created["id"])
    assert steps["suspend"].data["google_user_id"] == GID
    (action,) = off.actions(created["id"])
    assert action.params["google_user_id"] == GID


def test_scheduled_delete_uses_the_google_id(
    off: Offboard, fake_gam: Any, worker: WorkerDriver, app_session: Session
) -> None:
    created = _deletion_job(off, fake_gam, worker)
    before = len(fake_gam.calls())
    fake_gam.scenario([_info(off.user, suspended=True, uid_match=GID)])
    _make_actions_due(app_session, created["id"])
    worker.drain()
    (action,) = off.actions(created["id"])
    assert action.status == ScheduledStatus.done, action.result
    assert _argvs(fake_gam)[before:] == [
        ["info", "user", f"uid:{GID}", "quick", "formatjson"],
        ["delete", "user", f"uid:{GID}"],
    ]
    done = _events(app_session, "scheduled_action.done")[-1]
    assert done.details["argv"] == ["delete", "user", f"uid:{GID}"]


def test_scheduled_delete_refused_when_account_was_reactivated(
    off: Offboard, fake_gam: Any, worker: WorkerDriver, app_session: Session
) -> None:
    created = _deletion_job(off, fake_gam, worker)
    fake_gam.scenario([_info(off.user, suspended=False, uid_match=GID)])
    _make_actions_due(app_session, created["id"])
    worker.drain()
    (action,) = off.actions(created["id"])
    assert action.status == ScheduledStatus.refused
    assert "not suspended" in (action.result or "")
    assert not [a for a in _argvs(fake_gam) if a[:2] == ["delete", "user"]]
    assert len(_events(app_session, "scheduled_action.refused")) == 1


def test_scheduled_delete_refused_when_the_address_moved_to_another_account(
    off: Offboard, fake_gam: Any, worker: WorkerDriver, app_session: Session
) -> None:
    created = _deletion_job(off, fake_gam, worker)
    # The offboarded account was renamed; its id now carries another address.
    fake_gam.scenario([_info(off.user, suspended=True, uid_match=GID,
                             email=f"archived-leaver@{off.domain}")])
    _make_actions_due(app_session, created["id"])
    worker.drain()
    (action,) = off.actions(created["id"])
    assert action.status == ScheduledStatus.refused
    assert "no longer" in (action.result or "")
    assert not [a for a in _argvs(fake_gam) if a[:2] == ["delete", "user"]]

    # A reply for a different id is refused too.
    second = off.create(off.only(delete_after_days=2, confirm_delete_email=off.user))
    fake_gam.scenario([_info(off.user, suspended=False)])
    worker.drain()
    fake_gam.scenario([_info(off.user, suspended=True, uid_match=GID, gid="999")])
    _make_actions_due(app_session, second["id"])
    worker.drain()
    (action,) = off.actions(second["id"])
    assert action.status == ScheduledStatus.refused
    assert not [a for a in _argvs(fake_gam) if a[:2] == ["delete", "user"]]


def test_scheduled_delete_refused_without_a_recorded_id(
    off: Offboard, fake_gam: Any, worker: WorkerDriver, app_session: Session
) -> None:
    created = _deletion_job(off, fake_gam, worker)
    app_session.execute(update(ScheduledAction)
                        .where(ScheduledAction.job_id == uuid.UUID(created["id"]))
                        .values(params={"target": off.user, "user": off.user}))
    app_session.commit()
    before = len(fake_gam.calls())
    _make_actions_due(app_session, created["id"])
    worker.drain()
    (action,) = off.actions(created["id"])
    assert action.status == ScheduledStatus.refused
    assert "Google account id" in (action.result or "")
    assert len(fake_gam.calls()) == before  # GAM never ran


def test_scheduled_delete_of_an_already_deleted_account_is_done(
    off: Offboard, fake_gam: Any, worker: WorkerDriver, app_session: Session
) -> None:
    created = _deletion_job(off, fake_gam, worker)
    fake_gam.scenario([{"match": ["info", "user", f"uid:{GID}"], "exit": 56,
                        "stderr": "User: does not exist\n"}])
    _make_actions_due(app_session, created["id"])
    worker.drain()
    (action,) = off.actions(created["id"])
    assert action.status == ScheduledStatus.done
    assert "already" in (action.result or "")
    assert not [a for a in _argvs(fake_gam) if a[:2] == ["delete", "user"]]


# --- account_suspended ------------------------------------------------------------------

def test_failed_job_reports_the_account_is_not_suspended(
    off: Offboard, fake_gam: Any, worker: WorkerDriver
) -> None:
    fake_gam.scenario([{"match": ["user", off.user, "signout"], "exit": 50, "stderr": "no\n"}])
    created = off.create(off.only(signout=True))
    worker.drain()
    detail = off.client.get(off.url(f"/jobs/{created['id']}")).json()
    assert detail["status"] == "failed"
    assert detail["account_suspended"] is False


def test_account_suspended_true_once_suspend_succeeded(
    off: Offboard, fake_gam: Any, worker: WorkerDriver
) -> None:
    fake_gam.scenario([
        _info(off.user, suspended=False),
        {"match": ["user", off.user, "print", "groups"], "exit": 50, "stderr": "no\n"},
    ])
    created = off.create(off.only(remove_groups=True))
    worker.drain()
    detail = off.client.get(off.url(f"/jobs/{created['id']}")).json()
    assert detail["status"] == "failed"
    assert detail["account_suspended"] is True
    assert off.steps(created["id"])["suspend"].status == StepStatus.succeeded


# --- job.created carries the parameters ---------------------------------------------------

def test_job_created_event_has_redacted_params(
    off: Offboard, fake_gam: Any, app_session: Session
) -> None:
    message, subject = "Farewell text 51ab", "Subject 7c"
    created = off.create(off.full_params(auto_reply={"subject": subject, "message": message}))
    app_session.expire_all()
    event = app_session.scalars(
        select(AuditEvent).where(AuditEvent.action == "job.created")).one()
    params = event.details["params"]
    assert params["user"] == off.user
    assert params["transfer_drive_to"] == off.manager
    assert params["delete_after_days"] == 30
    assert "sealed" not in params
    dumped = json.dumps(event.details)
    assert message not in dumped and subject not in dumped
    job = off.job(created["id"])
    assert json.dumps(job.params["sealed"]) not in dumped
    assert str(job.params["sealed"]["ciphertext"]) not in dumped


# --- One active offboarding per user --------------------------------------------------------

def test_second_offboarding_of_the_same_user_is_409(
    off: Offboard, fake_gam: Any, worker: WorkerDriver, app_session: Session
) -> None:
    first = off.create(off.only())
    for params in (off.only(), off.only(signout=True), off.only(user=off.user.upper())):
        r = off.preview(params)
        assert r.status_code == 409, r.text
        assert first["id"] in r.json()["detail"]

    # Another user of the same tenant is fine.
    other = off.only(user=f"other@{off.domain}")
    assert off.preview(other).status_code == 200

    # Once the job has finished, a new offboarding is allowed.
    fake_gam.scenario([_info(off.user, suspended=False)])
    worker.drain()
    assert off.job(first["id"]).status == JobStatus.succeeded
    assert off.preview(off.only()).status_code == 200


def test_repeat_confirm_returns_existing_job_and_new_token_is_409(
    off: Offboard, fake_gam: Any
) -> None:
    params, other = off.only(), off.only(signout=True)
    token = off.preview(params).json()["preview_token"]
    other_token = off.preview(other).json()["preview_token"]  # previewed before the job
    body = {"workflow": "offboarding", "params": params}
    r1 = off.client.post(off.url("/jobs"), json={**body, "preview_token": token})
    assert r1.status_code == 201
    r2 = off.client.post(off.url("/jobs"), json={**body, "preview_token": token})
    assert r2.status_code == 200 and r2.json()["id"] == r1.json()["id"]
    r3 = off.client.post(off.url("/jobs"), json={"workflow": "offboarding", "params": other,
                                                  "preview_token": other_token})
    assert r3.status_code == 409, r3.text


def test_failed_job_blocks_until_resolved(
    off: Offboard, fake_gam: Any, worker: WorkerDriver
) -> None:
    fake_gam.scenario([{"match": ["info", "user"], "exit": 50, "stderr": "boom\n"}])
    first = off.create(off.only())
    worker.drain()
    assert off.job(first["id"]).status == JobStatus.failed
    r = off.preview(off.only())
    assert r.status_code == 409 and "retry" in r.json()["detail"]


def test_pending_scheduled_delete_blocks_a_new_offboarding(
    off: Offboard, fake_gam: Any, worker: WorkerDriver, app_session: Session
) -> None:
    created = _deletion_job(off, fake_gam, worker)
    r = off.preview(off.only())
    assert r.status_code == 409 and "deletion" in r.json()["detail"]
    (action,) = off.actions(created["id"])
    assert off.client.post(off.url(f"/scheduled-actions/{action.id}/cancel")).status_code == 200
    assert off.preview(off.only()).status_code == 200


# --- The tenant's admin account ------------------------------------------------------------

def test_tenant_admin_account_cannot_be_offboarded(off: Offboard) -> None:
    admin = off.tenant.admin_email
    assert admin
    r = off.preview(off.only(user=admin.upper()))
    assert r.status_code == 422, r.text
    assert any(e["loc"][-1] == "user" and "admin" in e["msg"] for e in r.json()["detail"])
