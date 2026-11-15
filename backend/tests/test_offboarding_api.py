# SPDX-License-Identifier: AGPL-3.0-only
"""Offboarding HTTP routes: preview, confirm (idempotent), jobs, retry, skip, roles."""

import json
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import AuditEvent, Job, JobStatus, Membership, Role, Tenant, TenantStatus, User
from tests.conftest import WorkerDriver

Login = Callable[[TestClient, User], str]


@pytest.fixture
def tenant(make_ready_tenant: Callable[..., Tenant]) -> Tenant:
    return make_ready_tenant(primary_domain="acme.com", domains=["acme.com", "acme.org"])


def _member(
    make_user: Callable[..., User], session: Session, tenant: Tenant, role: Role
) -> User:
    user = make_user(email=f"{role.value}-{uuid.uuid4().hex[:6]}@example.com")
    session.add(Membership(user_id=user.id, tenant_id=tenant.id, role=role))
    return user


@pytest.fixture
def tech(
    client: TestClient, login_as: Login, make_user: Callable[..., User], app_session: Session,
    tenant: Tenant,
) -> TestClient:
    login_as(client, _member(make_user, app_session, tenant, Role.technician))
    return client


def _preview(client: TestClient, tenant: Tenant, params: dict[str, Any]) -> Any:
    return client.post(f"/api/tenants/{tenant.id}/workflows/offboarding/preview", json=params)


def _confirm(client: TestClient, tenant: Tenant, params: dict[str, Any], token: str) -> Any:
    return client.post(f"/api/tenants/{tenant.id}/jobs", json={
        "workflow": "offboarding", "params": params, "preview_token": token,
    })


def _count(session: Session, model: Any) -> int:
    session.expire_all()
    return int(session.scalar(select(func.count()).select_from(model)) or 0)


PARAMS: dict[str, Any] = {
    "user": "leaver@acme.com",
    "auto_reply": {"subject": "Away", "message": "Gone"},
    "transfer_drive_to": "boss@acme.org",
}


def test_preview_has_no_side_effects(
    tech: TestClient, tenant: Tenant, app_session: Session, fake_gam: Any
) -> None:
    events_before = _count(app_session, AuditEvent)
    r = _preview(tech, tenant, {**PARAMS, "delete_after_days": 30,
                                "confirm_delete_email": "leaver@acme.com"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["preview_token"]
    assert [s["key"] for s in body["steps"]] == [
        "reset_password", "signout", "deprovision", "auto_reply", "suspend",
        "remove_groups", "drive_transfer", "schedule_delete",
    ]
    by_key = {s["key"]: s for s in body["steps"]}
    assert by_key["suspend"]["args_display"] == "gam update user leaver@acme.com suspended on"
    assert by_key["auto_reply"]["args_display"] == (
        "gam user leaver@acme.com vacation on subject '[redacted]' message '[redacted]'")
    assert by_key["drive_transfer"]["args_display"] == (
        "gam create datatransfer leaver@acme.com gdrive boss@acme.org")
    assert by_key["schedule_delete"]["args_display"] == "gam delete user leaver@acme.com"
    assert all(s["title"] for s in body["steps"])

    assert _count(app_session, Job) == 0
    assert fake_gam.calls() == []
    events = list(app_session.scalars(select(AuditEvent)))
    assert len(events) - events_before <= 1
    assert not [e for e in events if e.action.startswith("job.")]


@pytest.mark.parametrize(("field", "value"), [
    ("user", "x@acme.com.evil.io"),
    ("user", "x@evil.io"),
    ("user", "x@sub.acme.com"),
    ("transfer_drive_to", "x@acme.com.evil.io"),
    ("transfer_drive_to", "boss@evil.io"),
    ("user", "not-an-email"),
])
def test_preview_rejects_foreign_and_lookalike_domains(
    tech: TestClient, tenant: Tenant, field: str, value: str
) -> None:
    r = _preview(tech, tenant, {**PARAMS, field: value})
    assert r.status_code == 422, r.text
    locs = [e["loc"] for e in r.json()["detail"]]
    assert any(field in loc for loc in locs), locs


def test_preview_normalizes_case_and_spaces(tech: TestClient, tenant: Tenant) -> None:
    r = _preview(tech, tenant, {**PARAMS, "user": "  LeAver@ACME.com ",
                                "transfer_drive_to": "Boss@Acme.ORG"})
    assert r.status_code == 200, r.text
    suspend = next(s for s in r.json()["steps"] if s["key"] == "suspend")
    assert suspend["args_display"] == "gam update user leaver@acme.com suspended on"


def test_preview_rejects_manager_equal_user(tech: TestClient, tenant: Tenant) -> None:
    r = _preview(tech, tenant, {**PARAMS, "transfer_drive_to": " LEAVER@acme.com"})
    assert r.status_code == 422
    assert any("transfer_drive_to" in e["loc"] for e in r.json()["detail"])


def test_preview_rejects_file_reference_text(tech: TestClient, tenant: Tenant) -> None:
    r = _preview(tech, tenant, {**PARAMS, "auto_reply": {"subject": "x",
                                                         "message": "file /etc/passwd"}})
    assert r.status_code == 422
    assert any("message" in e["loc"] for e in r.json()["detail"])


def test_confirm_is_idempotent_on_preview_token(
    tech: TestClient, tenant: Tenant, app_session: Session
) -> None:
    token = _preview(tech, tenant, PARAMS).json()["preview_token"]
    first = _confirm(tech, tenant, PARAMS, token)
    assert first.status_code == 201, first.text
    again = _confirm(tech, tenant, PARAMS, token)
    assert again.status_code in (200, 201), again.text
    assert again.json()["id"] == first.json()["id"]
    assert _count(app_session, Job) == 1
    created = [e for e in app_session.scalars(select(AuditEvent))
               if e.action == "job.created"]
    assert len(created) == 1 and created[0].target == "leaver@acme.com"


def test_confirm_with_altered_params_rejected(
    tech: TestClient, tenant: Tenant, app_session: Session,
    make_client: Callable[..., TestClient], login_as: Login, make_user: Callable[..., User],
) -> None:
    token = _preview(tech, tenant, PARAMS).json()["preview_token"]
    for altered in ({**PARAMS, "user": "other@acme.com"},
                    {**PARAMS, "auto_reply": {"subject": "Away", "message": "Changed"}},
                    {**PARAMS, "remove_groups": False}):
        r = _confirm(tech, tenant, altered, token)
        assert r.status_code == 400, r.text
    assert _confirm(tech, tenant, PARAMS, token + "0").status_code == 400
    assert _confirm(tech, tenant, PARAMS, "garbage").status_code == 400
    # The same params with case/space differences are the same canonical params.
    same = {**PARAMS, "user": " LEAVER@acme.com"}
    assert _confirm(tech, tenant, same, token).status_code == 201
    # Another user cannot use this user's token.
    other = make_client()
    login_as(other, _member(make_user, app_session, tenant, Role.technician))
    assert _confirm(other, tenant, PARAMS, token).status_code == 400
    assert _count(app_session, Job) == 1


def test_expired_preview_token_rejected(
    tech: TestClient, tenant: Tenant, app_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    import app.api.workflows as workflows

    real_now = workflows._now
    monkeypatch.setattr(workflows, "_now", lambda: real_now() - timedelta(minutes=11))
    token = _preview(tech, tenant, PARAMS).json()["preview_token"]
    monkeypatch.setattr(workflows, "_now", real_now)
    r = _confirm(tech, tenant, PARAMS, token)
    assert r.status_code == 400 and "expired" in r.text
    assert _count(app_session, Job) == 0


def test_auditor_cannot_create_job(
    client: TestClient, login_as: Login, make_user: Callable[..., User],
    app_session: Session, tenant: Tenant,
) -> None:
    login_as(client, _member(make_user, app_session, tenant, Role.auditor))
    assert _preview(client, tenant, PARAMS).status_code == 403
    r = _confirm(client, tenant, PARAMS, "x")
    assert r.status_code == 403
    assert client.get(f"/api/tenants/{tenant.id}/jobs").status_code == 200
    assert _count(app_session, Job) == 0


def test_job_routes_and_roles(
    tech: TestClient, tenant: Tenant, app_session: Session, fake_gam: Any,
    worker: WorkerDriver, make_client: Callable[..., TestClient], login_as: Login,
    make_user: Callable[..., User], make_ready_tenant: Callable[..., Tenant],
) -> None:
    params = {"user": "leaver@acme.com", "signout": False, "deprovision": False,
              "remove_groups": False}
    fake_gam.scenario([{"match": ["update", "user", "leaver@acme.com", "password"], "exit": 50},
                       {"match": ["info", "user"], "stdout": '{"suspended": true}'}])
    token = _preview(tech, tenant, params).json()["preview_token"]
    job = _confirm(tech, tenant, params, token).json()
    assert set(job) >= {"id", "workflow", "status", "target", "params", "created_by",
                        "created_at", "steps", "scheduled_actions"}
    assert job["target"] == "leaver@acme.com" and "sealed" not in job["params"]
    worker.drain()

    detail = tech.get(f"/api/tenants/{tenant.id}/jobs/{job['id']}")
    assert detail.status_code == 200
    body = detail.json()
    assert body["status"] == "failed"
    steps = {s["key"]: s for s in body["steps"]}
    assert steps["reset_password"]["status"] == "failed"
    assert steps["suspend"]["status"] == "pending"
    assert set(steps["reset_password"]) >= {
        "id", "position", "key", "title", "kind", "optional", "status", "args", "exit_code",
        "output", "data", "next_poll_at", "poll_attempts", "started_at", "finished_at"}

    listing = tech.get(f"/api/tenants/{tenant.id}/jobs")
    assert listing.status_code == 200
    assert [j["id"] for j in listing.json()] == [job["id"]]
    assert listing.json()[0]["target"] == "leaver@acme.com"

    # An auditor reads but cannot retry, skip or cancel.
    auditor = make_client()
    login_as(auditor, _member(make_user, app_session, tenant, Role.auditor))
    step_id = steps["reset_password"]["id"]
    assert auditor.get(f"/api/tenants/{tenant.id}/jobs/{job['id']}").status_code == 200
    base = f"/api/tenants/{tenant.id}/jobs/{job['id']}/steps/{step_id}"
    assert auditor.post(f"{base}/retry").status_code == 403
    assert auditor.post(f"{base}/skip").status_code == 403
    assert auditor.post(
        f"/api/tenants/{tenant.id}/scheduled-actions/{uuid.uuid4()}/cancel").status_code == 403

    # Skip the failed optional step: the job runs on and succeeds.
    r = tech.post(f"{base}/skip")
    assert r.status_code == 200 and r.json()["status"] == "queued"
    assert tech.post(f"{base}/skip").status_code == 409  # no longer failed
    worker.drain()
    done = tech.get(f"/api/tenants/{tenant.id}/jobs/{job['id']}").json()
    assert done["status"] == "succeeded"
    assert [s["status"] for s in done["steps"]] == ["skipped", "succeeded"]

    # Unknown ids, and ids of another tenant the caller can also see, are 404.
    assert tech.get(f"/api/tenants/{tenant.id}/jobs/{uuid.uuid4()}").status_code == 404
    other = make_ready_tenant()
    owner = make_client()
    login_as(owner, make_user(is_owner=True))
    assert owner.get(f"/api/tenants/{other.id}/jobs/{job['id']}").status_code == 404
    assert owner.post(
        f"/api/tenants/{other.id}/jobs/{job['id']}/steps/{step_id}/retry").status_code == 404


def test_mandatory_step_cannot_be_skipped(
    tech: TestClient, tenant: Tenant, fake_gam: Any, worker: WorkerDriver
) -> None:
    params = {"user": "leaver@acme.com", "reset_password": False, "signout": False,
              "deprovision": False, "remove_groups": False}
    fake_gam.scenario([{"match": ["info", "user"], "exit": 50}])
    job = _confirm(tech, tenant, params, _preview(tech, tenant, params).json()["preview_token"])
    worker.drain()
    detail = tech.get(f"/api/tenants/{tenant.id}/jobs/{job.json()['id']}").json()
    (step,) = detail["steps"]
    assert step["key"] == "suspend" and step["status"] == "failed"
    base = f"/api/tenants/{tenant.id}/jobs/{detail['id']}/steps/{step['id']}"
    r = tech.post(f"{base}/skip")
    assert r.status_code == 409 and "optional" in r.text
    assert tech.post(f"{base}/retry").status_code == 200


def test_disabled_tenant_cannot_create_jobs(
    tech: TestClient, tenant: Tenant, app_session: Session
) -> None:
    token = _preview(tech, tenant, PARAMS).json()["preview_token"]
    tenant.status = TenantStatus.disabled
    app_session.commit()
    assert _confirm(tech, tenant, PARAMS, token).status_code == 409
    assert _preview(tech, tenant, PARAMS).status_code == 409


def test_unknown_workflow_is_422(tech: TestClient, tenant: Tenant) -> None:
    r = tech.post(f"/api/tenants/{tenant.id}/jobs", json={
        "workflow": "health_check", "params": {}, "preview_token": "x"})
    assert r.status_code == 422


def test_manual_health_check_returns_the_active_check(
    client: TestClient, login_as: Login, make_user: Callable[..., User],
    app_session: Session, tenant: Tenant,
) -> None:
    login_as(client, _member(make_user, app_session, tenant, Role.admin))
    first = client.post(f"/api/tenants/{tenant.id}/health-check")
    second = client.post(f"/api/tenants/{tenant.id}/health-check")
    assert first.status_code == second.status_code == 202
    assert first.json()["job_id"] == second.json()["job_id"]
    assert _count(app_session, Job) == 1
    job = app_session.get(Job, uuid.UUID(first.json()["job_id"]))
    assert job is not None
    job.status = JobStatus.succeeded
    job.finished_at = datetime.now(UTC)
    app_session.commit()
    third = client.post(f"/api/tenants/{tenant.id}/health-check")
    assert third.json()["job_id"] != first.json()["job_id"]


def test_stored_params_are_redacted_and_sealed(
    tech: TestClient, tenant: Tenant, app_session: Session
) -> None:
    params = {**PARAMS, "auto_reply": {"subject": "Away 51x", "message": "Body 77y"}}
    job = _confirm(tech, tenant, params, _preview(tech, tenant, params).json()["preview_token"])
    assert job.status_code == 201
    app_session.expire_all()
    row = app_session.get(Job, uuid.UUID(job.json()["id"]))
    assert row is not None
    dumped = json.dumps(row.params)
    assert "Away 51x" not in dumped and "Body 77y" not in dumped
    assert row.params["sealed"]  # the worker opens it with the private key
    assert "Body 77y" not in job.text and "sealed" not in job.text
