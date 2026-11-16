# SPDX-License-Identifier: AGPL-3.0-only
"""GET /api/tenants/{id}/dashboard."""

from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import (
    Job,
    JobStatus,
    JobStep,
    Membership,
    Role,
    ScheduledAction,
    ScheduledStatus,
    StepStatus,
    Tenant,
    TenantCredential,
    User,
)

Login = Callable[[TestClient, User], str]
NOW = datetime.now(UTC)


def _job(db: Session, tenant: Tenant, workflow: str, status: JobStatus, *,
         created: datetime, finished: datetime | None = None, params: dict | None = None) -> Job:
    job = Job(tenant_id=tenant.id, workflow=workflow, status=status, params=params or {},
              created_at=created, started_at=created, finished_at=finished)
    db.add(job)
    db.flush()
    return job


def _step(db: Session, job: Job, position: int, key: str, status: StepStatus,
          started: datetime | None = None) -> None:
    db.add(JobStep(job_id=job.id, position=position, key=key, title=key.upper(), kind="run",
                   status=status, exit_code=0 if status == StepStatus.succeeded else 1,
                   started_at=started))
    db.flush()


def _viewer(db: Session, tenant: Tenant, make_user: Callable[..., User], role: Role) -> User:
    user = make_user()
    db.add(Membership(user_id=user.id, tenant_id=tenant.id, role=role))
    db.flush()
    return user


def test_dashboard_aggregates(
    client: TestClient, login_as: Login, make_tenant: Callable[..., Tenant],
    make_user: Callable[..., User], app_session: Session,
) -> None:
    t = make_tenant()
    app_session.add(TenantCredential(
        tenant_id=t.id, ciphertext=b"x", nonce=b"x", wrapped_key=b"x", key_version=1,
        file_names=["oauth2service.json"], sa_client_email="sa@p.iam.gserviceaccount.com",
        sa_client_id="123", uploaded_at=NOW - timedelta(days=100, hours=1),
    ))
    passed = _job(app_session, t, "health_check", JobStatus.succeeded,
                  created=NOW - timedelta(hours=5), finished=NOW - timedelta(hours=4))
    failed_h = _job(app_session, t, "health_check", JobStatus.failed,
                    created=NOW - timedelta(hours=3), finished=NOW - timedelta(hours=2))
    _step(app_session, passed, 0, "info_domain", StepStatus.succeeded)
    _step(app_session, failed_h, 1, "directory_role", StepStatus.failed)
    _step(app_session, failed_h, 0, "info_domain", StepStatus.succeeded)
    _step(app_session, failed_h, 2, "mystery", StepStatus.failed)
    off_failed = _job(app_session, t, "offboarding", JobStatus.failed,
                      created=NOW - timedelta(hours=1), finished=NOW,
                      params={"target": "a@x.com"})
    off_wait = _job(app_session, t, "offboarding", JobStatus.waiting,
                    created=NOW - timedelta(hours=6), params={"target": "b@x.com"})
    waiting_at = NOW - timedelta(hours=2)
    _step(app_session, off_wait, 0, "transfer", StepStatus.waiting, started=waiting_at)
    _step(app_session, off_wait, 1, "other", StepStatus.waiting,
          started=waiting_at + timedelta(hours=1))
    for i in range(12):
        _job(app_session, t, "offboarding", JobStatus.succeeded,
             created=NOW - timedelta(days=1, minutes=i), finished=NOW)
    for i, delta in enumerate((5, 2)):
        app_session.add(ScheduledAction(
            tenant_id=t.id, job_id=off_failed.id, action="delete", params={"target": f"u{i}"},
            run_at=NOW + timedelta(days=delta), status=ScheduledStatus.scheduled))
    app_session.add(ScheduledAction(
        tenant_id=t.id, job_id=off_failed.id, action="delete", params={},
        run_at=NOW + timedelta(days=1), status=ScheduledStatus.cancelled))
    app_session.flush()
    login_as(client, _viewer(app_session, t, make_user, Role.technician))

    r = client.get(f"/api/tenants/{t.id}/dashboard")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["tenant"]["id"] == str(t.id)
    assert body["health"]["job_id"] == str(failed_h.id)
    assert body["health"]["ok"] is False
    assert [(c["key"], c["section"]) for c in body["health"]["checks"]] == [
        ("info_domain", "credentials"), ("directory_role", "roles"), ("mystery", None)]
    assert body["credentials"]["age_days"] == 100
    assert body["credentials"]["rotate_soon"] is True
    assert body["credentials"]["sa_client_id"] == "123"
    assert body["credentials"]["file_names"] == ["oauth2service.json"]
    assert [j["id"] for j in body["failed_jobs"]] == [str(off_failed.id)]
    assert [j["id"] for j in body["waiting_jobs"]] == [str(off_wait.id)]
    assert datetime.fromisoformat(body["waiting_jobs"][0]["waiting_since"]) == waiting_at
    assert [a["target"] for a in body["scheduled"]] == ["u1", "u0"]
    assert len(body["recent_jobs"]) == 10


def test_dashboard_roles_and_no_secrets(
    client: TestClient, login_as: Login, make_tenant: Callable[..., Tenant],
    make_user: Callable[..., User], app_session: Session,
) -> None:
    t = make_tenant()
    app_session.add(TenantCredential(
        tenant_id=t.id, ciphertext=b"x", nonce=b"x", wrapped_key=b"x", key_version=1,
        file_names=["oauth2service.json"]))
    app_session.flush()
    login_as(client, _viewer(app_session, t, make_user, Role.auditor))
    r = client.get(f"/api/tenants/{t.id}/dashboard")
    assert r.status_code == 200, r.text
    for word in ("private_key", "refresh_token", "client_secret"):
        assert word not in r.text


def test_dashboard_empty_tenant(
    client: TestClient, login_as: Login, make_tenant: Callable[..., Tenant],
    make_user: Callable[..., User], app_session: Session,
) -> None:
    t = make_tenant()
    login_as(client, _viewer(app_session, t, make_user, Role.auditor))
    body = client.get(f"/api/tenants/{t.id}/dashboard").json()
    assert body["health"] is None and body["credentials"] is None
    assert body["failed_jobs"] == body["waiting_jobs"] == []
    assert body["scheduled"] == [] and body["recent_jobs"] == []
