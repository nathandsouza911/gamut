# SPDX-License-Identifier: AGPL-3.0-only
"""Tenant import: credential upload/replace/delete, tenant deletion, health check."""

import json
import os
import threading
import time
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from fastapi.testclient import TestClient
from sqlalchemy import Engine, func, select, text
from sqlalchemy.orm import Session

from app.crypto.envelope import SealedBundle, open_bundle
from app.jobs.execute import run_steps
from app.models import (
    AuditEvent,
    Job,
    JobStatus,
    JobStep,
    Membership,
    Role,
    StepStatus,
    Tenant,
    TenantCredential,
    TenantStatus,
    User,
)
from app.tenants.service import MAX_FILE_BYTES

Login = Callable[[TestClient, User], str]
Keys = tuple[X25519PrivateKey, str]

ADMIN = "gam-admin@acme.test"
OAUTH2 = json.dumps({"client_id": "cid", "client_secret": "CS-1", "refresh_token": "RT-1"})
SERVICE = json.dumps({"type": "service_account", "client_email": "sa@p.iam", "private_key": "PK"})
GOOD_FILES = {"oauth2.txt": OAUTH2.encode(), "oauth2service.json": SERVICE.encode()}
SCOPE_FAIL = "Scope: https://www.googleapis.com/auth/gmail.settings.basic FAIL\n"


def _multipart(files: dict[str, bytes]) -> list[tuple[str, tuple[str, bytes, str]]]:
    return [("files", (name, data, "application/octet-stream")) for name, data in files.items()]


def _events(session: Session, action: str) -> list[AuditEvent]:
    session.expire_all()
    return list(
        session.scalars(
            select(AuditEvent).where(AuditEvent.action == action).order_by(AuditEvent.id)
        )
    )


@pytest.fixture
def owner(make_user: Callable[..., User]) -> User:
    return make_user(email="owner@example.com", is_owner=True)


@pytest.fixture
def tenant(make_tenant: Callable[..., Tenant]) -> Tenant:
    return make_tenant(
        name="Acme", primary_domain="acme.test", status=TenantStatus.pending, admin_email=ADMIN
    )


@pytest.fixture
def owner_client(client: TestClient, login_as: Login, owner: User, tenant: Tenant) -> TestClient:
    login_as(client, owner)
    return client


def _upload(client: TestClient, tenant: Tenant, files: dict[str, bytes] = GOOD_FILES) -> Any:
    return client.put(f"/api/tenants/{tenant.id}/credentials", files=_multipart(files))


# --- Upload, replace, delete ---------------------------------------------------------

def test_upload_never_returned(
    owner_client: TestClient, tenant: Tenant, app_session: Session, credential_keys: Keys
) -> None:
    r = _upload(owner_client, tenant)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["file_names"] == ["oauth2.txt", "oauth2service.json"]
    assert body["health_job_id"]  # an import queues a health check
    for text_ in (r.text, owner_client.get(f"/api/tenants/{tenant.id}").text,
                  owner_client.get("/api/tenants").text):
        for secret in ("CS-1", "RT-1", '"PK"', "client_secret", "private_key"):
            assert secret not in text_
    got = owner_client.get(f"/api/tenants/{tenant.id}").json()
    assert got["has_credentials"] is True
    assert got["credential_files"] == ["oauth2.txt", "oauth2service.json"]
    assert got["credentials_uploaded_at"]
    listed = owner_client.get("/api/tenants").json()
    assert listed[0]["has_credentials"] is True

    row = app_session.get(TenantCredential, tenant.id)
    assert row is not None and b"RT-1" not in row.ciphertext
    sealed = SealedBundle(row.ciphertext, row.nonce, row.wrapped_key, row.key_version)
    assert open_bundle(sealed, credential_keys[0], associated_data=tenant.id.bytes) == GOOD_FILES
    event = _events(app_session, "tenant.credentials.upload")[0]
    assert event.details == {"file_names": ["oauth2.txt", "oauth2service.json"]}
    assert event.tenant_id == tenant.id and event.actor == "owner@example.com"


@pytest.mark.parametrize(
    ("files", "status", "needle"),
    [
        ({**GOOD_FILES, "gam.cfg": b"[DEFAULT]\noauth2_txt = /etc/x\n"}, 422, "gam.cfg"),
        ({**GOOD_FILES, "../oauth2.txt": b"{}"}, 422, "not allowed"),
        ({"oauth2.txt": OAUTH2.encode()}, 422, "oauth2service.json"),
        ({**GOOD_FILES, "oauth2.txt": b"SECRET-NOT-JSON"}, 422, "oauth2.txt"),
        ({**GOOD_FILES, "client_secrets.json": b"{" + b" " * MAX_FILE_BYTES + b"}"}, 413, "256"),
    ],
    ids=["gam_cfg", "path", "incomplete", "not_json", "oversize"],
)
def test_upload_rejects_bad_files(
    owner_client: TestClient,
    tenant: Tenant,
    app_session: Session,
    files: dict[str, bytes],
    status: int,
    needle: str,
) -> None:
    r = _upload(owner_client, tenant, files)
    assert r.status_code == status, r.text
    assert needle in r.text
    assert "SECRET-NOT-JSON" not in r.text and "RT-1" not in r.text
    assert app_session.get(TenantCredential, tenant.id) is None


def test_upload_accepts_optional_client_secrets(owner_client: TestClient, tenant: Tenant) -> None:
    r = _upload(owner_client, tenant, {**GOOD_FILES, "client_secrets.json": b'{"installed": {}}'})
    assert r.status_code == 200, r.text
    assert r.json()["file_names"] == ["client_secrets.json", "oauth2.txt", "oauth2service.json"]


def test_duplicate_file_names_rejected(owner_client: TestClient, tenant: Tenant) -> None:
    files = [*_multipart(GOOD_FILES), ("files", ("oauth2.txt", b"{}", "text/plain"))]
    r = owner_client.put(f"/api/tenants/{tenant.id}/credentials", files=files)
    assert r.status_code == 422 and "more than once" in r.text


def test_replace_and_delete_credentials_audited(
    owner_client: TestClient, tenant: Tenant, app_session: Session
) -> None:
    assert _upload(owner_client, tenant).status_code == 200
    replaced = {**GOOD_FILES, "client_secrets.json": b"{}"}
    assert _upload(owner_client, tenant, replaced).status_code == 200
    replace_events = _events(app_session, "tenant.credentials.replace")
    assert [e.details for e in replace_events] == [
        {"file_names": ["client_secrets.json", "oauth2.txt", "oauth2service.json"],
         "previous_file_names": ["oauth2.txt", "oauth2service.json"]}
    ]
    assert app_session.scalar(text("SELECT count(*) FROM tenant_credentials")) == 1

    r = owner_client.delete(f"/api/tenants/{tenant.id}/credentials")
    assert r.status_code == 204
    got = owner_client.get(f"/api/tenants/{tenant.id}").json()
    assert got["has_credentials"] is False and got["credential_files"] == []
    assert got["status"] == "pending"
    deleted = _events(app_session, "tenant.credentials.delete")
    assert [e.details for e in deleted] == [
        {"file_names": ["client_secrets.json", "oauth2.txt", "oauth2service.json"]}
    ]
    assert owner_client.delete(f"/api/tenants/{tenant.id}/credentials").status_code == 404


def test_replacing_credentials_resets_active_tenant_to_pending(
    owner_client: TestClient, tenant: Tenant, app_session: Session
) -> None:
    tenant.status = TenantStatus.active
    app_session.commit()
    assert _upload(owner_client, tenant).status_code == 200
    assert owner_client.get(f"/api/tenants/{tenant.id}").json()["status"] == "pending"


def test_credentials_are_owner_only(
    client: TestClient,
    login_as: Login,
    make_user: Callable[..., User],
    tenant: Tenant,
    app_session: Session,
) -> None:
    admin = make_user()
    app_session.add(Membership(user_id=admin.id, tenant_id=tenant.id, role=Role.admin))
    login_as(client, admin)
    assert _upload(client, tenant).status_code == 403
    assert client.delete(f"/api/tenants/{tenant.id}/credentials").status_code == 403
    assert client.delete(f"/api/tenants/{tenant.id}").status_code == 403
    assert client.patch(f"/api/tenants/{tenant.id}", json={"admin_email": ADMIN}).status_code == 403


def test_delete_tenant_keeps_audit(
    owner_client: TestClient, tenant: Tenant, app_session: Session
) -> None:
    assert _upload(owner_client, tenant).status_code == 200
    tenant_id = tenant.id
    before = app_session.scalar(
        select(func.count()).select_from(AuditEvent).where(AuditEvent.tenant_id == tenant_id)
    )
    assert before
    r = owner_client.delete(f"/api/tenants/{tenant_id}")
    assert r.status_code == 204
    app_session.expire_all()
    assert app_session.get(TenantCredential, tenant_id) is None
    assert app_session.get(Tenant, tenant_id) is None
    after = list(app_session.scalars(select(AuditEvent).where(AuditEvent.tenant_id == tenant_id)))
    assert len(after) == before + 1
    assert after[-1].action == "tenant.delete"
    assert after[-1].details == {"name": "Acme", "primary_domain": "acme.test"}
    assert owner_client.get(f"/api/tenants/{tenant_id}").status_code == 404


def test_patch_tenant_admin_email_and_domains(
    owner_client: TestClient, tenant: Tenant, app_session: Session
) -> None:
    r = owner_client.patch(
        f"/api/tenants/{tenant.id}",
        json={"admin_email": " Boss@Acme.Test ", "domains": ["other.test"]},
    )
    assert r.status_code == 200, r.text
    assert r.json()["admin_email"] == "boss@acme.test"
    assert r.json()["domains"] == ["acme.test", "other.test"]
    assert _events(app_session, "tenant.update")[0].details == {
        "admin_email": "boss@acme.test", "domains": ["acme.test", "other.test"]
    }
    bad = owner_client.patch(f"/api/tenants/{tenant.id}", json={"admin_email": "x@evil.test"})
    assert bad.status_code == 422


# --- Health check --------------------------------------------------------------------

@pytest.fixture
def stored(owner_client: TestClient, tenant: Tenant) -> Tenant:
    assert _upload(owner_client, tenant).status_code == 200
    return tenant


def _health_job(client: TestClient, tenant: Tenant, session: Session) -> Job:
    r = client.post(f"/api/tenants/{tenant.id}/health-check")
    assert r.status_code == 202, r.text
    session.expire_all()
    job = session.get(Job, uuid.UUID(r.json()["job_id"]))
    assert job is not None
    return job


def _steps(session: Session, job: Job) -> list[JobStep]:
    session.expire_all()
    query = select(JobStep).where(JobStep.job_id == job.id).order_by(JobStep.position)
    return list(session.scalars(query))


@pytest.mark.parametrize(
    ("initial", "check_exit", "expected"),
    [
        (TenantStatus.pending, 0, TenantStatus.active),
        (TenantStatus.degraded, 0, TenantStatus.active),
        (TenantStatus.pending, 1, TenantStatus.pending),
        (TenantStatus.active, 1, TenantStatus.degraded),
        (TenantStatus.active, 10, TenantStatus.degraded),
    ],
)
def test_health_check_activates_or_reports(
    owner_client: TestClient,
    stored: Tenant,
    app_session: Session,
    credential_keys: Keys,
    fake_gam: Any,
    job_dir: Path,
    initial: TenantStatus,
    check_exit: int,
    expected: TenantStatus,
) -> None:
    fake_gam.scenario([
        {"match": ["info", "domain"], "exit": 0, "stdout": '{"customerId": "C01"}'},
        {"match": ["user", ADMIN, "check", "serviceaccount"], "exit": check_exit,
         "stdout": "Service account check\n", "stderr": SCOPE_FAIL if check_exit else ""},
    ])
    job = _health_job(owner_client, stored, app_session)
    stored.status = initial
    app_session.commit()

    run_steps(app_session, job, credential_keys[0])

    app_session.expire_all()
    tenant = app_session.get(Tenant, stored.id)
    assert tenant is not None
    assert tenant.status == expected
    assert tenant.last_health_check_at is not None
    steps = _steps(app_session, job)
    assert [s.args for s in steps] == [
        ["info", "domain", "formatjson"], ["user", ADMIN, "check", "serviceaccount"]
    ]
    assert job.gam_version == "GAM 7.x.y - fake"
    calls = fake_gam.calls()
    assert [c["argv"][:2] for c in calls] == [["info", "domain"], ["user", ADMIN]]
    for call in calls:  # credentials were materialized, in a per-job directory under job_dir
        assert {"oauth2.txt", "oauth2service.json"} <= set(call["env"]["files"])
        assert Path(call["env"]["GAMCFGDIR"]).parent == job_dir
    assert os.listdir(job_dir) == []  # removed afterwards

    if check_exit == 0:
        assert job.status == JobStatus.succeeded
        assert [s.status for s in steps] == [StepStatus.succeeded] * 2
        assert [s.exit_code for s in steps] == [0, 0]
        assert tenant.last_health_message == "Health check passed"
        events = _events(app_session, "job.step.succeeded")
        assert [e.details["argv"] for e in events] == [s.args for s in steps]
        assert all(e.details["gam_version"] == "GAM 7.x.y - fake" for e in events)
        assert _events(app_session, "job.succeeded")[0].tenant_id == tenant.id
    else:
        assert job.status == JobStatus.failed and job.finished_at is not None
        assert [s.status for s in steps] == [StepStatus.succeeded, StepStatus.failed]
        assert steps[1].exit_code == check_exit
        assert steps[1].output is not None and SCOPE_FAIL.strip() in steps[1].output
        assert tenant.last_health_message is not None
        assert SCOPE_FAIL.strip() in tenant.last_health_message
        if check_exit == 10:
            assert "not authorized" in tenant.last_health_message
        failed = _events(app_session, "job.step.failed")[0]
        assert failed.details["exit_code"] == check_exit
        assert failed.actor == "owner@example.com"


def test_health_check_stops_at_first_failed_step(
    owner_client: TestClient,
    stored: Tenant,
    app_session: Session,
    credential_keys: Keys,
    fake_gam: Any,
    job_dir: Path,
) -> None:
    fake_gam.scenario([{"match": ["info", "domain"], "exit": 1, "stderr": "ERROR: 401 invalid"}])
    job = _health_job(owner_client, stored, app_session)
    run_steps(app_session, job, credential_keys[0])
    steps = _steps(app_session, job)
    assert [s.status for s in steps] == [StepStatus.failed, StepStatus.pending]
    assert len(fake_gam.calls()) == 1
    assert job.status == JobStatus.failed


def test_health_check_without_usable_credentials_fails_cleanly(
    owner_client: TestClient,
    stored: Tenant,
    app_session: Session,
    fake_gam: Any,
    job_dir: Path,
) -> None:
    job = _health_job(owner_client, stored, app_session)
    run_steps(app_session, job, X25519PrivateKey.generate())  # wrong key
    steps = _steps(app_session, job)
    assert job.status == JobStatus.failed
    assert steps[0].status == StepStatus.failed
    assert steps[0].output is not None and "could not be decrypted" in steps[0].output
    assert fake_gam.calls() == []

    assert owner_client.delete(f"/api/tenants/{stored.id}/credentials").status_code == 204
    job2 = _health_job(owner_client, stored, app_session)
    run_steps(app_session, job2, X25519PrivateKey.generate())
    first = _steps(app_session, job2)[0]
    assert first.output is not None and "no stored credentials" in first.output


def test_health_check_route_rules(
    client: TestClient,
    login_as: Login,
    make_user: Callable[..., User],
    stored: Tenant,
    app_session: Session,
) -> None:
    tech = make_user()
    admin = make_user()
    app_session.add(Membership(user_id=tech.id, tenant_id=stored.id, role=Role.technician))
    app_session.add(Membership(user_id=admin.id, tenant_id=stored.id, role=Role.admin))
    login_as(client, tech)
    assert client.post(f"/api/tenants/{stored.id}/health-check").status_code == 403
    login_as(client, admin)
    r = client.post(f"/api/tenants/{stored.id}/health-check")
    assert r.status_code == 202
    created = _events(app_session, "job.create")[-1]
    assert created.actor == admin.email and created.details["workflow"] == "health_check"

    stored.status = TenantStatus.disabled
    app_session.commit()
    assert client.post(f"/api/tenants/{stored.id}/health-check").status_code == 409
    stored.status = TenantStatus.pending
    stored.admin_email = None
    app_session.commit()
    r = client.post(f"/api/tenants/{stored.id}/health-check")
    assert r.status_code == 422 and "admin_email" in r.text


# --- Parked from Task 3 --------------------------------------------------------------

def test_concurrent_member_insert_is_409_not_500(
    client: TestClient,
    login_as: Login,
    owner: User,
    tenant: Tenant,
    make_user: Callable[..., User],
    app_session: Session,
    app_engine: Engine,
) -> None:
    target = make_user(email="target@example.com")
    login_as(client, owner)
    # Another transaction inserts the same membership but has not committed yet: the
    # route sees no row, inserts, and blocks on the unique index until that commits.
    rival = app_engine.connect()
    rival.begin()
    rival.execute(
        text(
            "INSERT INTO memberships (id, user_id, tenant_id, role)"
            " VALUES (:i, :u, :t, 'auditor')"
        ),
        {"i": uuid.uuid4(), "u": target.id, "t": tenant.id},
    )
    result: dict[str, Any] = {}

    def call() -> None:
        result["r"] = client.post(
            f"/api/tenants/{tenant.id}/members", json={"email": target.email, "role": "admin"}
        )

    worker = threading.Thread(target=call)
    worker.start()
    time.sleep(0.5)
    rival.commit()
    rival.close()
    worker.join(timeout=10)
    assert result["r"].status_code == 409, result["r"].text
