# SPDX-License-Identifier: AGPL-3.0-only
"""Credential material never reaches logs, output, API responses or the audit log."""

import base64
import json
import logging
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.jobs.execute import run_steps
from app.models import AuditEvent, Job, JobStep, Tenant, User

MARKERS = {
    "client_secret": "MARKER-CLIENT-SECRET-7f3a91",
    "refresh_token": "MARKER-REFRESH-TOKEN-c41d02",
    "private_key": (
        "-----BEGIN PRIVATE KEY-----\nMARKER-PRIVATE-KEY-9b77e5\n-----END PRIVATE KEY-----\n"
    ),
    "private_key_id": "MARKER-PRIVATE-KEY-ID-0e5a",
    "installed_secret": "MARKER-INSTALLED-SECRET-55aa",
}
FILES = {
    "oauth2.txt": json.dumps({
        "client_id": "123.apps.googleusercontent.com",
        "client_secret": MARKERS["client_secret"],
        "refresh_token": MARKERS["refresh_token"],
        "token": "ya29.MARKER-ACCESS-TOKEN-d00d",
    }).encode(),
    "oauth2service.json": json.dumps({
        "type": "service_account",
        "client_email": "gam@project.iam.gserviceaccount.com",
        "private_key_id": MARKERS["private_key_id"],
        "private_key": MARKERS["private_key"],
    }).encode(),
    "client_secrets.json": json.dumps(
        {"installed": {"client_id": "x", "client_secret": MARKERS["installed_secret"]}}
    ).encode(),
}
NEEDLES = [
    *MARKERS.values(),
    "MARKER-PRIVATE-KEY-9b77e5",
    "MARKER-ACCESS-TOKEN-d00d",
    *(base64.b64encode(content).decode() for content in FILES.values()),
]


def _scan(where: str, haystack: str) -> None:
    for needle in NEEDLES:
        assert needle not in haystack, f"secret marker found in {where}"


def test_no_secret_leaks(
    client: TestClient,
    login_as: Callable[[TestClient, User], str],
    make_user: Callable[..., User],
    app_session: Session,
    credential_keys: tuple[X25519PrivateKey, str],
    fake_gam: Any,
    job_dir: Path,
    caplog: pytest.LogCaptureFixture,
    capfd: pytest.CaptureFixture[str],
) -> None:
    caplog.set_level(logging.DEBUG)
    login_as(client, make_user(email="owner@example.com", is_owner=True))
    # GAM misbehaves and echoes token values: they must be scrubbed from stored output.
    fake_gam.scenario([
        {"match": ["info", "domain"], "exit": 0,
         "stdout": json.dumps({"debug": MARKERS["refresh_token"]})},
        {"match": ["user"], "exit": 10,
         "stdout": f"client_secret={MARKERS['client_secret']}\n",
         "stderr": f"key {MARKERS['private_key_id']} FAIL scope gmail.settings.basic\n"},
    ])
    responses: list[httpx.Response] = []

    def call(method: str, url: str, **kwargs: Any) -> httpx.Response:
        r: httpx.Response = client.request(method, url, **kwargs)
        responses.append(r)
        return r

    created = call("POST", "/api/tenants", json={
        "name": "Acme", "primary_domain": "acme.test", "admin_email": "admin@acme.test",
    })
    tenant_id = created.json()["id"]
    upload = [("files", (n, c, "application/json")) for n, c in FILES.items()]
    assert call("PUT", f"/api/tenants/{tenant_id}/credentials", files=upload).status_code == 200
    bad = [*upload, ("files", ("gam.cfg", FILES["oauth2.txt"], "text/plain"))]
    assert call("PUT", f"/api/tenants/{tenant_id}/credentials", files=bad).status_code == 422
    not_json = [("files", ("oauth2.txt", MARKERS["refresh_token"].encode(), "text/plain")),
                ("files", ("oauth2service.json", FILES["oauth2service.json"], "text/plain"))]
    assert call("PUT", f"/api/tenants/{tenant_id}/credentials", files=not_json).status_code == 422
    job_id = call("POST", f"/api/tenants/{tenant_id}/health-check").json()["job_id"]

    job = app_session.get(Job, uuid.UUID(job_id))
    assert job is not None
    run_steps(app_session, job, credential_keys[0])

    call("GET", f"/api/tenants/{tenant_id}")
    call("GET", "/api/tenants")
    for r in responses:
        _scan(f"response to {r.request.method} {r.request.url.path}", r.text)

    app_session.expire_all()
    for event in app_session.scalars(select(AuditEvent)):
        _scan(f"audit event {event.action}", json.dumps(event.details))
    steps = list(app_session.scalars(select(JobStep).where(JobStep.job_id == job.id)))
    assert steps and all(s.output for s in steps)
    for step in steps:
        _scan(f"step {step.key}", json.dumps([step.output, step.args, step.data]))
    assert "[redacted]" in (steps[0].output or "") + (steps[1].output or "")
    tenant = app_session.get(Tenant, uuid.UUID(tenant_id))
    assert tenant is not None and tenant.last_health_message
    _scan("tenant.last_health_message", tenant.last_health_message)
    assert "gmail.settings.basic" in tenant.last_health_message  # the useful part stays

    _scan("log records", caplog.text)
    captured = capfd.readouterr()
    _scan("stdout", captured.out)
    _scan("stderr", captured.err)
