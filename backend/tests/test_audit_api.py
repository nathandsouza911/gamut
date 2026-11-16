# SPDX-License-Identifier: AGPL-3.0-only
"""Audit list and verify routes, /api/meta, and the static UI mount."""

from collections.abc import Callable
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.audit.chain import append_event
from app.models import Membership, Role, Tenant, User

Login = Callable[[TestClient, User], str]


def _event(session: Session, tenant: Tenant | None, action: str) -> None:
    append_event(session, actor="a@example.com", tenant_id=None if tenant is None else tenant.id,
                 action=action, target="t", details={"n": 1})


def test_audit_list_scoped_to_tenant(
    client: TestClient, login_as: Login, make_tenant: Callable[..., Tenant],
    make_user: Callable[..., User], app_session: Session,
) -> None:
    a, b = make_tenant(name="A"), make_tenant(name="B")
    for i in range(3):
        _event(app_session, a, f"a.{i}")
    _event(app_session, b, "b.secret")
    _event(app_session, None, "global.event")
    auditor = make_user()
    app_session.add(Membership(user_id=auditor.id, tenant_id=a.id, role=Role.auditor))
    login_as(client, auditor)

    r = client.get(f"/api/tenants/{a.id}/audit")
    assert r.status_code == 200, r.text
    body = r.json()
    assert [e["action"] for e in body["items"]] == ["a.2", "a.1", "a.0"]  # newest first
    assert body["next_cursor"] is None
    assert set(body["items"][0]) == {"id", "time", "actor", "action", "target", "details"}
    assert client.get(f"/api/tenants/{b.id}/audit").status_code == 404


def test_audit_cursor_pagination_and_limit(
    client: TestClient, login_as: Login, make_tenant: Callable[..., Tenant],
    make_user: Callable[..., User], app_session: Session,
) -> None:
    t = make_tenant()
    for i in range(5):
        _event(app_session, t, f"e.{i}")
    u = make_user()
    app_session.add(Membership(user_id=u.id, tenant_id=t.id, role=Role.auditor))
    login_as(client, u)
    first = client.get(f"/api/tenants/{t.id}/audit?limit=2").json()
    assert [e["action"] for e in first["items"]] == ["e.4", "e.3"]
    second = client.get(f"/api/tenants/{t.id}/audit?limit=2&cursor={first['next_cursor']}").json()
    assert [e["action"] for e in second["items"]] == ["e.2", "e.1"]
    third = client.get(f"/api/tenants/{t.id}/audit?limit=2&cursor={second['next_cursor']}").json()
    assert [e["action"] for e in third["items"]] == ["e.0"]
    assert third["next_cursor"] is None
    assert client.get(f"/api/tenants/{t.id}/audit?limit=201").status_code == 422
    assert client.get(f"/api/tenants/{t.id}/audit?cursor=abc").status_code == 422


def test_verify_is_owner_only(
    client: TestClient, login_as: Login, make_tenant: Callable[..., Tenant],
    make_user: Callable[..., User], app_session: Session,
) -> None:
    t = make_tenant()
    _event(app_session, t, "x")
    admin = make_user()
    app_session.add(Membership(user_id=admin.id, tenant_id=t.id, role=Role.admin))
    login_as(client, admin)
    assert client.get("/api/audit/verify").status_code == 403
    owner = make_user(is_owner=True)
    login_as(client, owner)
    r = client.get("/api/audit/verify")
    assert r.status_code == 200
    assert r.json() == {"ok": True, "checked": 1, "first_broken_id": None, "reason": None}


def test_verify_unauthenticated_is_401(client: TestClient) -> None:
    assert client.get("/api/audit/verify").status_code == 401


def test_meta_is_public_and_has_no_secrets(client: TestClient) -> None:
    r = client.get("/api/meta")
    assert r.status_code == 200
    assert r.json() == {"source_url": "https://github.com/nathandsouza911/gamut", "version": "0.1.0"}


def test_static_ui_spa_fallback(
    make_client: Callable[..., TestClient], tmp_path: Path
) -> None:
    (tmp_path / "assets").mkdir()
    (tmp_path / "index.html").write_text("<html>SPA</html>")
    (tmp_path / "assets" / "app.js").write_text("console.log(1)")
    c = make_client(static_dir=tmp_path)
    assert "SPA" in c.get("/").text
    assert "SPA" in c.get("/tenants/123/audit").text
    assert c.get("/assets/app.js").text == "console.log(1)"
    assert "SPA" in c.get("/../../etc/passwd").text  # never leaves the directory
    miss = c.get("/api/nope")
    assert miss.status_code == 404 and miss.json() == {"detail": "Not Found"}
    assert c.post("/api/nope", json={}).status_code == 404
    assert c.get("/api/me").status_code == 401  # real routes still win


def test_missing_static_dir_is_skipped(
    make_client: Callable[..., TestClient], tmp_path: Path
) -> None:
    c = make_client(static_dir=tmp_path / "absent")
    assert c.get("/").status_code == 404
    assert c.get("/api/meta").status_code == 200


