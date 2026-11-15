# SPDX-License-Identifier: AGPL-3.0-only
"""Ruling R15: owners list and disable panel users; owners and tenant admins list and
remove tenant members."""

from collections.abc import Callable
from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy import Engine, func, select
from sqlalchemy.orm import Session

from app.models import AuditEvent, Membership, Role, Tenant, User
from app.models import Session as SessionRow

Login = Callable[[TestClient, User], str]
BOOT_EMAIL = "boot@example.com"
BOOT_PASSWORD = "correct horse battery staple"


def _events(engine: Engine, action: str) -> list[AuditEvent]:
    with Session(engine) as s:
        return list(s.scalars(
            select(AuditEvent).where(AuditEvent.action == action).order_by(AuditEvent.id)))


def _sessions(engine: Engine, user_id: Any) -> int:
    with Session(engine) as s:
        return int(s.scalar(select(func.count()).select_from(SessionRow)
                            .where(SessionRow.user_id == user_id)) or 0)


# --- Users -------------------------------------------------------------------------------

def test_list_users_owner_only(
    make_client: Callable[..., TestClient], login_as: Login, make_user: Callable[..., User],
) -> None:
    owner_client, tech_client = make_client(), make_client()
    login_as(owner_client, make_user(email="owner@example.com", is_owner=True))
    login_as(tech_client, make_user(email="tech@example.com"))
    assert tech_client.get("/api/users").status_code == 403
    r = owner_client.get("/api/users")
    assert r.status_code == 200
    rows = {u["email"]: u for u in r.json()}
    assert set(rows) == {"owner@example.com", "tech@example.com"}
    assert rows["tech@example.com"]["disabled"] is False
    assert rows["owner@example.com"]["is_owner"] is True
    assert "password_hash" not in rows["owner@example.com"]


def test_disable_user_kills_sessions_and_blocks_access(
    make_client: Callable[..., TestClient], login_as: Login, make_user: Callable[..., User],
    app_engine: Engine,
) -> None:
    owner_client, tech_client, tech_client2 = make_client(), make_client(), make_client()
    login_as(owner_client, make_user(email="owner@example.com", is_owner=True))
    tech = make_user(email="tech@example.com")
    login_as(tech_client, tech)
    login_as(tech_client2, tech)
    assert tech_client.get("/api/me").status_code == 200
    assert _sessions(app_engine, tech.id) == 2

    assert tech_client.post(f"/api/users/{tech.id}/disable").status_code == 403
    r = owner_client.post(f"/api/users/{tech.id}/disable")
    assert r.status_code == 200, r.text
    assert r.json()["disabled"] is True
    assert _sessions(app_engine, tech.id) == 0
    assert tech_client.get("/api/me").status_code == 401
    assert tech_client2.get("/api/me").status_code == 401
    [event] = _events(app_engine, "user.disable")
    assert event.actor == "owner@example.com" and event.target == "tech@example.com"
    assert event.details["sessions_deleted"] == 2

    # Idempotent; unknown ids are 404; owners cannot lock themselves out.
    assert owner_client.post(f"/api/users/{tech.id}/disable").status_code == 200
    assert owner_client.post(
        "/api/users/00000000-0000-0000-0000-000000000000/disable").status_code == 404
    me = owner_client.get("/api/me").json()
    assert owner_client.post(f"/api/users/{me['id']}/disable").status_code == 409


def test_disabled_session_rejected_even_if_a_row_survives(
    client: TestClient, login_as: Login, make_user: Callable[..., User], app_session: Session,
) -> None:
    user = make_user(email="tech@example.com")
    login_as(client, user)
    user.disabled = True
    app_session.commit()  # flag set directly; the session row still exists
    assert client.get("/api/me").status_code == 401


def test_disabled_user_cannot_sign_in_with_oidc(
    make_client: Callable[..., TestClient], fake_idp: Any, make_user: Callable[..., User],
    app_session: Session, app_engine: Engine,
) -> None:
    make_user(email="tech@example.com", disabled=True)
    app_session.commit()
    client = make_client(oidc_transport=fake_idp.transport, **fake_idp.settings_overrides())
    r = fake_idp.login(client, email="tech@example.com")
    assert r.status_code == 403
    [event] = _events(app_engine, "auth.login_failed")
    assert event.details["reason"] == "user_disabled"


def test_disabled_bootstrap_owner_cannot_sign_in(
    make_client: Callable[..., TestClient], app_engine: Engine,
) -> None:
    client = make_client(bootstrap_admin_email=BOOT_EMAIL, bootstrap_admin_password=BOOT_PASSWORD)
    with Session(app_engine) as s:
        boot = s.scalars(select(User).where(User.email == BOOT_EMAIL)).one()
        boot.disabled = True
        s.commit()
    r = client.post("/api/auth/bootstrap-login",
                    json={"email": BOOT_EMAIL, "password": BOOT_PASSWORD})
    assert r.status_code == 401


# --- Tenant members ------------------------------------------------------------------------

def test_list_and_remove_members(
    make_client: Callable[..., TestClient], login_as: Login, make_user: Callable[..., User],
    make_tenant: Callable[..., Tenant], app_session: Session, app_engine: Engine,
) -> None:
    tenant, other = make_tenant(), make_tenant()
    admin = make_user(email="admin@example.com")
    tech = make_user(email="tech@example.com")
    auditor = make_user(email="aud@example.com")
    app_session.add_all([
        Membership(user_id=admin.id, tenant_id=tenant.id, role=Role.admin),
        Membership(user_id=tech.id, tenant_id=tenant.id, role=Role.technician),
        Membership(user_id=auditor.id, tenant_id=other.id, role=Role.auditor),
    ])
    admin_client, tech_client = make_client(), make_client()
    login_as(admin_client, admin)
    login_as(tech_client, tech)
    url = f"/api/tenants/{tenant.id}/members"

    assert tech_client.get(url).status_code == 403
    r = admin_client.get(url)
    assert r.status_code == 200
    assert [(m["email"], m["role"]) for m in r.json()] == [
        ("admin@example.com", "admin"), ("tech@example.com", "technician")]
    assert r.json()[0]["user_id"] == str(admin.id)

    assert tech_client.delete(f"{url}/{admin.id}").status_code == 403
    assert admin_client.delete(f"{url}/{auditor.id}").status_code == 404  # other tenant's
    assert admin_client.delete(f"{url}/{tech.id}").status_code == 204
    assert admin_client.delete(f"{url}/{tech.id}").status_code == 404
    assert [m["email"] for m in admin_client.get(url).json()] == ["admin@example.com"]
    # The removed technician no longer sees the tenant.
    assert tech_client.get(f"/api/tenants/{tenant.id}").status_code == 404
    [event] = _events(app_engine, "membership.remove")
    assert event.tenant_id == tenant.id and event.target == "tech@example.com"
    assert event.details == {"user_id": str(tech.id), "previous_role": "technician"}

    # The other tenant's membership is untouched.
    with Session(app_engine) as s:
        assert s.scalar(select(Membership.role).where(Membership.user_id == auditor.id)) \
            == Role.auditor


def test_owner_manages_members_of_any_tenant(
    make_client: Callable[..., TestClient], login_as: Login, make_user: Callable[..., User],
    make_tenant: Callable[..., Tenant], app_session: Session,
) -> None:
    tenant = make_tenant()
    tech = make_user(email="tech@example.com")
    app_session.add(Membership(user_id=tech.id, tenant_id=tenant.id, role=Role.technician))
    owner_client = make_client()
    login_as(owner_client, make_user(email="owner@example.com", is_owner=True))
    url = f"/api/tenants/{tenant.id}/members"
    assert [m["email"] for m in owner_client.get(url).json()] == ["tech@example.com"]
    assert owner_client.delete(f"{url}/{tech.id}").status_code == 204
