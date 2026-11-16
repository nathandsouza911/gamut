# SPDX-License-Identifier: AGPL-3.0-only
"""Login (bootstrap password and OIDC), sessions, CSRF, rate limits, users, members."""

import base64
import hashlib
import json
import secrets
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, select, text
from sqlalchemy.orm import Session

from app.models import AuditEvent, Membership, Role, Tenant, User
from app.models import Session as SessionRow

BOOT_EMAIL = "boot@example.com"
BOOT_PASSWORD = "correct horse battery staple"

Login = Callable[[TestClient, User], str]


def _events(engine: Engine, action: str | None = None) -> list[AuditEvent]:
    with Session(engine) as s:
        q = select(AuditEvent).order_by(AuditEvent.id)
        if action is not None:
            q = q.where(AuditEvent.action == action)
        return list(s.scalars(q))


def _set_cookie_headers(response: Any, name: str) -> list[str]:
    return [h for h in response.headers.get_list("set-cookie") if h.startswith(f"{name}=")]


def _flags(header: str) -> set[str]:
    return {part.strip().lower() for part in header.split(";")[1:]}


@pytest.fixture
def boot_client(make_client: Callable[..., TestClient]) -> TestClient:
    return make_client(bootstrap_admin_email=BOOT_EMAIL, bootstrap_admin_password=BOOT_PASSWORD)


def _boot_login(client: TestClient, password: str = BOOT_PASSWORD) -> Any:
    return client.post(
        "/api/auth/bootstrap-login", json={"email": BOOT_EMAIL, "password": password}
    )


# --- Bootstrap owner ----------------------------------------------------------------

def test_bootstrap_owner_created_once(
    make_client: Callable[..., TestClient], app_engine: Engine
) -> None:
    make_client(bootstrap_admin_email=BOOT_EMAIL, bootstrap_admin_password=BOOT_PASSWORD)
    with Session(app_engine) as s:
        users = list(s.scalars(select(User)))
    assert len(users) == 1
    owner = users[0]
    assert owner.email == BOOT_EMAIL and owner.is_owner
    assert owner.password_hash is not None and owner.password_hash.startswith("$argon2id$")
    assert BOOT_PASSWORD not in owner.password_hash

    # A second start with a different password neither duplicates nor resets.
    second = make_client(bootstrap_admin_email=BOOT_EMAIL, bootstrap_admin_password="other")
    with Session(app_engine) as s:
        users = list(s.scalars(select(User)))
    assert len(users) == 1 and users[0].password_hash == owner.password_hash
    assert _boot_login(second).status_code == 200
    assert _boot_login(second, "other").status_code == 401
    assert len(_events(app_engine, "auth.bootstrap_owner_created")) == 1


def test_bootstrap_login_is_audited_and_me_works(
    boot_client: TestClient, app_engine: Engine
) -> None:
    r = _boot_login(boot_client)
    assert r.status_code == 200
    me = boot_client.get("/api/me")
    assert me.status_code == 200
    assert me.json()["email"] == BOOT_EMAIL and me.json()["is_owner"] is True
    [event] = _events(app_engine, "auth.bootstrap_login")
    assert event.actor == BOOT_EMAIL


def test_failed_login_is_audited_without_password(
    boot_client: TestClient, app_engine: Engine
) -> None:
    wrong = "Wr0ng-Pa55word-xyzzy"
    r = _boot_login(boot_client, wrong)
    assert r.status_code == 401
    unknown = boot_client.post(
        "/api/auth/bootstrap-login", json={"email": "nobody@example.com", "password": wrong}
    )
    assert unknown.status_code == 401
    assert unknown.json() == r.json()  # no hint whether the account exists
    failures = _events(app_engine, "auth.login_failed")
    assert [e.target for e in failures] == [BOOT_EMAIL, "nobody@example.com"]
    with Session(app_engine) as s:
        dump = json.dumps([list(row) for row in s.execute(text("SELECT * FROM audit_events"))],
                          default=str)
    assert wrong not in dump
    assert "gamut_session" not in r.headers.get("set-cookie", "")


def test_oidc_user_cannot_use_password_login(
    client: TestClient, make_user: Callable[..., User], app_session: Session
) -> None:
    make_user(email="plain@example.com")
    app_session.commit()
    r = client.post(
        "/api/auth/bootstrap-login", json={"email": "plain@example.com", "password": "x"}
    )
    assert r.status_code == 401


# --- Sessions and cookies -------------------------------------------------------------

def test_session_cookie_flags(boot_client: TestClient) -> None:
    r = _boot_login(boot_client)
    assert r.status_code == 200
    [session_cookie] = _set_cookie_headers(r, "gamut_session")
    assert {"httponly", "secure", "samesite=lax", "path=/"} <= _flags(session_cookie)
    [csrf_cookie] = _set_cookie_headers(r, "gamut_csrf")
    assert {"secure", "samesite=lax"} <= _flags(csrf_cookie)
    assert "httponly" not in _flags(csrf_cookie)  # the UI must read it


def test_session_id_is_stored_only_as_sha256(boot_client: TestClient, app_engine: Engine) -> None:
    _boot_login(boot_client)
    raw = boot_client.cookies["gamut_session"]
    with Session(app_engine) as s:
        rows = list(s.scalars(select(SessionRow)))
    assert len(rows) == 1
    session_id = base64.urlsafe_b64decode(raw + "=")
    assert len(session_id) == 32
    assert rows[0].id_hash == hashlib.sha256(session_id).digest()
    assert rows[0].expires_at - rows[0].created_at == timedelta(hours=12)


def test_me_requires_login(client: TestClient) -> None:
    assert client.get("/api/me").status_code == 401
    client.cookies.set("gamut_session", secrets.token_urlsafe(32))
    assert client.get("/api/me").status_code == 401


@pytest.mark.parametrize(
    ("column", "age"),
    [("last_seen_at", timedelta(hours=2, minutes=1)), ("created_at", timedelta(hours=12))],
    ids=["idle-2h", "absolute-12h"],
)
def test_session_expiry(
    client: TestClient,
    login_as: Login,
    make_user: Callable[..., User],
    owner_engine: Engine,
    column: str,
    age: timedelta,
) -> None:
    login_as(client, make_user())
    assert client.get("/api/me").status_code == 200
    past = datetime.now(UTC) - age
    with owner_engine.begin() as conn:
        if column == "created_at":
            # Absolute expiry is fixed at creation; keep the session otherwise active.
            conn.execute(text("UPDATE sessions SET created_at = :t, expires_at = :t + "
                              "interval '12 hours', last_seen_at = now()"), {"t": past})
        else:
            conn.execute(text("UPDATE sessions SET last_seen_at = :t"), {"t": past})
    assert client.get("/api/me").status_code == 401
    with owner_engine.connect() as conn:
        assert conn.scalar(text("SELECT count(*) FROM sessions")) == 0


def test_activity_extends_idle_expiry(
    client: TestClient, login_as: Login, make_user: Callable[..., User], owner_engine: Engine
) -> None:
    login_as(client, make_user())
    with owner_engine.begin() as conn:
        conn.execute(text("UPDATE sessions SET last_seen_at = now() - interval '90 minutes'"))
    assert client.get("/api/me").status_code == 200
    with owner_engine.connect() as conn:
        idle = conn.scalar(text("SELECT now() - last_seen_at FROM sessions"))
    assert idle < timedelta(minutes=1)


def test_logout_revokes_session(boot_client: TestClient, app_engine: Engine) -> None:
    _boot_login(boot_client)
    raw = boot_client.cookies["gamut_session"]
    csrf = boot_client.cookies["gamut_csrf"]
    r = boot_client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf})
    assert r.status_code == 204
    cleared = _set_cookie_headers(r, "gamut_session")
    assert cleared and "max-age=0" in _flags(cleared[0])
    # The old cookie no longer works even if the browser kept it.
    boot_client.cookies.set("gamut_session", raw)
    assert boot_client.get("/api/me").status_code == 401
    [event] = _events(app_engine, "auth.logout")
    assert event.actor == BOOT_EMAIL


# --- CSRF -------------------------------------------------------------------------------

def test_state_change_without_csrf_is_403(
    client: TestClient, login_as: Login, make_user: Callable[..., User]
) -> None:
    csrf = login_as(client, make_user(is_owner=True))
    body = {"name": "Acme", "primary_domain": "acme.example"}
    del client.headers["X-CSRF-Token"]
    assert client.post("/api/tenants", json=body).status_code == 403
    wrong = client.post("/api/tenants", json=body, headers={"X-CSRF-Token": "nope"})
    assert wrong.status_code == 403
    # Header equal to a forged cookie is not enough: it must match the session's token.
    forged = secrets.token_urlsafe(32)
    client.cookies.set("gamut_csrf", forged)
    assert client.post(
        "/api/tenants", json=body, headers={"X-CSRF-Token": forged}
    ).status_code == 403
    # Header matching the session but not the cookie is refused too.
    assert client.post(
        "/api/tenants", json=body, headers={"X-CSRF-Token": csrf}
    ).status_code == 403
    client.cookies.set("gamut_csrf", csrf)
    assert client.post(
        "/api/tenants", json=body, headers={"X-CSRF-Token": csrf}
    ).status_code == 201


def test_every_state_changing_route_requires_csrf(
    client: TestClient,
    login_as: Login,
    make_user: Callable[..., User],
    make_tenant: Callable[..., Tenant],
) -> None:
    from app.auth.csrf import CSRF_EXEMPT_PATHS
    from app.auth.tenant_guard import iter_routes

    tenant = make_tenant()
    login_as(client, make_user(is_owner=True))
    del client.headers["X-CSRF-Token"]
    checked = 0
    for path, methods, _ in iter_routes(client.app):  # type: ignore[arg-type]
        if path in CSRF_EXEMPT_PATHS or not path.startswith("/api/"):
            continue
        url = path.replace("{tenant_id}", str(tenant.id))
        for method in sorted(methods - {"GET", "HEAD", "OPTIONS"}):
            r = client.request(method, url, json={})
            assert r.status_code == 403, f"{method} {path} -> {r.status_code}"
            checked += 1
    assert checked >= 4  # logout, users, tenants, members at least


# --- Rate limit -------------------------------------------------------------------------

def test_login_rate_limited(boot_client: TestClient) -> None:
    for _ in range(10):
        assert _boot_login(boot_client, "wrong").status_code == 401
    r = _boot_login(boot_client)  # even the right password is refused now
    assert r.status_code == 429
    assert "retry-after" in r.headers


def test_rate_limiter_window_slides() -> None:
    from app.auth.ratelimit import SlidingWindowLimiter

    now = [1000.0]
    limiter = SlidingWindowLimiter(clock=lambda: now[0])
    assert all(limiter.hit("k", limit=3, window_s=60) is None for _ in range(3))
    assert limiter.hit("k", limit=3, window_s=60) is not None
    assert limiter.hit("other", limit=3, window_s=60) is None
    now[0] += 61
    assert limiter.hit("k", limit=3, window_s=60) is None


# --- OIDC -------------------------------------------------------------------------------

def test_oidc_login_known_user(
    make_client: Callable[..., TestClient],
    fake_idp: Any,
    make_user: Callable[..., User],
    app_session: Session,
    app_engine: Engine,
) -> None:
    make_user(email="tech@example.com")
    app_session.commit()
    client = make_client(oidc_transport=fake_idp.transport, **fake_idp.settings_overrides())
    r = fake_idp.login(client, email="Tech@Example.com", sub="google-123")
    assert r.status_code == 303, r.text
    assert r.headers["location"] == "https://gamut.test/"
    [session_cookie] = _set_cookie_headers(r, "gamut_session")
    assert {"httponly", "secure", "samesite=lax"} <= _flags(session_cookie)
    assert client.get("/api/me").json()["email"] == "tech@example.com"
    with Session(app_engine) as s:
        user = s.scalars(select(User)).one()
    assert user.oidc_subject == "google-123"
    [event] = _events(app_engine, "auth.login")
    assert event.actor == "tech@example.com" and event.details["method"] == "oidc"


def test_oidc_callback_unknown_email_rejected(
    make_client: Callable[..., TestClient], fake_idp: Any, app_engine: Engine
) -> None:
    client = make_client(oidc_transport=fake_idp.transport, **fake_idp.settings_overrides())
    r = fake_idp.login(client, email="stranger@example.com")
    assert r.status_code == 403
    assert not _set_cookie_headers(r, "gamut_session")
    with Session(app_engine) as s:
        assert s.scalars(select(User)).all() == []  # no auto-signup
    [event] = _events(app_engine, "auth.login_failed")
    assert event.target == "stranger@example.com" and event.details["reason"] == "unknown_user"


def test_oidc_requires_verified_email(
    make_client: Callable[..., TestClient],
    fake_idp: Any,
    make_user: Callable[..., User],
    app_session: Session,
) -> None:
    make_user(email="tech@example.com")
    app_session.commit()
    client = make_client(oidc_transport=fake_idp.transport, **fake_idp.settings_overrides())
    r = fake_idp.login(client, email="tech@example.com", email_verified=False)
    assert r.status_code == 403


def test_oidc_subject_mismatch_rejected(
    make_client: Callable[..., TestClient],
    fake_idp: Any,
    make_user: Callable[..., User],
    app_session: Session,
) -> None:
    make_user(email="tech@example.com", oidc_subject="google-original")
    app_session.commit()
    client = make_client(oidc_transport=fake_idp.transport, **fake_idp.settings_overrides())
    assert fake_idp.login(client, email="tech@example.com", sub="google-other").status_code == 403


def test_oidc_callback_with_bad_state_rejected(
    make_client: Callable[..., TestClient], fake_idp: Any
) -> None:
    client = make_client(oidc_transport=fake_idp.transport, **fake_idp.settings_overrides())
    r = client.get("/api/auth/callback", params={"code": "c", "state": "forged"},
                   follow_redirects=False)
    assert r.status_code == 401


def test_oidc_login_unconfigured_is_503(client: TestClient) -> None:
    assert client.get("/api/auth/login", follow_redirects=False).status_code == 503


# --- Users and memberships -------------------------------------------------------------

def test_create_user_owner_only(
    make_client: Callable[..., TestClient],
    login_as: Login,
    make_user: Callable[..., User],
    app_engine: Engine,
) -> None:
    owner_client, tech_client = make_client(), make_client()
    login_as(owner_client, make_user(email="owner@example.com", is_owner=True))
    login_as(tech_client, make_user())
    body = {"email": " New.Person@Example.com ", "display_name": "New Person"}
    assert tech_client.post("/api/users", json=body).status_code == 403
    r = owner_client.post("/api/users", json=body)
    assert r.status_code == 201
    assert r.json()["email"] == "new.person@example.com"
    assert owner_client.post("/api/users", json=body).status_code == 409
    [event] = _events(app_engine, "user.create")
    assert event.actor == "owner@example.com" and event.target == "new.person@example.com"


def test_set_member_role(
    make_client: Callable[..., TestClient],
    login_as: Login,
    make_user: Callable[..., User],
    make_tenant: Callable[..., Tenant],
    app_session: Session,
    app_engine: Engine,
) -> None:
    tenant = make_tenant()
    admin = make_user(email="admin@example.com")
    tech = make_user(email="tech@example.com")
    make_user(email="new@example.com")
    app_session.add_all([
        Membership(user_id=admin.id, tenant_id=tenant.id, role=Role.admin),
        Membership(user_id=tech.id, tenant_id=tenant.id, role=Role.technician),
    ])
    admin_client, tech_client = make_client(), make_client()
    login_as(admin_client, admin)
    login_as(tech_client, tech)
    url = f"/api/tenants/{tenant.id}/members"

    assert tech_client.post(url, json={"email": "new@example.com", "role": "auditor"}
                            ).status_code == 403
    r = admin_client.post(url, json={"email": "New@example.com", "role": "auditor"})
    assert r.status_code == 201, r.text
    assert r.json() == {"email": "new@example.com", "role": "auditor"}
    r = admin_client.post(url, json={"email": "new@example.com", "role": "technician"})
    assert r.status_code == 200
    unknown = admin_client.post(url, json={"email": "ghost@example.com", "role": "auditor"})
    assert unknown.status_code == 422 and "ghost@example.com" not in unknown.text
    assert "POST /api/users" in unknown.json()["detail"]
    assert admin_client.post(url, json={"email": "new@example.com", "role": "owner"}
                             ).status_code == 422

    with Session(app_engine) as s:
        role = s.scalar(select(Membership.role).join(User).where(User.email == "new@example.com"))
    assert role == Role.technician
    events = _events(app_engine, "membership.set")
    assert [(e.target, e.details["role"], e.details["previous_role"]) for e in events] == [
        ("new@example.com", "auditor", None),
        ("new@example.com", "technician", "auditor"),
    ]
    assert all(e.tenant_id == tenant.id and e.actor == "admin@example.com" for e in events)


def test_tenant_list_shows_only_member_tenants(
    make_client: Callable[..., TestClient],
    login_as: Login,
    make_user: Callable[..., User],
    make_tenant: Callable[..., Tenant],
    app_session: Session,
) -> None:
    a, b = make_tenant(name="A"), make_tenant(name="B")
    user = make_user()
    app_session.add(Membership(user_id=user.id, tenant_id=a.id, role=Role.auditor))
    user_client, owner_client = make_client(), make_client()
    login_as(user_client, user)
    login_as(owner_client, make_user(is_owner=True))
    listed = user_client.get("/api/tenants").json()
    assert [(t["name"], t["role"]) for t in listed] == [("A", "auditor")]
    assert sorted(t["name"] for t in owner_client.get("/api/tenants").json()) == ["A", "B"]
    assert user_client.get(f"/api/tenants/{a.id}").json()["role"] == "auditor"
    assert user_client.get(f"/api/tenants/{b.id}").status_code == 404


def test_create_tenant_owner_only_and_audited(
    make_client: Callable[..., TestClient],
    login_as: Login,
    make_user: Callable[..., User],
    app_engine: Engine,
) -> None:
    owner_client, user_client = make_client(), make_client()
    login_as(owner_client, make_user(email="owner@example.com", is_owner=True))
    login_as(user_client, make_user())
    body = {"name": "Acme", "primary_domain": "Acme.Example", "admin_email": "gam@acme.example"}
    assert user_client.post("/api/tenants", json=body).status_code == 403
    r = owner_client.post("/api/tenants", json=body)
    assert r.status_code == 201
    created = r.json()
    assert created["primary_domain"] == "acme.example"
    assert created["domains"] == ["acme.example"] and created["status"] == "pending"
    assert owner_client.post("/api/tenants", json=body).status_code == 409
    [event] = _events(app_engine, "tenant.create")
    assert str(event.tenant_id) == created["id"]
