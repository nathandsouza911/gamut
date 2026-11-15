# SPDX-License-Identifier: AGPL-3.0-only
"""A user of tenant A can neither read nor act on tenant B.

The route list is built from the app itself, so routes added by later tasks are covered
automatically. Every request also carries a malformed JSON body: the tenant check must
answer 404 before the body is parsed or validated.
"""

import re
import uuid
from collections.abc import Callable

import pytest
from fastapi import APIRouter, FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import Membership, Role, Tenant, User

Login = Callable[[TestClient, User], str]
MALFORMED = b'{"not": json'


def _tenant_routes(app: FastAPI) -> list[tuple[str, str]]:
    from app.auth.tenant_guard import iter_routes

    return sorted(
        (method, path)
        for path, methods, _ in iter_routes(app)
        if "{tenant_id}" in path
        for method in methods
    )


def _fill(path: str, tenant_id: uuid.UUID) -> str:
    path = path.replace("{tenant_id}", str(tenant_id))
    return re.sub(r"\{[^}]+\}", lambda _: str(uuid.uuid4()), path)


@pytest.fixture
def two_tenants(
    make_tenant: Callable[..., Tenant], make_user: Callable[..., User], app_session: Session
) -> tuple[Tenant, Tenant, User]:
    a, b = make_tenant(name="Tenant A"), make_tenant(name="Tenant B")
    user = make_user()
    app_session.add(Membership(user_id=user.id, tenant_id=a.id, role=Role.admin))
    return a, b, user


def test_user_without_role_gets_404_on_every_tenant_route(
    client: TestClient, login_as: Login, two_tenants: tuple[Tenant, Tenant, User]
) -> None:
    _, b, user = two_tenants
    login_as(client, user)
    routes = _tenant_routes(client.app)  # type: ignore[arg-type]
    assert routes, "no {tenant_id} routes found: the isolation test would prove nothing"
    for method, path in routes:
        for tenant_id in (b.id, uuid.uuid4()):
            r = client.request(
                method,
                _fill(path, tenant_id),
                content=MALFORMED,
                headers={"Content-Type": "application/json"},
            )
            assert r.status_code == 404, f"{method} {path} -> {r.status_code} {r.text}"


def test_non_uuid_tenant_id_is_404(
    client: TestClient, login_as: Login, two_tenants: tuple[Tenant, Tenant, User]
) -> None:
    login_as(client, two_tenants[2])
    assert client.get("/api/tenants/not-a-uuid").status_code == 404


def test_tenant_404_precedes_body_validation(
    client: TestClient, login_as: Login, two_tenants: tuple[Tenant, Tenant, User]
) -> None:
    a, b, user = two_tenants
    login_as(client, user)
    for body in ({"role": "nonsense"}, {}):
        assert client.post(f"/api/tenants/{b.id}/members", json=body).status_code == 404
    malformed = client.post(
        f"/api/tenants/{b.id}/members",
        content=MALFORMED,
        headers={"Content-Type": "application/json"},
    )
    assert malformed.status_code == 404
    # Control: on the user's own tenant the same bodies reach validation.
    assert client.post(f"/api/tenants/{a.id}/members", json={}).status_code == 422


def test_member_route_works_on_own_tenant(
    client: TestClient, login_as: Login, two_tenants: tuple[Tenant, Tenant, User]
) -> None:
    a, _, user = two_tenants
    login_as(client, user)
    assert client.get(f"/api/tenants/{a.id}").status_code == 200


def test_unauthenticated_is_401_not_404(
    client: TestClient, two_tenants: tuple[Tenant, Tenant, User], app_session: Session
) -> None:
    app_session.commit()
    assert client.get(f"/api/tenants/{two_tenants[0].id}").status_code == 401


def test_owner_bypasses_membership(
    client: TestClient,
    login_as: Login,
    make_user: Callable[..., User],
    two_tenants: tuple[Tenant, Tenant, User],
) -> None:
    _, b, _ = two_tenants
    login_as(client, make_user(is_owner=True))
    r = client.get(f"/api/tenants/{b.id}")
    assert r.status_code == 200 and r.json()["role"] == "owner"
    assert client.get(f"/api/tenants/{uuid.uuid4()}").status_code == 404


def test_wrong_role_on_visible_tenant_is_403(
    client: TestClient,
    login_as: Login,
    make_user: Callable[..., User],
    make_tenant: Callable[..., Tenant],
    app_session: Session,
) -> None:
    tenant = make_tenant()
    auditor = make_user()
    app_session.add(Membership(user_id=auditor.id, tenant_id=tenant.id, role=Role.auditor))
    login_as(client, auditor)
    r = client.post(
        f"/api/tenants/{tenant.id}/members", json={"email": "x@example.com", "role": "auditor"}
    )
    assert r.status_code == 403


def test_unguarded_tenant_route_is_refused_at_startup() -> None:
    from app.auth.tenant_guard import TenantRouteError, check_tenant_routes

    app = FastAPI()
    router = APIRouter()

    @router.get("/api/tenants/{tenant_id}/leaky")
    def leaky(tenant_id: str) -> dict[str, str]:
        return {"tenant_id": tenant_id}

    app.include_router(router)
    with pytest.raises(TenantRouteError, match="leaky"):
        check_tenant_routes(app)
