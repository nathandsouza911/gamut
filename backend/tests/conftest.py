# SPDX-License-Identifier: AGPL-3.0-only
"""Shared fixtures.

TEST_DATABASE_URL     connects as the owner role (gamut_owner): migrations and cleanup.
TEST_APP_DATABASE_URL connects as the app role (gamut_app): what the code under test uses.
"""

import json
import os
import shutil
import time
import uuid
import warnings
from collections.abc import Callable, Iterator
from contextlib import ExitStack
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from alembic import command
from alembic.config import Config
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from fastapi.testclient import TestClient
from joserfc import jwt
from joserfc.jwk import RSAKey
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.orm import Session

from app import db
from app.models import Tenant, TenantStatus, User
from app.settings import Settings, load_settings

# isort: split
# Authlib warns at import that it prefers the httpx2 package. httpx works; import it here,
# quietly, so the notice does not clutter test output. authlib.deprecate installs an
# "always" filter for its warnings when imported, so it must be imported first, outside
# the catch_warnings block, or that filter would override the "ignore" below.
import authlib.deprecate  # noqa: F401

with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    import authlib.integrations.starlette_client  # noqa: F401

BACKEND_DIR = Path(__file__).resolve().parents[1]

TABLES = (
    "audit_events",
    "scheduled_actions",
    "job_steps",
    "jobs",
    "memberships",
    "tenant_credentials",
    "sessions",
    "tenants",
    "users",
)


def _env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        pytest.skip(f"{name} is not set")
    return value


@pytest.fixture(scope="session")
def _migrated_owner_engine() -> Iterator[Engine]:
    """Owner-role engine on a freshly migrated schema (once per test session)."""
    url = _env("TEST_DATABASE_URL")
    engine = create_engine(url)
    with engine.begin() as conn:
        conn.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
        conn.execute(text("CREATE SCHEMA public"))
    cfg = Config(str(BACKEND_DIR / "alembic.ini"))
    cfg.set_main_option("sqlalchemy.url", url.replace("%", "%%"))
    command.upgrade(cfg, "head")
    yield engine
    engine.dispose()


@pytest.fixture(scope="session")
def _app_engine() -> Iterator[Engine]:
    engine = create_engine(_env("TEST_APP_DATABASE_URL"))
    yield engine
    engine.dispose()


@pytest.fixture
def owner_engine(_migrated_owner_engine: Engine) -> Engine:
    """Owner-role engine; every table is emptied (identities reset) before the test."""
    with _migrated_owner_engine.begin() as conn:
        conn.execute(text(f"TRUNCATE {', '.join(TABLES)} RESTART IDENTITY CASCADE"))
    return _migrated_owner_engine


@pytest.fixture
def app_engine(owner_engine: Engine, _app_engine: Engine) -> Iterator[Engine]:
    """App-role engine on a clean database; app.db.session_scope() uses it too."""
    db.configure_engine(_app_engine)
    yield _app_engine
    db.configure_engine(None)


@pytest.fixture
def app_session(app_engine: Engine) -> Iterator[Session]:
    """App-role session. Commit explicitly; uncommitted work is rolled back."""
    with Session(app_engine) as session:
        yield session
        session.rollback()


@pytest.fixture
def make_user(app_session: Session) -> Callable[..., User]:
    """Adds a User to app_session (flushed, not committed)."""

    def _make(**overrides: Any) -> User:
        fields: dict[str, Any] = {
            "email": f"user-{uuid.uuid4().hex[:8]}@example.com",
            "display_name": "Test User",
        }
        fields.update(overrides)
        user = User(**fields)
        app_session.add(user)
        app_session.flush()
        return user

    return _make


@pytest.fixture
def make_tenant(app_session: Session) -> Callable[..., Tenant]:
    """Adds an active Tenant to app_session (flushed, not committed)."""

    def _make(**overrides: Any) -> Tenant:
        suffix = uuid.uuid4().hex[:8]
        domain = overrides.pop("primary_domain", f"t{suffix}.example.com")
        fields: dict[str, Any] = {
            "name": f"Tenant {suffix}",
            "primary_domain": domain,
            "domains": [domain],
            "status": TenantStatus.active,
        }
        fields.update(overrides)
        tenant = Tenant(**fields)
        app_session.add(tenant)
        app_session.flush()
        return tenant

    return _make


# --- Web app, clients and login ---------------------------------------------------

TEST_SECRET_KEY = "test-secret-key-not-for-production-0123456789"
BASE_URL = "https://testserver"  # https, so Secure cookies round-trip


@pytest.fixture(scope="session")
def credential_keys() -> tuple[X25519PrivateKey, str]:
    """A credential key pair for the session: (private key, base64 public key)."""
    from app.crypto.envelope import encode_public_key

    private = X25519PrivateKey.generate()
    return private, encode_public_key(private.public_key())


@pytest.fixture
def web_settings(
    app_engine: Engine, credential_keys: tuple[X25519PrivateKey, str]
) -> Callable[..., Settings]:
    """Builds web-role settings for the test database (overrides as keyword args)."""

    def _make(**overrides: Any) -> Settings:
        fields: dict[str, Any] = {
            "role": "web",
            "database_url": _env("TEST_APP_DATABASE_URL"),
            "secret_key": TEST_SECRET_KEY,
            "credential_public_key": credential_keys[1],
        }
        fields.update(overrides)
        return load_settings(**fields)

    return _make


@pytest.fixture
def make_client(web_settings: Callable[..., Settings]) -> Iterator[Callable[..., TestClient]]:
    """Starts an app (lifespan included) and returns a TestClient on https://testserver.

    make_client(settings=None, oidc_transport=None, **settings_overrides)
    """
    with ExitStack() as stack:

        def _make(
            settings: Settings | None = None,
            oidc_transport: httpx.AsyncBaseTransport | None = None,
            **overrides: Any,
        ) -> TestClient:
            from app.main import create_app

            app = create_app(settings or web_settings(**overrides), oidc_transport=oidc_transport)
            return stack.enter_context(TestClient(app, base_url=BASE_URL))

        yield _make


@pytest.fixture
def client(make_client: Callable[..., TestClient]) -> TestClient:
    return make_client()


@pytest.fixture
def login_as(app_session: Session) -> Callable[[TestClient, User], str]:
    """Signs `user` in on `client` (commits app_session first). Returns the CSRF token.

    The client then sends the session and CSRF cookies and the X-CSRF-Token header.
    """

    def _login(client: TestClient, user: User) -> str:
        from app.auth.csrf import CSRF_COOKIE, CSRF_HEADER
        from app.auth.sessions import SESSION_COOKIE, create_session

        app_session.commit()
        with db.session_scope() as session:
            raw_id, csrf = create_session(session, user.id)
        client.cookies.set(SESSION_COOKIE, raw_id)
        client.cookies.set(CSRF_COOKIE, csrf)
        client.headers[CSRF_HEADER] = csrf
        return csrf

    return _login


# --- Fake OpenID Connect provider (no network) --------------------------------------

class FakeIdP:
    """Serves discovery metadata, JWKS and a token endpoint through an httpx MockTransport.

    The id_token is signed with a fresh RSA key and carries the nonce that the app sent
    in its authorization redirect.
    """

    ISSUER = "https://idp.test"
    METADATA_URL = "https://idp.test/.well-known/openid-configuration"
    CLIENT_ID = "gamut-test-client"

    def __init__(self) -> None:
        self.key = RSAKey.generate_key(2048, parameters={"kid": "test-key"})
        self.nonce: str | None = None
        self.claims: dict[str, Any] = {}
        self.transport = httpx.MockTransport(self._handle)

    def settings_overrides(self) -> dict[str, Any]:
        return {
            "oidc_client_id": self.CLIENT_ID,
            "oidc_client_secret": "test-client-secret",
            "oidc_metadata_url": self.METADATA_URL,
            "public_base_url": "https://gamut.test",
        }

    def _handle(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url == self.METADATA_URL:
            return httpx.Response(200, json={
                "issuer": self.ISSUER,
                "authorization_endpoint": f"{self.ISSUER}/authorize",
                "token_endpoint": f"{self.ISSUER}/token",
                "jwks_uri": f"{self.ISSUER}/jwks",
                "id_token_signing_alg_values_supported": ["RS256"],
            })
        if url == f"{self.ISSUER}/jwks":
            return httpx.Response(200, json={"keys": [self.key.as_dict(private=False)]})
        if url == f"{self.ISSUER}/token" and request.method == "POST":
            now = int(time.time())
            claims = {
                "iss": self.ISSUER,
                "aud": self.CLIENT_ID,
                "iat": now,
                "exp": now + 300,
                "nonce": self.nonce,
                **self.claims,
            }
            id_token = jwt.encode({"alg": "RS256", "kid": "test-key"}, claims, self.key)
            return httpx.Response(200, json={
                "access_token": "test-access-token",
                "token_type": "Bearer",
                "expires_in": 300,
                "id_token": id_token,
            })
        return httpx.Response(404)

    def login(
        self, client: TestClient, *, email: str, sub: str = "sub-1", email_verified: bool = True
    ) -> httpx.Response:
        """Runs the browser side of the flow; returns the callback response."""
        start = client.get("/api/auth/login", follow_redirects=False)
        assert start.status_code == 302, start.text
        query = parse_qs(urlsplit(start.headers["location"]).query)
        self.nonce = query["nonce"][0]
        self.claims = {"sub": sub, "email": email, "email_verified": email_verified}
        callback: httpx.Response = client.get(
            "/api/auth/callback",
            params={"code": "test-code", "state": query["state"][0]},
            follow_redirects=False,
        )
        return callback


@pytest.fixture
def fake_idp() -> FakeIdP:
    return FakeIdP()


# --- Fake gam executable ------------------------------------------------------------

class FakeGam:
    """Handle on a fake `gam` installed in a temporary directory.

    .path         the executable (GAMUT_GAM_BIN points at it)
    .scenario(l)  replace the scenario: a list of {"match": [argv prefix], "exit": int,
                  "stdout": str, "stderr": str, "sleep": float}; the first match wins
    .calls()      every recorded invocation, oldest first, as
                  {"argv": [...], "env": {"GAMCFGDIR": str, "files": [...], "keys": [...]}}
                  (`version` calls are not recorded)
    """

    def __init__(self, directory: Path) -> None:
        self.dir = directory
        self.path = directory / "gam"

    def scenario(self, rules: list[dict[str, Any]]) -> None:
        (self.dir / "scenario.json").write_text(json.dumps(rules), encoding="utf-8")

    def calls(self) -> list[dict[str, Any]]:
        log = self.dir / "calls.jsonl"
        if not log.exists():
            return []
        lines = log.read_text(encoding="utf-8").splitlines()
        return [json.loads(line) for line in lines if line]


@pytest.fixture
def fake_gam(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[FakeGam]:
    """Installs tests/fake_gam/gam and points GAMUT_GAM_BIN (settings) at it."""
    from app.settings import get_settings

    directory = tmp_path / "fake_gam"
    directory.mkdir()
    source = Path(__file__).resolve().parent / "fake_gam" / "gam"
    shutil.copyfile(source, directory / "gam")
    (directory / "gam").chmod(0o755)
    monkeypatch.setenv("GAMUT_GAM_BIN", str(directory / "gam"))
    monkeypatch.setenv("GAMUT_ROLE", "cli")
    monkeypatch.setenv(
        "GAMUT_DATABASE_URL",
        os.environ.get("GAMUT_DATABASE_URL", "postgresql+psycopg://x:x@localhost/x"),
    )
    get_settings.cache_clear()
    yield FakeGam(directory)
    get_settings.cache_clear()


@pytest.fixture
def job_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_gam: FakeGam) -> Path:
    """GAMUT_JOB_DIR (where jobs materialize credentials) in a temporary directory."""
    from app.settings import get_settings

    directory = tmp_path / "jobs"
    directory.mkdir()
    monkeypatch.setenv("GAMUT_JOB_DIR", str(directory))
    get_settings.cache_clear()
    return directory


# --- Ready tenants and an in-process worker (Task 6) --------------------------------

TEST_GAM_FILES = {
    "oauth2.txt": json.dumps(
        {"client_id": "cid", "client_secret": "CS-test-secret", "refresh_token": "RT-test-token"}
    ).encode(),
    "oauth2service.json": json.dumps(
        {"type": "service_account", "client_email": "sa@p.iam", "private_key": "PK-test-key"}
    ).encode(),
}


@pytest.fixture
def make_ready_tenant(
    app_session: Session,
    make_tenant: Callable[..., Tenant],
    credential_keys: tuple[X25519PrivateKey, str],
) -> Callable[..., Tenant]:
    """An active tenant with an admin_email and sealed TEST_GAM_FILES (committed).

    Its last health check is "now" unless overridden, so the worker's daily health
    check leaves it alone.
    """
    from app.crypto.envelope import load_public_key, seal_bundle
    from app.models import TenantCredential

    def _make(**overrides: Any) -> Tenant:
        tenant = make_tenant(**overrides)
        if "admin_email" not in overrides:
            tenant.admin_email = f"admin@{tenant.primary_domain}"
        if "last_health_check_at" not in overrides:  # not due for the daily health check
            tenant.last_health_check_at = datetime.now(UTC)
        sealed = seal_bundle(
            TEST_GAM_FILES, load_public_key(credential_keys[1]),
            associated_data=tenant.id.bytes,
        )
        app_session.add(TenantCredential(
            tenant_id=tenant.id, ciphertext=sealed.ciphertext, nonce=sealed.nonce,
            wrapped_key=sealed.wrapped_key, key_version=sealed.key_version,
            file_names=sorted(TEST_GAM_FILES),
        ))
        app_session.commit()
        return tenant

    return _make


class WorkerDriver:
    """Drives the worker loop in-process (no threads, no sleeping).

    .tick()             one loop iteration (claim+run one job, due scheduled actions,
                        daily health enqueue); returns True when it did any work
    .drain(max_ticks)   tick until idle (bounded); returns the number of busy ticks
    .make_due(job_id)   make the job's waiting steps due now (skip the backoff wait)
    """

    def __init__(self, private_key: X25519PrivateKey, session: Session) -> None:
        self.key = private_key
        self.session = session

    def tick(self) -> bool:
        from app.worker.loop import tick

        busy = tick(self.key, worker_id="test-worker")
        self.session.expire_all()
        return busy

    def drain(self, max_ticks: int = 25) -> int:
        busy = 0
        for _ in range(max_ticks):
            if not self.tick():
                return busy
            busy += 1
        raise AssertionError(f"the worker was still busy after {max_ticks} ticks")

    def make_due(self, job_id: uuid.UUID) -> None:
        with db.session_scope() as session:
            session.execute(
                text(
                    "UPDATE job_steps SET next_poll_at = now() - interval '1 second'"
                    " WHERE job_id = :j AND status = 'waiting'"
                ),
                {"j": job_id},
            )
        self.session.expire_all()


@pytest.fixture
def worker(
    app_session: Session, credential_keys: tuple[X25519PrivateKey, str], job_dir: Path
) -> WorkerDriver:
    """An in-process worker using the fake gam and the test job directory."""
    from app.gam.runner import clear_gam_version_cache

    clear_gam_version_cache()
    return WorkerDriver(credential_keys[0], app_session)
