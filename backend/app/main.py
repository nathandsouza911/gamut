# SPDX-License-Identifier: AGPL-3.0-only
"""FastAPI application factory for the web process (API plus the built UI)."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from fastapi import FastAPI, Request
from fastapi.exception_handlers import http_exception_handler
from fastapi.responses import FileResponse, Response
from starlette.concurrency import run_in_threadpool
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.sessions import SessionMiddleware

from app.api import audit, auth, jobs, tenants, users, workflows
from app.auth.bootstrap import ensure_bootstrap_owner
from app.auth.oidc import OidcClient
from app.auth.ratelimit import SlidingWindowLimiter
from app.auth.tenant_guard import check_tenant_routes
from app.crypto.envelope import load_public_key
from app.settings import Settings, SettingsError, get_settings

OIDC_STATE_COOKIE = "gamut_oidc"


def create_app(
    settings: Settings | None = None,
    *,
    oidc_transport: httpx.AsyncBaseTransport | None = None,
) -> FastAPI:
    """Build the web app. `oidc_transport` replaces the network for the OIDC provider (tests)."""
    settings = settings or get_settings()
    secret = settings.secret_key.get_secret_value() if settings.secret_key else ""
    if not secret:
        raise SettingsError("the web app requires: GAMUT_SECRET_KEY")
    # Only the public key: the web process can seal credentials but never open them.
    credential_public_key = load_public_key(settings.credential_public_key)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        await run_in_threadpool(ensure_bootstrap_owner, settings)
        yield

    app = FastAPI(
        title="GAMUT",
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url="/api/openapi.json",
    )
    app.state.settings = settings
    app.state.credential_public_key = credential_public_key
    app.state.rate_limiter = SlidingWindowLimiter()
    app.state.oidc = OidcClient(settings, oidc_transport) if settings.oidc_enabled else None
    # Holds only the OIDC state and nonce between /api/auth/login and the callback:
    # signed with GAMUT_SECRET_KEY, sent to /api/auth only, valid for 10 minutes.
    app.add_middleware(
        SessionMiddleware,
        secret_key=secret,
        session_cookie=OIDC_STATE_COOKIE,
        max_age=600,
        path="/api/auth",
        same_site="lax",
        https_only=True,
    )
    for router in (auth.router, users.router, tenants.router, workflows.router,
                   jobs.router, audit.router, audit.global_router):
        app.include_router(router)

    _mount_ui(app, settings.static_dir)
    check_tenant_routes(app)
    return app


def _mount_ui(app: FastAPI, directory: Path) -> None:
    """Serve the built UI from 404s: a file that exists is sent, any other non-API GET gets
    index.html (client-side routing). Routes win over it, and /api/* misses stay JSON."""
    root = directory.resolve()
    index = root / "index.html"
    if not index.is_file():
        return

    @app.exception_handler(StarletteHTTPException)
    async def not_found_to_ui(request: Request, exc: StarletteHTTPException) -> Response:
        path = request.url.path.lstrip("/")
        is_api = path == "api" or path.startswith("api/")
        if exc.status_code != 404 or request.method != "GET" or is_api:
            return await http_exception_handler(request, exc)
        candidate = (root / path).resolve()
        if path and candidate.is_file() and candidate.is_relative_to(root):
            return FileResponse(candidate)
        return FileResponse(index)
