# SPDX-License-Identifier: AGPL-3.0-only
"""FastAPI application factory for the web process.

The static UI mount arrives with the UI (Task 8).
"""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI
from starlette.concurrency import run_in_threadpool
from starlette.middleware.sessions import SessionMiddleware

from app.api import auth, tenants, users
from app.auth.bootstrap import ensure_bootstrap_owner
from app.auth.oidc import OidcClient
from app.auth.ratelimit import SlidingWindowLimiter
from app.auth.tenant_guard import check_tenant_routes
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
    for router in (auth.router, users.router, tenants.router):
        app.include_router(router)
    check_tenant_routes(app)
    return app
