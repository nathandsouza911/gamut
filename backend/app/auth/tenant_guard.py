# SPDX-License-Identifier: AGPL-3.0-only
"""Tenant isolation at the route level.

Every route whose path has a `{tenant_id}` parameter must use TenantScopedRoute (build
its router with `APIRouter(route_class=TenantScopedRoute)`). The route checks the
session and the caller's access to the tenant BEFORE FastAPI reads or validates the
request body, so a non-member always gets 404, never 422 (which would confirm that the
route exists for that tenant). create_app() calls check_tenant_routes() and refuses to
start if any `{tenant_id}` route uses another route class.
"""

from collections.abc import Callable, Coroutine, Iterator
from typing import Any

from fastapi import FastAPI, Request, Response
from fastapi.routing import APIRoute
from starlette.concurrency import run_in_threadpool
from starlette.routing import BaseRoute

from app.auth.deps import authenticate, tenant_access


class TenantRouteError(RuntimeError):
    """A `{tenant_id}` route is not protected by TenantScopedRoute."""


class TenantScopedRoute(APIRoute):
    def get_route_handler(self) -> Callable[[Request], Coroutine[Any, Any, Response]]:
        handler = super().get_route_handler()

        async def guarded(request: Request) -> Response:
            raw_tenant_id = request.path_params.get("tenant_id")
            if raw_tenant_id is not None:
                user = await run_in_threadpool(authenticate, request)
                await run_in_threadpool(tenant_access, request, user, str(raw_tenant_id))
            return await handler(request)

        return guarded


def iter_routes(app: FastAPI) -> Iterator[tuple[str, set[str], BaseRoute]]:
    """(full path, methods, route object) for every HTTP route, included routers too."""
    try:
        # FastAPI >= 0.16x keeps included routers nested; this flattens them.
        from fastapi.routing import iter_route_contexts
    except ImportError:  # pragma: no cover - older FastAPI flattens app.routes itself
        for route in app.routes:
            path = getattr(route, "path", None)
            if path is not None:
                yield path, set(getattr(route, "methods", None) or ()), route
        return
    for context in iter_route_contexts(app.routes):
        if context.path is not None:
            yield context.path, set(context.methods or ()), context.original_route


def check_tenant_routes(app: FastAPI) -> None:
    unguarded = [
        f"{getattr(route, 'name', '?')} {path}"
        for path, _, route in iter_routes(app)
        if "{tenant_id}" in path and not isinstance(route, TenantScopedRoute)
    ]
    if unguarded:
        raise TenantRouteError(
            "routes with {tenant_id} must use TenantScopedRoute: " + ", ".join(unguarded)
        )
