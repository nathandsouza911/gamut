# SPDX-License-Identifier: AGPL-3.0-only
"""Request authentication and authorisation dependencies.

- current_user: the signed-in User (401 without a live session). For POST, PUT, PATCH
  and DELETE it also enforces the CSRF token (403).
- require_owner: 403 unless the user is an owner.
- require_tenant_role(*roles): the caller's Membership on the `tenant_id` path parameter.
  Owners always pass (with a transient Membership whose role is `owner`). A user with no
  membership gets 404, exactly as if the tenant did not exist; a member whose role is not
  in `roles` gets 403. With no roles given, any member passes.

Results are cached on request.state, so the tenant guard (app/auth/tenant_guard.py) and
the dependencies share one lookup per request.
"""

import uuid
from collections.abc import Callable
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select

from app.auth.csrf import check_csrf
from app.auth.sessions import SESSION_COOKIE, load_session
from app.db import session_scope
from app.models import Membership, Role, Tenant, User

TENANT_NOT_FOUND = "tenant not found"


def authenticate(request: Request) -> User:
    """The session's user (cached per request); 401 if none, 403 on a CSRF failure."""
    cached: User | None = getattr(request.state, "gamut_user", None)
    if cached is not None:
        return cached
    user: User | None = None
    csrf_token = ""
    with session_scope() as db:
        row = load_session(db, request.cookies.get(SESSION_COOKIE))
        if row is not None:
            user = db.get(User, row.user_id)
            csrf_token = row.csrf_token
    # Raised after the commit, so an expired session's deletion is kept.
    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "not signed in")
    check_csrf(request, csrf_token)
    request.state.gamut_user = user
    return user


def tenant_access(request: Request, user: User, raw_tenant_id: str) -> Membership:
    """The user's Membership on the tenant (cached per request). 404 if the user has none."""
    cache = _membership_cache(request)
    if raw_tenant_id in cache:
        return cache[raw_tenant_id]
    try:
        tenant_id = uuid.UUID(raw_tenant_id)
    except ValueError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, TENANT_NOT_FOUND) from None
    membership: Membership | None
    with session_scope() as db:
        if user.is_owner:
            exists = db.scalar(select(Tenant.id).where(Tenant.id == tenant_id))
            membership = None
        else:
            exists = None
            membership = db.scalar(
                select(Membership).where(
                    Membership.user_id == user.id, Membership.tenant_id == tenant_id
                )
            )
    if user.is_owner and exists is not None:
        membership = Membership(user_id=user.id, tenant_id=tenant_id, role=Role.owner)
    if membership is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, TENANT_NOT_FOUND)
    cache[raw_tenant_id] = membership
    return membership


def _membership_cache(request: Request) -> dict[str, Membership]:
    cache: dict[str, Membership] | None = getattr(request.state, "gamut_memberships", None)
    if cache is None:
        cache = {}
        request.state.gamut_memberships = cache
    return cache


def current_user(request: Request) -> User:
    return authenticate(request)


def require_owner(user: Annotated[User, Depends(current_user)]) -> User:
    if not user.is_owner:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "owner role required")
    return user


def require_tenant_role(*roles: Role) -> Callable[..., Membership]:
    allowed = frozenset(roles)

    def dependency(
        request: Request, user: Annotated[User, Depends(current_user)]
    ) -> Membership:
        raw_tenant_id = request.path_params.get("tenant_id")
        if raw_tenant_id is None:
            raise RuntimeError("require_tenant_role used on a route without {tenant_id}")
        membership = tenant_access(request, user, str(raw_tenant_id))
        if membership.role is not Role.owner and allowed and membership.role not in allowed:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "your role does not allow this")
        return membership

    return dependency
