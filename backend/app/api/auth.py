# SPDX-License-Identifier: AGPL-3.0-only
"""Sign-in and sign-out.

GET  /api/auth/login            redirect to the OIDC provider
GET  /api/auth/callback         finish OIDC sign-in (existing users only), then redirect to /
POST /api/auth/bootstrap-login  break-glass password sign-in for the bootstrap owner
POST /api/auth/logout           end the session

Every attempt is audited: auth.login / auth.bootstrap_login on success, auth.login_failed
(never with the attempted password) on failure, auth.logout on sign-out. Both login
endpoints share the login rate limit: 10 per minute per client IP.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from starlette.concurrency import run_in_threadpool

from app.api.users import MeOut, me_payload
from app.audit.chain import append_event
from app.auth.bootstrap import normalize_email, verify_password_login
from app.auth.deps import current_user
from app.auth.oidc import OidcClient, OidcError, OidcIdentity
from app.auth.ratelimit import LOGIN_LIMIT, rate_limit
from app.auth.sessions import (
    SESSION_COOKIE,
    clear_session_cookies,
    create_session,
    delete_session,
    set_session_cookies,
)
from app.db import session_scope
from app.models import User
from app.settings import Settings

router = APIRouter(prefix="/api/auth", tags=["auth"])
login_rate_limit = Depends(rate_limit("login", *LOGIN_LIMIT, per="ip"))
_SIGN_IN_FAILED = "sign-in failed"


class PasswordLogin(BaseModel):
    email: str = Field(max_length=320)
    password: str = Field(max_length=1024)


def _audit_failure(target: str | None, method: str, reason: str) -> None:
    with session_scope() as db:
        append_event(
            db, actor="anonymous", tenant_id=None, action="auth.login_failed",
            target=None if target is None else target[:320],
            details={"method": method, "reason": reason},
        )


def _oidc(request: Request) -> OidcClient:
    client: OidcClient | None = request.app.state.oidc
    if client is None:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "OIDC sign-in is not configured")
    return client


@router.get("/login")
async def oidc_login(request: Request) -> Response:
    try:
        return await _oidc(request).redirect(request)
    except OidcError:
        raise HTTPException(
            status.HTTP_502_BAD_GATEWAY, "the sign-in provider is unavailable"
        ) from None


def _finish_oidc(identity: OidcIdentity) -> tuple[str, str] | str:
    """(session cookie, CSRF token) for a known user, else the failure reason."""
    with session_scope() as db:
        if not identity.email_verified:
            return "email_not_verified"
        user = db.scalar(select(User).where(User.oidc_subject == identity.subject))
        if user is None:
            user = db.scalar(select(User).where(func.lower(User.email) == identity.email))
            if user is None:
                return "unknown_user"
            if user.oidc_subject is None:
                user.oidc_subject = identity.subject  # first OIDC sign-in links the account
            elif user.oidc_subject != identity.subject:
                return "subject_mismatch"
        if user.disabled:
            return "user_disabled"
        session = create_session(db, user.id)
        append_event(
            db, actor=user.email, tenant_id=None, action="auth.login",
            target=user.email, details={"method": "oidc", "user_id": str(user.id)},
        )
        return session


@router.get("/callback", dependencies=[login_rate_limit])
async def oidc_callback(request: Request) -> Response:
    client = _oidc(request)
    try:
        identity = await client.identity(request)
    except OidcError as exc:
        await run_in_threadpool(_audit_failure, None, "oidc", f"provider_error:{exc}")
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, _SIGN_IN_FAILED) from None
    result = await run_in_threadpool(_finish_oidc, identity)
    if isinstance(result, str):
        await run_in_threadpool(_audit_failure, identity.email, "oidc", result)
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "this account may not sign in to GAMUT; ask an owner to add you",
        )
    settings: Settings = request.app.state.settings
    response = RedirectResponse((settings.public_base_url or "").rstrip("/") + "/", 303)
    set_session_cookies(response, *result)
    return response


@router.post("/bootstrap-login", dependencies=[login_rate_limit])
def bootstrap_login(body: PasswordLogin, response: Response) -> MeOut:
    with session_scope() as db:
        user = verify_password_login(db, body.email, body.password)
        if user is not None:
            cookie, csrf = create_session(db, user.id)
            append_event(
                db, actor=user.email, tenant_id=None, action="auth.bootstrap_login",
                target=user.email, details={"method": "password", "user_id": str(user.id)},
            )
            payload = me_payload(db, user)
    if user is None:
        _audit_failure(normalize_email(body.email), "password", "invalid_credentials")
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid email or password")
    set_session_cookies(response, cookie, csrf)
    return payload


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(request: Request, user: Annotated[User, Depends(current_user)]) -> Response:
    with session_scope() as db:
        delete_session(db, request.cookies.get(SESSION_COOKIE))
        append_event(
            db, actor=user.email, tenant_id=None, action="auth.logout",
            target=user.email, details={},
        )
    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    clear_session_cookies(response)
    return response
