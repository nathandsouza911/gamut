# SPDX-License-Identifier: AGPL-3.0-only
"""OpenID Connect sign-in through Authlib (Google by default).

The authorization-code flow keeps its state and nonce in a short-lived signed cookie
(Starlette SessionMiddleware, see app/main.py). Only a verified email is accepted, and
it must belong to an existing panel user: sign-in never creates users.
"""

from dataclasses import dataclass
from typing import Any

import httpx
from authlib.common.errors import AuthlibBaseError
from authlib.integrations.starlette_client import OAuth
from joserfc.errors import JoseError
from starlette.requests import Request
from starlette.responses import Response

from app.settings import Settings

PROVIDER = "oidc"
CALLBACK_PATH = "/api/auth/callback"


class OidcError(Exception):
    """The provider exchange failed (bad state, bad token, provider unreachable)."""


@dataclass(frozen=True)
class OidcIdentity:
    subject: str
    email: str
    email_verified: bool


class OidcClient:
    def __init__(
        self, settings: Settings, transport: httpx.AsyncBaseTransport | None = None
    ) -> None:
        if not settings.oidc_enabled or settings.oidc_client_secret is None:
            raise ValueError("OIDC is not configured")
        client_kwargs: dict[str, Any] = {"scope": "openid email profile"}
        if transport is not None:  # tests: a mocked provider, no network
            client_kwargs["transport"] = transport
        self._oauth = OAuth()
        self._oauth.register(
            PROVIDER,
            client_id=settings.oidc_client_id,
            client_secret=settings.oidc_client_secret.get_secret_value(),
            server_metadata_url=settings.oidc_metadata_url,
            client_kwargs=client_kwargs,
        )
        self._redirect_uri = (settings.public_base_url or "").rstrip("/") + CALLBACK_PATH

    @property
    def _client(self) -> Any:
        return self._oauth.create_client(PROVIDER)

    async def redirect(self, request: Request) -> Response:
        try:
            response: Response = await self._client.authorize_redirect(
                request, self._redirect_uri
            )
        except (AuthlibBaseError, httpx.HTTPError) as exc:
            raise OidcError(type(exc).__name__) from None
        return response

    async def identity(self, request: Request) -> OidcIdentity:
        """Exchange the callback's code and validate the id_token (signature, nonce, aud)."""
        try:
            token = await self._client.authorize_access_token(request)
        except (AuthlibBaseError, JoseError, httpx.HTTPError, ValueError) as exc:
            raise OidcError(type(exc).__name__) from None
        claims = token.get("userinfo") or {}
        subject, email = claims.get("sub"), claims.get("email")
        if not isinstance(subject, str) or not isinstance(email, str) or not subject:
            raise OidcError("id_token lacks sub or email")
        return OidcIdentity(
            subject=subject,
            email=email.strip().lower(),
            email_verified=claims.get("email_verified") is True,
        )
