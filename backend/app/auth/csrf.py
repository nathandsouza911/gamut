# SPDX-License-Identifier: AGPL-3.0-only
"""CSRF protection for state-changing requests.

At login the server sets a readable `gamut_csrf` cookie holding the session's random
token. A POST, PUT, PATCH or DELETE must send the same value in `X-CSRF-Token`; it has to
equal both the cookie and the token stored with the session. The check runs wherever a
request is authenticated (app/auth/deps.py), so every authenticated state change is
covered. The login endpoints themselves are exempt (there is no session yet); they are
rate-limited instead.
"""

import hmac

from fastapi import HTTPException, Request, status

CSRF_COOKIE = "gamut_csrf"
CSRF_HEADER = "X-CSRF-Token"
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
# Login endpoints: no session exists yet. Tests assert every other unsafe route checks CSRF.
CSRF_EXEMPT_PATHS = frozenset({"/api/auth/bootstrap-login", "/api/auth/callback"})


def check_csrf(request: Request, session_token: str) -> None:
    """Raise 403 unless a state-changing request carries the session's CSRF token."""
    if request.method in SAFE_METHODS:
        return
    header = request.headers.get(CSRF_HEADER, "")
    cookie = request.cookies.get(CSRF_COOKIE, "")
    if not (
        header
        and hmac.compare_digest(header.encode(), cookie.encode())
        and hmac.compare_digest(header.encode(), session_token.encode())
    ):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "missing or invalid CSRF token")
