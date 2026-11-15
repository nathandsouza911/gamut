# SPDX-License-Identifier: AGPL-3.0-only
"""Sliding-window rate limits.

LIMITATION (Milestone 1): the counters live in memory, per web process. They reset on
restart, and with several web processes each one counts separately, so the effective
limit is `limit` times the number of processes. GAMUT runs one web process by default.
A shared store (PostgreSQL) is the fix if that ever changes.
"""

import math
import threading
import time
from collections import deque
from collections.abc import Callable
from typing import Annotated, Literal

from fastapi import Depends, HTTPException, Request, status

from app.auth.deps import current_user
from app.models import User

LOGIN_LIMIT = (10, 60)  # 10 attempts per minute per client IP
JOB_CREATE_LIMIT = (30, 60)  # 30 jobs per minute per user


class SlidingWindowLimiter:
    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def hit(self, key: str, *, limit: int, window_s: int) -> float | None:
        """Record one hit. Returns None if allowed, else seconds until a slot frees up."""
        now = self._clock()
        with self._lock:
            hits = self._hits.setdefault(key, deque())
            while hits and hits[0] <= now - window_s:
                hits.popleft()
            if len(hits) >= limit:
                return hits[0] + window_s - now
            hits.append(now)
            # Drop idle keys so the table does not grow without bound.
            if len(self._hits) > 10_000:
                for k in [k for k, v in self._hits.items() if not v or v[-1] <= now - window_s]:
                    del self._hits[k]
            return None


def _limiter(request: Request) -> SlidingWindowLimiter:
    limiter: SlidingWindowLimiter = request.app.state.rate_limiter
    return limiter


def _enforce(request: Request, bucket: str, limit: int, window_s: int) -> None:
    retry_after = _limiter(request).hit(bucket, limit=limit, window_s=window_s)
    if retry_after is not None:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "too many requests; try again later",
            headers={"Retry-After": str(max(1, math.ceil(retry_after)))},
        )


def rate_limit(
    key: str, limit: int, window_s: int, *, per: Literal["ip", "user"] = "ip"
) -> Callable[..., None]:
    """Dependency: at most `limit` requests per `window_s` seconds for each client IP
    (per="ip") or signed-in user (per="user"), counted in the bucket named `key`."""
    if per == "user":

        def by_user(request: Request, user: Annotated[User, Depends(current_user)]) -> None:
            _enforce(request, f"{key}:user:{user.id}", limit, window_s)

        return by_user

    def by_ip(request: Request) -> None:
        # Behind the reverse proxy, uvicorn sets client.host from X-Forwarded-For
        # (trusted proxies: GAMUT_FORWARDED_ALLOW_IPS).
        host = request.client.host if request.client else "unknown"
        _enforce(request, f"{key}:ip:{host}", limit, window_s)

    return by_ip
