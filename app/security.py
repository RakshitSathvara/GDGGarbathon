"""HTTP hardening for the FastAPI app, matching the Node server (server/security.ts):
security headers, per-path request-body limits and per-IP sliding-window rate limits."""

from __future__ import annotations

import json
import math
import threading
import time
from collections import deque
from collections.abc import Callable, Iterable

from fastapi import HTTPException, Request
from starlette.types import ASGIApp, Message, Receive, Scope, Send

PERMISSIONS_POLICY = "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
TOO_MANY_REQUESTS = "Too many requests. Please wait a moment and try again."
BODY_TOO_LARGE = "Request body is too large."
MAX_TRACKED_CLIENTS = 10_000


def build_csp(frame_ancestors: Iterable[str] | None = None) -> str:
    directives = {
        "default-src": ["'self'"],
        "script-src": ["'self'"],
        "script-src-attr": ["'none'"],
        "style-src": ["'self'", "https://fonts.googleapis.com"],
        "font-src": ["'self'", "https://fonts.gstatic.com"],
        "img-src": ["'self'", "data:"],
        "media-src": ["'self'", "blob:"],
        "connect-src": ["'self'"],
        "object-src": ["'none'"],
        "base-uri": ["'self'"],
        "form-action": ["'self'"],
    }
    if frame_ancestors:
        directives["frame-ancestors"] = list(frame_ancestors)
    return ";".join(f"{name} {' '.join(values)}" for name, values in directives.items())


class SecurityHeadersMiddleware:
    """Adds CSP and companion headers to every response, plus no-store on API responses."""

    def __init__(self, app: ASGIApp, frame_ancestors: Iterable[str] | None = None) -> None:
        self.app = app
        self.headers = [
            (b"content-security-policy", build_csp(frame_ancestors).encode()),
            (b"x-content-type-options", b"nosniff"),
            (b"referrer-policy", b"strict-origin-when-cross-origin"),
            (b"permissions-policy", PERMISSIONS_POLICY.encode()),
            (b"cross-origin-opener-policy", b"same-origin"),
            (b"cross-origin-resource-policy", b"same-origin"),
            (b"strict-transport-security", b"max-age=31536000; includeSubDomains"),
        ]

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        is_api = scope["path"].startswith("/api/")

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = [*message.get("headers", []), *self.headers]
                if is_api:
                    headers.append((b"cache-control", b"no-store"))
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_with_headers)


def _declared_length(scope: Scope) -> int | None:
    for name, value in scope.get("headers", []):
        if name == b"content-length":
            try:
                return int(value)
            except ValueError:
                return None
    return None


class BodySizeLimitMiddleware:
    """Rejects oversized request bodies with 413, whether or not Content-Length is sent."""

    def __init__(self, app: ASGIApp, default_limit: int, path_limits: dict[str, int]) -> None:
        self.app = app
        self.default_limit = default_limit
        self.path_limits = path_limits

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        limit = self.path_limits.get(scope["path"], self.default_limit)
        declared = _declared_length(scope)
        if declared is not None and declared > limit:
            body = json.dumps({"detail": BODY_TOO_LARGE}).encode()
            await send(
                {
                    "type": "http.response.start",
                    "status": 413,
                    "headers": [(b"content-type", b"application/json")],
                }
            )
            await send({"type": "http.response.body", "body": body})
            return

        received = 0

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    raise HTTPException(status_code=413, detail=BODY_TOO_LARGE)
            return message

        await self.app(scope, limited_receive, send)


class RateLimiter:
    """Sliding-window limiter keyed by client address (thread-safe, in-memory per process)."""

    def __init__(
        self, limit: int, window_s: float, clock: Callable[[], float] = time.monotonic
    ) -> None:
        self.limit = limit
        self.window_s = window_s
        self._clock = clock
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def retry_after(self, key: str) -> int | None:
        """Records a request; returns None when allowed, else seconds until a slot frees up."""
        now = self._clock()
        with self._lock:
            if len(self._hits) > MAX_TRACKED_CLIENTS:
                self._sweep(now)
            hits = self._hits.setdefault(key, deque())
            while hits and hits[0] <= now - self.window_s:
                hits.popleft()
            if len(hits) >= self.limit:
                return max(1, math.ceil(hits[0] + self.window_s - now))
            hits.append(now)
            return None

    def _sweep(self, now: float) -> None:
        stale = [
            key for key, hits in self._hits.items() if not hits or hits[-1] <= now - self.window_s
        ]
        for key in stale:
            del self._hits[key]


def rate_limit(limiter: RateLimiter) -> Callable[[Request], None]:
    """FastAPI dependency that answers 429 (with Retry-After) once a client exceeds the limit."""

    def dependency(request: Request) -> None:
        client = request.client.host if request.client else "unknown"
        wait = limiter.retry_after(client)
        if wait is not None:
            raise HTTPException(
                status_code=429, detail=TOO_MANY_REQUESTS, headers={"Retry-After": str(wait)}
            )

    return dependency
