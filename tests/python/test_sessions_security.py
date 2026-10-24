from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from app import security
from app.security import RateLimiter, build_csp
from app.sessions import SessionStore


class Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def test_session_store_expires_idle_sessions_with_sliding_ttl() -> None:
    clock = Clock()
    store: SessionStore[str] = SessionStore(ttl_s=10, max_sessions=5, clock=clock)
    store.set("a", "alpha")
    clock.now = 9
    assert store.get("a") == "alpha"
    clock.now = 18
    assert store.get("a") == "alpha"
    clock.now = 28.1
    assert store.get("a") is None
    assert store.lock("a") is None
    assert len(store) == 0


def test_session_store_evicts_least_recently_used() -> None:
    store: SessionStore[str] = SessionStore(ttl_s=60, max_sessions=2, clock=Clock())
    store.set("a", "alpha")
    store.set("b", "beta")
    store.get("a")
    store.set("c", "gamma")
    assert store.get("b") is None
    assert store.get("a") == "alpha"
    assert store.lock("a") is store.lock("a")


def test_session_store_prunes_expired_before_evicting() -> None:
    clock = Clock()
    store: SessionStore[str] = SessionStore(ttl_s=10, max_sessions=2, clock=clock)
    store.set("old", "x")
    clock.now = 5
    store.set("live", "y")
    clock.now = 12
    store.set("new", "z")
    assert store.get("live") == "y"
    assert store.get("new") == "z"


def test_csp_restricts_framing_only_when_configured() -> None:
    assert "frame-ancestors" not in build_csp()
    csp = build_csp(["'self'", "https://aistudio.google.com"])
    assert "frame-ancestors 'self' https://aistudio.google.com" in csp
    assert "script-src 'self'" in csp
    assert "unsafe-inline" not in csp


def test_rate_limiter_window() -> None:
    clock = Clock()
    limiter = RateLimiter(limit=2, window_s=10, clock=clock)
    assert limiter.retry_after("ip") is None
    assert limiter.retry_after("ip") is None
    assert limiter.retry_after("ip") == 10
    assert limiter.retry_after("other") is None
    clock.now = 10.5
    assert limiter.retry_after("ip") is None


def test_rate_limiter_forgets_idle_clients(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(security, "MAX_TRACKED_CLIENTS", 2)
    clock = Clock()
    limiter = RateLimiter(limit=5, window_s=10, clock=clock)
    for client in ("a", "b", "c"):
        limiter.retry_after(client)
    clock.now = 20
    limiter.retry_after("d")
    assert set(limiter._hits) == {"d"}


def test_security_headers_on_pages_and_api(client: TestClient) -> None:
    page = client.get("/")
    assert "default-src 'self'" in page.headers["content-security-policy"]
    assert page.headers["x-content-type-options"] == "nosniff"
    assert "microphone=()" in page.headers["permissions-policy"]
    assert "cache-control" not in page.headers
    assert client.get("/api/calls").headers["cache-control"] == "no-store"


def test_oversized_bodies_are_rejected(client: TestClient) -> None:
    declared = client.post("/api/session", json={"call_id": "x" * 20_000})
    assert declared.status_code == 413

    def chunked() -> Iterator[bytes]:
        yield b'{"call_id": "'
        for _ in range(40):
            yield b"x" * 1024
        yield b'"}'

    streamed = client.post(
        "/api/session", content=chunked(), headers={"content-type": "application/json"}
    )
    assert streamed.status_code == 413
    assert streamed.json() == {"detail": "Request body is too large."}
