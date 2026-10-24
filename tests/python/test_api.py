"""HTTP tests for the FastAPI app (same contract as tests/node/app.test.ts)."""

from __future__ import annotations

import base64
import dataclasses
import json
import uuid
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient

from app.config import RateLimit, Settings
from app.main import create_app
from app.storage import CallStore

from .conftest import ScriptedAnalyzer, analysis, make_wav


def new_session(client: TestClient, call_id: str = "fake_kyc") -> str:
    response = client.post("/api/session", json={"call_id": call_id})
    assert response.status_code == 200
    return response.json()["session_id"]


def analyze(client: TestClient, session_id: str, chunk_index: int, **extra: object):
    return client.post(
        "/api/analyze", json={"session_id": session_id, "chunk_index": chunk_index, **extra}
    )


def test_health_and_calls(client: TestClient) -> None:
    assert client.get("/api/health").json() == {"status": "ok"}
    body = client.get("/api/calls").json()
    assert [call["id"] for call in body["calls"]] == ["fake_kyc"]
    assert len(body["calls"][0]["chunks"]) == 4
    assert body["demo_replay"] is False
    assert body["model"] == "gemini-3.8-flash"


def test_live_analysis_applies_rules_and_feeds_context(
    client: TestClient, analyzer: ScriptedAnalyzer
) -> None:
    session_id = new_session(client)
    first = analyze(client, session_id, 0).json()
    assert first["chunk"]["verdict"] == "SAFE"
    assert first["chunk"]["mode"] == "LIVE"

    second = analyze(client, session_id, 1).json()
    assert second["chunk"]["model_risk_score"] == 40
    assert second["chunk"]["risk_score"] == 75
    assert second["session"]["verdict"] == "SCAM"
    assert "તમારો OTP આપો" in second["session"]["warning_gu"]
    assert "CALL SO FAR:\nCALLER: નમસ્તે" in analyzer.context_blocks[-1]


def test_concurrent_requests_for_a_chunk_analyze_it_once(
    client: TestClient, analyzer: ScriptedAnalyzer
) -> None:
    session_id = new_session(client)
    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(pool.map(lambda _: analyze(client, session_id, 0), range(2)))
    assert responses[0].json()["chunk"] == responses[1].json()["chunk"]
    assert len(analyzer.context_blocks) == 1


@pytest.mark.parametrize(
    ("body", "status", "detail"),
    [
        ({"chunk_index": 99}, 400, "Invalid chunk_index 99"),
        ({"chunk_index": -1}, 400, "chunk_index"),
        ({"chunk_index": 1.5}, 400, "chunk_index"),
        ({"session_id": "not-a-uuid", "chunk_index": 0}, 400, "session_id"),
        ({"session_id": str(uuid.uuid4()), "chunk_index": 0}, 404, "Session not found"),
    ],
)
def test_analyze_validation(client: TestClient, body: dict, status: int, detail: str) -> None:
    payload = {"session_id": new_session(client), **body}
    response = client.post("/api/analyze", json=payload)
    assert response.status_code == status
    assert detail in response.json()["detail"]


def test_session_validation(client: TestClient) -> None:
    assert client.post("/api/session", json={"call_id": "nope"}).status_code == 404
    malformed = client.post(
        "/api/session", content=b"{bad", headers={"content-type": "application/json"}
    )
    assert malformed.status_code == 400
    assert malformed.json() == {"detail": "Malformed request."}
    assert client.post("/api/session", json={}).status_code == 400
    assert client.get("/api/nope").status_code == 404


def test_upload_creates_a_playable_call(client: TestClient) -> None:
    wav = make_wav([(7.0, 3000)])
    response = client.post(
        "/api/upload",
        json={
            "filename": "Grandpa.wav",
            "data_base64": base64.b64encode(wav).decode(),
            "title": "Grandpa",
            "expected": "SAFE",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["call"]["id"] == "upload_grandpa"
    assert body["call"]["expected"] == "SAFE"
    assert len(body["calls"]) == 2
    assert client.get("/calls/upload_grandpa.wav").status_code == 200

    bad_base64 = client.post("/api/upload", json={"filename": "x.wav", "data_base64": "!!!!"})
    assert bad_base64.status_code == 400
    wrong_type = client.post(
        "/api/upload",
        json={"filename": "x.mp3", "data_base64": base64.b64encode(wav).decode()},
    )
    assert wrong_type.status_code == 400
    assert "Only .wav" in wrong_type.json()["detail"]


def test_serves_only_top_level_audio_and_the_app(client: TestClient) -> None:
    audio = client.get("/calls/fake_kyc.wav")
    assert audio.status_code == 200
    assert audio.headers["content-type"] == "audio/wav"
    for blocked in ("/calls/manifest.json", "/calls/raw/x.wav", "/calls/missing.wav"):
        assert client.get(blocked).status_code == 404, blocked
    assert '<h1 class="brand">' in client.get("/").text
    script = client.get("/static/js/app.js")
    assert script.status_code == 200
    assert "javascript" in script.headers["content-type"]


def test_missing_audio_is_reported(client: TestClient, settings: Settings) -> None:
    session_id = new_session(client)
    (settings.calls_dir / "fake_kyc.wav").unlink()
    response = analyze(client, session_id, 0)
    assert response.status_code == 404
    assert "Audio file missing" in response.json()["detail"]


@pytest.fixture
def replay_client(settings: Settings, store: CallStore, analyzer: ScriptedAnalyzer) -> TestClient:
    replay_settings = dataclasses.replace(settings, demo_replay=True)
    store.settings = replay_settings
    return TestClient(create_app(replay_settings, analyzer, store, sleep=lambda _s: None))


def test_replay_mode_reuses_the_rules(
    replay_client: TestClient, settings: Settings, analyzer: ScriptedAnalyzer
) -> None:
    cache = settings.cache_dir / "fake_kyc.json"
    cache.write_text(
        json.dumps(
            {
                "model": "recorded-model",
                "chunks": [
                    {
                        **analysis(risk_score=20),
                        "raw_new_red_flags": [{"type": "SECRECY", "quote": "shh", "why": "x"}],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    session_id = new_session(replay_client)
    body = analyze(replay_client, session_id, 0).json()
    assert body["chunk"]["mode"] == "REPLAY"
    assert body["chunk"]["model"] == "recorded-model"
    assert body["chunk"]["risk_score"] == 75
    assert analyzer.context_blocks == []

    assert analyze(replay_client, session_id, 3).status_code == 404
    cache.write_text("{corrupt", encoding="utf-8")
    assert analyze(replay_client, session_id, 2).status_code == 500
    cache.unlink()
    missing = analyze(replay_client, session_id, 1, replay=True)
    assert missing.status_code == 404
    assert "Run scripts/eval.py" in missing.json()["detail"]


def make_client(
    settings: Settings, store: CallStore, analyzer: ScriptedAnalyzer, **changes: object
) -> TestClient:
    changed = dataclasses.replace(settings, **changes)
    return TestClient(create_app(changed, analyzer, store, sleep=lambda _s: None))


def test_rate_limits_return_429_with_retry_after(
    settings: Settings, store: CallStore, analyzer: ScriptedAnalyzer
) -> None:
    client = make_client(settings, store, analyzer, read_limit=RateLimit(limit=2, window_s=60))
    statuses = [client.get("/api/calls").status_code for _ in range(3)]
    assert statuses == [200, 200, 429]
    assert client.get("/api/calls").headers["retry-after"] == "60"


def test_frame_ancestors_are_configurable(
    settings: Settings, store: CallStore, analyzer: ScriptedAnalyzer
) -> None:
    client = make_client(settings, store, analyzer, frame_ancestors=("'self'",))
    assert "frame-ancestors 'self'" in client.get("/").headers["content-security-policy"]


def test_unexpected_errors_are_hidden(settings: Settings, store: CallStore) -> None:
    def broken(_wav: bytes, _context: str) -> dict:
        raise RuntimeError("database password is hunter2")

    app = create_app(settings, broken, store, sleep=lambda _s: None)
    with TestClient(app, raise_server_exceptions=False) as client:
        session_id = new_session(client)
        response = analyze(client, session_id, 0)
    assert response.status_code == 500
    assert "hunter2" not in response.text


def test_default_app_is_importable(monkeypatch: pytest.MonkeyPatch) -> None:
    from app import main

    assert main.app.title == "Saavdhan API"
    analyzer: Callable[[bytes, str], dict] = main._gemini_analyzer
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    assert analyzer(b"wav", "CHUNK 1/1")["status"] == "unavailable"
