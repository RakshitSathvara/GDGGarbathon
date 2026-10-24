from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

import pytest
from pydantic import ValidationError

from app import detector
from app.detector import (
    analyze_chunk,
    describe_failure,
    extract_interaction_text,
    normalize_thinking_level,
    strip_code_fence,
    validate_chunk_payload,
)

from .conftest import analysis

MODEL_OUTPUT = json.dumps(analysis(risk_score=80, verdict="SCAM"))


@pytest.fixture
def sleeps(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    recorded: list[float] = []
    monkeypatch.setattr(detector.time, "sleep", recorded.append)
    return recorded


@pytest.fixture
def api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    monkeypatch.delenv("MODEL", raising=False)
    monkeypatch.delenv("THINKING_LEVEL", raising=False)


def scripted_api(monkeypatch: pytest.MonkeyPatch, *replies: str | Exception) -> list[dict]:
    calls: list[dict[str, Any]] = []
    queue = list(replies)

    def fake(wav_b64: str, context: str, model: str, thinking: str, key: str) -> str:
        calls.append({"model": model, "thinking": thinking, "context": context, "key": key})
        reply = queue.pop(0)
        if isinstance(reply, Exception):
            raise reply
        return reply

    monkeypatch.setattr(detector, "_call_interactions_api", fake)
    return calls


def test_validate_chunk_payload() -> None:
    assert validate_chunk_payload(analysis(risk_score=55))["risk_score"] == 55
    with pytest.raises(ValidationError):
        validate_chunk_payload(analysis(risk_score=101))
    with pytest.raises(ValidationError):
        validate_chunk_payload({**analysis(), "scam_type": "LOTTERY"})


def test_strip_code_fence() -> None:
    assert strip_code_fence('```json\n{"a": 1}\n```') == '{"a": 1}'
    assert strip_code_fence('```\n{"a": 1}') == '{"a": 1}'
    assert strip_code_fence('  {"a": 1} ') == '{"a": 1}'


def test_normalize_thinking_level() -> None:
    assert normalize_thinking_level("gemini-3.8-flash", "minimal") == "low"
    assert normalize_thinking_level("gemini-3.8-flash", "high") == "high"
    assert normalize_thinking_level("gemini-3.5-flash-lite", "minimal") == "minimal"


def test_extract_interaction_text_variants() -> None:
    assert extract_interaction_text({"output_text": "direct"}) == "direct"
    steps = {
        "steps": [
            {"type": "model_output", "content": [{"type": "text", "text": "older"}]},
            {"type": "thought", "content": [{"type": "text", "text": "ignored"}]},
            {"type": "model_output", "content": [{"type": "image"}, {"type": "text", "text": "x"}]},
        ]
    }
    assert extract_interaction_text(steps) == "x"
    assert extract_interaction_text({"outputs": [{"type": "text", "text": "out"}]}) == "out"
    sdk_object = SimpleNamespace(
        output_text=None,
        steps=[
            SimpleNamespace(
                type="model_output", content=[SimpleNamespace(type="text", text="from sdk")]
            )
        ],
    )
    assert extract_interaction_text(sdk_object) == "from sdk"
    with pytest.raises(ValueError, match="Empty output_text"):
        extract_interaction_text({"steps": []})


def test_describe_failure_is_safe_for_clients() -> None:
    assert describe_failure(TimeoutError("timed out")) == "Gemini request timed out"
    assert describe_failure(RuntimeError("429 RESOURCE_EXHAUSTED")) == "Gemini rate limit reached"
    assert describe_failure(json.JSONDecodeError("bad", "x", 0)) == (
        "Gemini returned an invalid response"
    )
    assert describe_failure(RuntimeError("500 secret details")) == "Gemini request failed"


def test_without_api_key_nothing_is_sent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    calls = scripted_api(monkeypatch)
    result = analyze_chunk(b"wav", "CHUNK 1/1")
    assert result["status"] == "unavailable"
    assert result["error"] == "GEMINI_API_KEY is not configured"
    assert calls == []


@pytest.mark.usefixtures("api_key")
def test_successful_analysis(monkeypatch: pytest.MonkeyPatch, sleeps: list[float]) -> None:
    calls = scripted_api(monkeypatch, f"```json\n{MODEL_OUTPUT}\n```")
    result = analyze_chunk(b"wav", "CHUNK 1/3", thinking_level="minimal")
    assert result["status"] == "ok"
    assert result["risk_score"] == 80
    assert result["model"] == "gemini-3.8-flash"
    assert calls[0]["thinking"] == "low"
    assert calls[0]["key"] == "test-key"
    assert sleeps == []


@pytest.mark.usefixtures("api_key")
def test_retries_once_after_a_failure(monkeypatch: pytest.MonkeyPatch, sleeps: list[float]) -> None:
    calls = scripted_api(monkeypatch, RuntimeError("503 overloaded"), MODEL_OUTPUT)
    result = analyze_chunk(b"wav", "CHUNK 1/1", model="gemini-3.5-flash-lite")
    assert result["status"] == "ok"
    assert [call["model"] for call in calls] == ["gemini-3.5-flash-lite"] * 2
    assert sleeps == [0.5]


@pytest.mark.usefixtures("api_key")
def test_gives_up_without_inventing_a_verdict(
    monkeypatch: pytest.MonkeyPatch, sleeps: list[float]
) -> None:
    scripted_api(monkeypatch, RuntimeError("429 RESOURCE_EXHAUSTED"), RuntimeError("429"))
    result = analyze_chunk(b"wav", "CHUNK 1/1")
    assert result == {
        "status": "unavailable",
        "error": "Gemini rate limit reached",
        "latency_ms": result["latency_ms"],
        "model": "gemini-3.8-flash",
    }
    assert sleeps == [2.0]


def test_interactions_request_contract(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    class FakeInteractions:
        def create(self, **kwargs: Any) -> SimpleNamespace:
            captured["request"] = kwargs
            return SimpleNamespace(output_text=MODEL_OUTPUT, steps=[])

    class FakeClient:
        def __init__(self, api_key: str, http_options: dict[str, Any]) -> None:
            captured["client"] = {"api_key": api_key, "http_options": http_options}
            self.interactions = FakeInteractions()

    monkeypatch.setattr(detector.genai, "Client", FakeClient)
    text = detector._call_interactions_api("QUJD", "CHUNK 1/2", "gemini-3.8-flash", "low", "k")
    assert text == MODEL_OUTPUT
    assert captured["client"] == {"api_key": "k", "http_options": {"timeout": 15_000}}
    assert captured["request"] == {
        "model": "gemini-3.8-flash",
        "system_instruction": detector.DETECTOR_PROMPT,
        "input": [
            {"type": "audio", "data": "QUJD", "mime_type": "audio/wav"},
            {"type": "text", "text": "CHUNK 1/2"},
        ],
        "response_format": detector.CHUNK_SCHEMA,
        "generation_config": {"thinking_level": "low"},
        "store": False,
    }
