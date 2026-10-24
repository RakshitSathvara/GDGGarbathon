"""Replay mode: serves results recorded by scripts/eval.py (cache/<call>.json) instead of calling
Gemini, so the demo works offline. Mirrors server/replay.ts."""

from __future__ import annotations

from typing import Any

from pydantic import ValidationError

from app.detector import validate_chunk_payload

MIN_REPLAY_DELAY_MS = 80
DEFAULT_REPLAY_LATENCY_MS = 350


def _first(mapping: dict[str, Any], *keys: str, default: Any) -> Any:
    """Value of the first key that is present and not None."""
    for key in keys:
        if mapping.get(key) is not None:
            return mapping[key]
    return default


def _text(value: Any) -> str:
    return value if isinstance(value, str) else ""


def replay_chunk(
    cache: Any, chunk_index: int, max_delay_s: float
) -> tuple[dict[str, Any], float] | None:
    """Returns (detector-style result, delay in seconds), or None if the chunk is not cached."""
    if not isinstance(cache, dict) or not isinstance(cache.get("chunks"), list):
        return None
    chunks = cache["chunks"]
    if not 0 <= chunk_index < len(chunks) or not isinstance(chunks[chunk_index], dict):
        return None
    raw = chunks[chunk_index]

    latency = raw.get("latency_ms")
    recorded = latency if isinstance(latency, (int, float)) and latency > 0 else 0
    delay_ms = min(
        max_delay_s * 1000, max(MIN_REPLAY_DELAY_MS, recorded or DEFAULT_REPLAY_LATENCY_MS)
    )
    latency_ms = recorded or delay_ms
    model = _text(raw.get("model")) or _text(cache.get("model")) or "replay"

    if raw.get("status") == "unavailable":
        error = _text(raw.get("error")) or "Analysis unavailable"
        result = {"status": "unavailable", "error": error, "latency_ms": latency_ms, "model": model}
        return result, delay_ms / 1000

    candidate = {
        "transcript": _first(raw, "raw_transcript", "transcript", default=[]),
        "new_red_flags": _first(raw, "raw_new_red_flags", "new_red_flags", default=[]),
        "new_genuine_signals": _first(
            raw, "raw_new_genuine_signals", "new_genuine_signals", default=[]
        ),
        "scam_type": _first(raw, "scam_type", default="NONE"),
        "risk_score": _first(raw, "model_risk_score", "risk_score", default=0),
        "verdict": _first(raw, "verdict", default="SAFE"),
        "warning_gu": _first(raw, "warning_gu", default=""),
        "warning_hi": _first(raw, "warning_hi", default=""),
        "warning_en": _first(raw, "warning_en", default=""),
    }
    try:
        validated = validate_chunk_payload(candidate)
    except ValidationError:
        error = "Replay cache entry is invalid"
        result = {"status": "unavailable", "error": error, "latency_ms": latency_ms, "model": model}
        return result, delay_ms / 1000
    return {"status": "ok", "latency_ms": latency_ms, "model": model, **validated}, delay_ms / 1000
