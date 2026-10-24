from __future__ import annotations

from app.replay import replay_chunk

from .conftest import analysis

TURN = {"speaker": "CALLER", "text": "raw"}


def test_prefers_raw_model_output_over_processed_fields() -> None:
    cache = {
        "model": "cached-model",
        "chunks": [
            {
                **analysis(risk_score=75, verdict="SCAM"),
                "model_risk_score": 40,
                "latency_ms": 420,
                "transcript": [{"speaker": "CALLER", "text": "processed", "chunk_index": 0}],
                "raw_transcript": [TURN],
                "raw_new_red_flags": [{"type": "OTP_OR_CREDENTIALS", "quote": "OTP", "why": "x"}],
            }
        ],
    }
    replay = replay_chunk(cache, 0, 1.2)
    assert replay is not None
    result, delay_s = replay
    assert delay_s == 0.42
    assert result["status"] == "ok"
    assert result["model"] == "cached-model"
    assert result["risk_score"] == 40
    assert result["transcript"] == [TURN]
    assert len(result["new_red_flags"]) == 1


def test_clamps_the_simulated_latency() -> None:
    fast = replay_chunk({"chunks": [{**analysis(), "latency_ms": 5}]}, 0, 1.2)
    slow = replay_chunk({"chunks": [{**analysis(), "latency_ms": 9_000}]}, 0, 1.2)
    unknown = replay_chunk({"chunks": [analysis()]}, 0, 1.2)
    assert fast is not None
    assert slow is not None
    assert unknown is not None
    assert fast[1] == 0.08
    assert slow[1] == 1.2
    assert unknown[1] == 0.35
    assert unknown[0]["latency_ms"] == 350
    assert unknown[0]["model"] == "replay"


def test_recorded_failures_stay_unavailable() -> None:
    replay = replay_chunk({"chunks": [{"status": "unavailable", "error": "timeout"}]}, 0, 1.2)
    assert replay is not None
    assert replay[0] == {
        "status": "unavailable",
        "error": "timeout",
        "latency_ms": 350,
        "model": "replay",
    }
    anonymous = replay_chunk({"chunks": [{"status": "unavailable"}]}, 0, 1.2)
    assert anonymous is not None
    assert anonymous[0]["error"] == "Analysis unavailable"


def test_malformed_entries_are_not_trusted() -> None:
    replay = replay_chunk({"chunks": [{**analysis(), "verdict": "MAYBE"}]}, 0, 1.2)
    assert replay is not None
    assert replay[0]["status"] == "unavailable"


def test_missing_chunks_return_none() -> None:
    assert replay_chunk({"chunks": []}, 0, 1.2) is None
    assert replay_chunk({"chunks": ["bad"]}, 0, 1.2) is None
    assert replay_chunk({"chunks": [analysis()]}, 5, 1.2) is None
    assert replay_chunk("not a cache", 0, 1.2) is None
