from __future__ import annotations

from typing import Any

from app.rules import (
    FALLBACK_WARNINGS,
    apply_session_rules,
    compute_final_risk,
    create_empty_session,
    fix_gujarati_text,
    format_mm_ss,
    format_mm_ss_tenths,
    verdict_from_risk,
)

from .conftest import analysis


def ok(**overrides: Any) -> dict[str, Any]:
    return {"status": "ok", "latency_ms": 300, "model": "test-model", **analysis(**overrides)}


def flag(flag_type: str, quote: str | None = None) -> dict[str, str]:
    return {"type": flag_type, "quote": quote or flag_type, "why": "test"}


def test_verdict_thresholds() -> None:
    assert [verdict_from_risk(r) for r in (0, 29, 30, 69, 70, 100)] == [
        "SAFE",
        "SAFE",
        "SUSPICIOUS",
        "SUSPICIOUS",
        "SCAM",
        "SCAM",
    ]


def test_time_formatting_rounds_half_up() -> None:
    assert format_mm_ss(12.5) == "00:13"
    assert format_mm_ss(12.49) == "00:12"
    assert format_mm_ss(75) == "01:15"
    assert format_mm_ss_tenths(5.8) == "00:05.8"
    assert format_mm_ss_tenths(68.5) == "01:08.5"


def test_risk_floors() -> None:
    fresh = create_empty_session("c", "s")
    assert compute_final_risk(fresh, 42, []) == 42
    assert compute_final_risk(fresh, 10, [flag("MONEY_REQUEST")]) == 75
    trio = create_empty_session("c", "s")
    trio["red_flags"] = [flag(t) for t in ("AUTHORITY_CLAIM", "THREAT", "URGENCY")]
    assert compute_final_risk(trio, 20, []) == 70
    sticky = {**create_empty_session("c", "s"), "ever_scam": True}
    assert compute_final_risk(sticky, 5, []) == 70
    assert compute_final_risk(sticky, 95, [flag("SECRECY")]) == 95


def test_fix_gujarati_text() -> None:
    assert fix_gujarati_text("सावधान! ફોન કાપો") == "સાવધાન! ફોન કાપો"
    assert fix_gujarati_text("सापवधान! a સાપવધાન! b") == "સાવધાન! a સાવધાન! b"


def test_records_transcript_and_flags_with_timing() -> None:
    session = create_empty_session("call", "session")
    record = apply_session_rules(
        session,
        2,
        12.0,
        18.4,
        ok(
            transcript=[{"speaker": "CALLER", "text": "CBI officer here"}],
            new_red_flags=[flag("AUTHORITY_CLAIM", "CBI officer")],
            risk_score=35,
        ),
    )
    assert record["status"] == "ok"
    assert session["transcript"][0] == {
        "speaker": "CALLER",
        "text": "CBI officer here",
        "chunk_index": 2,
        "start_s": 12.0,
        "end_s": 18.4,
    }
    assert session["red_flags"][0]["time_mm_ss"] == "00:18"
    assert session["verdict"] == "SUSPICIOUS"


def test_scam_type_survives_later_none() -> None:
    session = create_empty_session("call", "session")
    apply_session_rules(session, 0, 0, 6, ok(scam_type="FAKE_COURIER", risk_score=50))
    apply_session_rules(session, 1, 6, 12, ok(scam_type="NONE", risk_score=50))
    assert session["scam_type"] == "FAKE_COURIER"


def test_genuine_signals_are_not_deduplicated() -> None:
    session = create_empty_session("call", "session")
    signal = {"quote": "visit the branch", "why": "in person"}
    apply_session_rules(session, 0, 0, 6, ok(new_genuine_signals=[signal]))
    apply_session_rules(session, 1, 6, 12, ok(new_genuine_signals=[signal]))
    assert len(session["genuine_signals"]) == 2


def test_earlier_suspicious_warning_is_kept() -> None:
    session = create_empty_session("call", "session")
    apply_session_rules(
        session, 0, 0, 6, ok(risk_score=40, warning_gu="ગુ", warning_hi="हि", warning_en="en")
    )
    record = apply_session_rules(session, 1, 6, 12, ok(risk_score=45))
    assert record["warning_gu"] == "ગુ"
    assert record["warning_en"] != FALLBACK_WARNINGS["SUSPICIOUS"]["en"]


def test_unavailable_chunk_uses_default_error() -> None:
    session = create_empty_session("call", "session")
    record = apply_session_rules(session, 0, 0, 6, {"status": "unavailable", "error": ""})
    assert record["error"] == "Analysis unavailable"
    assert record["verdict"] == "unavailable"
    assert session["verdict"] == "SAFE"
