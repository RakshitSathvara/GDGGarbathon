"""Deterministic session rules applied on top of every Gemini chunk verdict.

Thresholds, floors and fallback texts come from shared/detection_policy.json, which the Node
backend (server/rules.ts) loads too; tests/fixtures/session_rules_cases.json keeps both in lockstep.
"""

from __future__ import annotations

import json
import math
from typing import Any

from app.config import SHARED_DIR

POLICY: dict[str, Any] = json.loads(
    (SHARED_DIR / "detection_policy.json").read_text(encoding="utf-8")
)
HARD_RED_FLAG_TYPES = frozenset(POLICY["hard_red_flags"])
TRIO_RED_FLAG_TYPES = frozenset(POLICY["trio_red_flags"])
FALLBACK_WARNINGS: dict[str, dict[str, str]] = POLICY["fallback_warnings"]
RISK_FLOORS: dict[str, int] = POLICY["risk_floors"]
VERDICT_THRESHOLDS: dict[str, int] = POLICY["verdict_thresholds"]

LANGUAGES = ("gu", "hi", "en")
VERDICT_RANK = {"SAFE": 0, "SUSPICIOUS": 1, "SCAM": 2}


def verdict_from_risk(risk: int) -> str:
    if risk < VERDICT_THRESHOLDS["SUSPICIOUS"]:
        return "SAFE"
    if risk < VERDICT_THRESHOLDS["SCAM"]:
        return "SUSPICIOUS"
    return "SCAM"


def format_mm_ss_tenths(sec: float) -> str:
    """18.2 -> "00:18.2"."""
    minutes = int(sec // 60)
    return f"{minutes:02d}:{sec - minutes * 60:04.1f}"


def format_mm_ss(sec: float) -> str:
    """12.5 -> "00:13" (round half up, matching JavaScript's Math.round)."""
    total = math.floor(sec + 0.5)
    return f"{total // 60:02d}:{total % 60:02d}"


def build_context_block(
    chunk_num: int,
    total_chunks: int,
    start_s: float,
    end_s: float,
    session: dict[str, Any],
) -> str:
    """Text context sent with each audio chunk so the model can reason across the whole call:

    CHUNK 4/14 | 00:18.2–00:24.6
    CALL SO FAR:
    CALLER: …
    RED FLAGS SO FAR: THREAT "…"; AUTHORITY_CLAIM "…"   (or: none)
    GENUINE SIGNALS SO FAR: "…"   (or: none)
    CURRENT: risk 55, SUSPICIOUS
    """
    header = (
        f"CHUNK {chunk_num}/{total_chunks} | "
        f"{format_mm_ss_tenths(start_s)}–{format_mm_ss_tenths(end_s)}"
    )
    turns = session.get("transcript", [])
    call_so_far = (
        "\n".join(f"{turn['speaker']}: {turn['text']}" for turn in turns)
        if turns
        else "(call just started)"
    )
    flags = session.get("red_flags", [])
    flags_str = "; ".join(f'{f["type"]} "{f["quote"]}"' for f in flags) if flags else "none"
    signals = session.get("genuine_signals", [])
    signals_str = "; ".join(f'"{s["quote"]}"' for s in signals) if signals else "none"
    return "\n".join(
        [
            header,
            "CALL SO FAR:",
            call_so_far,
            f"RED FLAGS SO FAR: {flags_str}",
            f"GENUINE SIGNALS SO FAR: {signals_str}",
            f"CURRENT: risk {session.get('risk', 0)}, {session.get('verdict', 'SAFE')}",
        ]
    )


def create_empty_session(call_id: str, session_id: str) -> dict[str, Any]:
    return {
        "session_id": session_id,
        "call_id": call_id,
        "transcript": [],
        "red_flags": [],
        "genuine_signals": [],
        "scam_type": "NONE",
        "risk": 0,
        "verdict": "SAFE",
        "ever_scam": False,
        "first_scam_at": None,
        "warning_gu": "",
        "warning_hi": "",
        "warning_en": "",
        "chunks": [],
    }


def fix_gujarati_text(text: str) -> str:
    """Repairs common script mix-ups in the Gujarati banner word "સાવધાન!"."""
    for wrong, right in POLICY["gujarati_text_fixes"]:
        text = text.replace(wrong, right)
    return text


def compute_final_risk(session: dict[str, Any], model_risk: int, new_flags: list[dict]) -> int:
    """Floors that make the verdict safer than the model alone:

    1. a new hard red flag (OTP, money, remote access, secrecy, hand-off) -> risk >= 75
    2. authority + threat + urgency heard anywhere in the call            -> risk >= 70
    3. once SCAM, the call never drops below SCAM again                   -> risk >= 70
    """
    risk = model_risk
    if any(flag["type"] in HARD_RED_FLAG_TYPES for flag in new_flags):
        risk = max(risk, RISK_FLOORS["hard_red_flag"])
    if TRIO_RED_FLAG_TYPES.issubset({flag["type"] for flag in session["red_flags"]}):
        risk = max(risk, RISK_FLOORS["authority_threat_urgency"])
    if session.get("ever_scam"):
        risk = max(risk, RISK_FLOORS["sticky_scam"])
    return risk


def _record_evidence(
    session: dict[str, Any], span: dict[str, Any], result: dict[str, Any]
) -> tuple[list[dict], list[dict], list[dict]]:
    time_mm_ss = format_mm_ss(span["end_s"])
    turns = [
        {"speaker": turn["speaker"], "text": turn["text"], **span}
        for turn in result.get("transcript", [])
    ]
    session["transcript"].extend(turns)

    flags = [
        {
            "type": flag["type"],
            "quote": flag["quote"],
            "why": flag["why"],
            **span,
            "time_mm_ss": time_mm_ss,
        }
        for flag in result.get("new_red_flags", [])
    ]
    known = {(flag["type"], flag["quote"]) for flag in session["red_flags"]}
    for flag in flags:
        key = (flag["type"], flag["quote"])
        if key not in known:
            session["red_flags"].append(flag)
            known.add(key)

    signals = [
        {"quote": signal["quote"], "why": signal["why"], **span, "time_mm_ss": time_mm_ss}
        for signal in result.get("new_genuine_signals", [])
    ]
    session["genuine_signals"].extend(signals)
    return turns, flags, signals


def _resolve_warnings(
    session: dict[str, Any],
    verdict: str,
    rule_raised_verdict: bool,
    candidate: dict[str, str],
    cited_quote: str | None,
) -> dict[str, str]:
    """SCAM always carries a warning; SUSPICIOUS falls back only when nothing has been said yet
    (or a rule raised it); every SCAM warning names at least one red-flag quote from the call."""
    resolved = dict(candidate)
    for lang in LANGUAGES:
        if resolved[lang]:
            continue
        if verdict == "SCAM":
            resolved[lang] = FALLBACK_WARNINGS["SCAM"][lang]
        elif verdict == "SUSPICIOUS" and (rule_raised_verdict or not session[f"warning_{lang}"]):
            resolved[lang] = FALLBACK_WARNINGS["SUSPICIOUS"][lang]

    if verdict == "SCAM" and cited_quote is not None:
        quotes = [flag["quote"] for flag in session["red_flags"] if flag.get("quote")]
        for lang in LANGUAGES:
            if quotes and not any(quote in resolved[lang] for quote in quotes):
                resolved[lang] = f'{resolved[lang]} ("{cited_quote}")'
    return resolved


def _record_unavailable(
    session: dict[str, Any], span: dict[str, Any], result: dict[str, Any]
) -> dict[str, Any]:
    record = {
        **span,
        "status": "unavailable",
        "error": result.get("error") or "Analysis unavailable",
        "latency_ms": result.get("latency_ms") or 0,
        "verdict": "unavailable",
        "risk_score": session["risk"],
        "transcript": [],
        "new_red_flags": [],
        "new_genuine_signals": [],
        "warning_gu": session.get("warning_gu", ""),
        "warning_hi": session.get("warning_hi", ""),
        "warning_en": session.get("warning_en", ""),
    }
    session["chunks"].append(record)
    return record


def apply_session_rules(
    session: dict[str, Any],
    chunk_index: int,
    start_s: float,
    end_s: float,
    chunk_result: dict[str, Any],
) -> dict[str, Any]:
    """Folds one chunk result into the session and returns the processed chunk record.

    A failed chunk never invents a verdict: it is recorded as "unavailable" and the session
    is left unchanged.
    """
    span = {"chunk_index": chunk_index, "start_s": start_s, "end_s": end_s}
    if chunk_result.get("status") != "ok":
        return _record_unavailable(session, span, chunk_result)

    turns, flags, signals = _record_evidence(session, span, chunk_result)
    model_risk = int(chunk_result.get("risk_score", 0))
    final_risk = compute_final_risk(session, model_risk, chunk_result.get("new_red_flags", []))
    final_verdict = verdict_from_risk(final_risk)

    if final_verdict == "SCAM":
        session["ever_scam"] = True
        if session.get("first_scam_at") is None:
            session["first_scam_at"] = round(end_s, 2)
    if chunk_result.get("scam_type", "NONE") != "NONE":
        session["scam_type"] = chunk_result["scam_type"]

    rule_raised = VERDICT_RANK[final_verdict] > VERDICT_RANK[verdict_from_risk(model_risk)]
    latest_flag = flags[-1] if flags else (session["red_flags"] or [None])[-1]
    warnings = _resolve_warnings(
        session,
        final_verdict,
        rule_raised,
        {
            "gu": fix_gujarati_text((chunk_result.get("warning_gu") or "").strip()),
            "hi": (chunk_result.get("warning_hi") or "").strip(),
            "en": (chunk_result.get("warning_en") or "").strip(),
        },
        latest_flag["quote"] if latest_flag else None,
    )

    session["risk"] = final_risk
    session["verdict"] = final_verdict
    for lang in LANGUAGES:
        if warnings[lang]:
            session[f"warning_{lang}"] = warnings[lang]

    record = {
        **span,
        "status": "ok",
        "latency_ms": chunk_result.get("latency_ms", 0),
        "model": chunk_result.get("model", ""),
        "transcript": turns,
        "new_red_flags": flags,
        "new_genuine_signals": signals,
        "scam_type": session["scam_type"],
        "model_risk_score": model_risk,
        "risk_score": final_risk,
        "verdict": final_verdict,
        **{f"warning_{lang}": warnings[lang] or session[f"warning_{lang}"] for lang in LANGUAGES},
    }
    session["chunks"].append(record)
    return record
