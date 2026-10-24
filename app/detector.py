"""Gemini Interactions API scam detector and session state rules for Saavdhan."""
from __future__ import annotations

import base64
import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

try:
    from dotenv import load_dotenv  # type: ignore

    load_dotenv()
except ImportError:
    pass

try:
    from pydantic import BaseModel, Field  # type: ignore
except ImportError:
    BaseModel = None  # type: ignore
    Field = None  # type: ignore

try:
    from google import genai  # type: ignore
except ImportError:
    genai = None  # type: ignore


ROOT_DIR = Path(__file__).resolve().parent.parent
PROMPT_PATH = ROOT_DIR / "prompts" / "detector_system.md"
DETECTOR_PROMPT = PROMPT_PATH.read_text(encoding="utf-8")

SPEAKER_VALUES = ("CALLER", "RECEIVER", "UNKNOWN")
RED_FLAG_TYPES = (
    "AUTHORITY_CLAIM",
    "URGENCY",
    "THREAT",
    "OTP_OR_CREDENTIALS",
    "MONEY_REQUEST",
    "REMOTE_ACCESS_OR_LINK",
    "SECRECY",
    "HANDOFF_TO_OFFICIAL",
)
HARD_RED_FLAG_TYPES = {
    "OTP_OR_CREDENTIALS",
    "MONEY_REQUEST",
    "REMOTE_ACCESS_OR_LINK",
    "SECRECY",
    "HANDOFF_TO_OFFICIAL",
}
TRIO_RED_FLAG_TYPES = {"AUTHORITY_CLAIM", "THREAT", "URGENCY"}

SCAM_TYPES = ("DIGITAL_ARREST", "FAKE_KYC", "FAKE_COURIER", "OTHER_FRAUD", "NONE")
VERDICT_VALUES = ("SAFE", "SUSPICIOUS", "SCAM")

SAFE_TEXT_GU = "અત્યાર સુધી કોઈ જોખમ સંભળાયું નથી"
SAFE_TEXT_HI = "अभी तक कोई ख़तरा सुनाई नहीं दिया"

SCAM_FALLBACK_GU = (
    "સાવધાન! આ કોલ ફ્રોડ હોઈ શકે છે. OTP કે પૈસા ન આપો. ફોન કાપી નાખો અને 1930 પર ફોન કરો."
)
SCAM_FALLBACK_HI = (
    "सावधान! यह कॉल फ्रॉड हो सकती है। OTP या पैसे मत दीजिए। फ़ोन काट दीजिए और 1930 पर कॉल कीजिए।"
)
SCAM_FALLBACK_EN = (
    "Warning! This call may be a fraud. Do not share OTP or money. Hang up and call 1930."
)

SUSPICIOUS_FALLBACK_GU = "સાવધાન! આ કોલ શંકાસ્પદ લાગે છે. કોઈ પણ માહિતી આપતા પહેલા ચકાસણી કરો."
SUSPICIOUS_FALLBACK_HI = "सावधान! यह कॉल संदिग्ध लग रही है। कोई भी जानकारी देने से पहले जाँच करें।"
SUSPICIOUS_FALLBACK_EN = "Caution! This call sounds suspicious. Verify before sharing any details."

# Plain JSON-schema dict, nested objects inlined, no $ref, strict field order (evidence before verdict)
CHUNK_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "transcript": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "speaker": {"type": "string", "enum": list(SPEAKER_VALUES)},
                    "text": {"type": "string"},
                },
                "required": ["speaker", "text"],
            },
        },
        "new_red_flags": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "type": {"type": "string", "enum": list(RED_FLAG_TYPES)},
                    "quote": {"type": "string"},
                    "why": {"type": "string"},
                },
                "required": ["type", "quote", "why"],
            },
        },
        "new_genuine_signals": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "quote": {"type": "string"},
                    "why": {"type": "string"},
                },
                "required": ["quote", "why"],
            },
        },
        "scam_type": {
            "type": "string",
            "enum": list(SCAM_TYPES),
        },
        "risk_score": {
            "type": "integer",
            "minimum": 0,
            "maximum": 100,
        },
        "verdict": {
            "type": "string",
            "enum": list(VERDICT_VALUES),
        },
        "warning_gu": {"type": "string"},
        "warning_hi": {"type": "string"},
        "warning_en": {"type": "string"},
    },
    "required": [
        "transcript",
        "new_red_flags",
        "new_genuine_signals",
        "scam_type",
        "risk_score",
        "verdict",
        "warning_gu",
        "warning_hi",
        "warning_en",
    ],
}


if BaseModel is not None:

    class TranscriptTurn(BaseModel):
        speaker: Literal["CALLER", "RECEIVER", "UNKNOWN"]
        text: str

    class RedFlagItem(BaseModel):
        type: Literal[
            "AUTHORITY_CLAIM",
            "URGENCY",
            "THREAT",
            "OTP_OR_CREDENTIALS",
            "MONEY_REQUEST",
            "REMOTE_ACCESS_OR_LINK",
            "SECRECY",
            "HANDOFF_TO_OFFICIAL",
        ]
        quote: str
        why: str

    class GenuineSignalItem(BaseModel):
        quote: str
        why: str

    class ChunkAnalysis(BaseModel):
        transcript: List[TranscriptTurn]
        new_red_flags: List[RedFlagItem]
        new_genuine_signals: List[GenuineSignalItem]
        scam_type: Literal["DIGITAL_ARREST", "FAKE_KYC", "FAKE_COURIER", "OTHER_FRAUD", "NONE"]
        risk_score: int = Field(ge=0, le=100)
        verdict: Literal["SAFE", "SUSPICIOUS", "SCAM"]
        warning_gu: str
        warning_hi: str
        warning_en: str


def validate_chunk_payload(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Validate model JSON response with Pydantic (or strict schema validator if Pydantic unavailable)."""
    if BaseModel is not None:
        validated = ChunkAnalysis.model_validate(raw)
        return validated.model_dump()

    # Strict manual validation matching ChunkAnalysis
    for req_key in CHUNK_SCHEMA["required"]:
        if req_key not in raw:
            raise ValueError(f"Missing required field: {req_key}")

    transcript = []
    for item in raw["transcript"]:
        spk = item.get("speaker", "UNKNOWN")
        if spk not in SPEAKER_VALUES:
            raise ValueError(f"Invalid speaker: {spk}")
        transcript.append({"speaker": spk, "text": str(item["text"])})

    new_red_flags = []
    for item in raw["new_red_flags"]:
        ftype = item.get("type")
        if ftype not in RED_FLAG_TYPES:
            raise ValueError(f"Invalid red flag type: {ftype}")
        new_red_flags.append(
            {"type": ftype, "quote": str(item["quote"]), "why": str(item["why"])}
        )

    new_genuine_signals = []
    for item in raw["new_genuine_signals"]:
        new_genuine_signals.append(
            {"quote": str(item["quote"]), "why": str(item["why"])}
        )

    scam_type = raw["scam_type"]
    if scam_type not in SCAM_TYPES:
        raise ValueError(f"Invalid scam_type: {scam_type}")

    risk_score = int(raw["risk_score"])
    if not (0 <= risk_score <= 100):
        raise ValueError(f"risk_score out of range: {risk_score}")

    verdict = raw["verdict"]
    if verdict not in VERDICT_VALUES:
        raise ValueError(f"Invalid verdict: {verdict}")

    return {
        "transcript": transcript,
        "new_red_flags": new_red_flags,
        "new_genuine_signals": new_genuine_signals,
        "scam_type": scam_type,
        "risk_score": risk_score,
        "verdict": verdict,
        "warning_gu": str(raw["warning_gu"]),
        "warning_hi": str(raw["warning_hi"]),
        "warning_en": str(raw["warning_en"]),
    }


def format_mm_ss_tenths(sec: float) -> str:
    m = int(sec // 60)
    s = sec - m * 60
    return f"{m:02d}:{s:04.1f}"


def format_mm_ss(sec: float) -> str:
    total = int(round(sec))
    m = total // 60
    s = total % 60
    return f"{m:02d}:{s:02d}"


def build_context_block(
    chunk_num: int,
    total_chunks: int,
    start_s: float,
    end_s: float,
    session: Dict[str, Any],
) -> str:
    """
    Build the exact context block required:
      CHUNK 4/14 | 00:18.2–00:24.6
      CALL SO FAR:
      CALLER: …
      RECEIVER: …
      RED FLAGS SO FAR: THREAT "…"; AUTHORITY_CLAIM "…"   (or: none)
      GENUINE SIGNALS SO FAR: "…"   (or: none)
      CURRENT: risk 55, SUSPICIOUS
    """
    header = (
        f"CHUNK {chunk_num}/{total_chunks} | "
        f"{format_mm_ss_tenths(start_s)}–{format_mm_ss_tenths(end_s)}"
    )
    transcript_lines = []
    for turn in session.get("transcript", []):
        transcript_lines.append(f"{turn['speaker']}: {turn['text']}")
    call_so_far = "\n".join(transcript_lines) if transcript_lines else "(call just started)"

    flags = session.get("red_flags", [])
    if flags:
        flags_str = "; ".join(f'{f["type"]} "{f["quote"]}"' for f in flags)
    else:
        flags_str = "none"

    signals = session.get("genuine_signals", [])
    if signals:
        signals_str = "; ".join(f'"{s["quote"]}"' for s in signals)
    else:
        signals_str = "none"

    current_risk = session.get("risk", 0)
    current_verdict = session.get("verdict", "SAFE")

    return (
        f"{header}\n"
        f"CALL SO FAR:\n"
        f"{call_so_far}\n"
        f"RED FLAGS SO FAR: {flags_str}\n"
        f"GENUINE SIGNALS SO FAR: {signals_str}\n"
        f"CURRENT: risk {current_risk}, {current_verdict}"
    )


def _extract_interaction_text(interaction: Any) -> str:
    """Extract output_text from a google-genai Interaction object or REST response dict."""
    if hasattr(interaction, "output_text") and interaction.output_text:
        return str(interaction.output_text)
    if isinstance(interaction, dict):
        if interaction.get("output_text"):
            return str(interaction["output_text"])
        for step in reversed(interaction.get("steps", [])):
            if step.get("type") == "model_output":
                for c in step.get("content", []):
                    if c.get("type") == "text" and c.get("text"):
                        return str(c["text"])
        for out in reversed(interaction.get("outputs", [])):
            if out.get("type") == "text" and out.get("text"):
                return str(out["text"])
    if hasattr(interaction, "steps") and interaction.steps:
        for step in reversed(interaction.steps):
            if getattr(step, "type", None) == "model_output":
                for c in getattr(step, "content", []) or []:
                    if getattr(c, "type", None) == "text" and getattr(c, "text", None):
                        return str(c.text)
    raise ValueError("Empty output_text from Gemini Interaction")


def _call_interactions_api(
    wav_b64: str,
    context_block: str,
    model: str,
    thinking_level: str,
    timeout_s: float = 15.0,
) -> str:
    """Call Gemini Interactions API via google-genai SDK (or REST fallback if SDK not installed)."""
    api_key = os.getenv("GEMINI_API_KEY", "")
    if not api_key or api_key == "MY_GEMINI_API_KEY":
        raise RuntimeError("GEMINI_API_KEY is not configured in environment")

    if genai is not None:
        client = genai.Client(
            api_key=api_key,
            http_options={"timeout": int(timeout_s * 1000)},
        )
        interaction = client.interactions.create(
            model=model,
            system_instruction=DETECTOR_PROMPT,
            input=[
                {"type": "audio", "data": wav_b64, "mime_type": "audio/wav"},
                {"type": "text", "text": context_block},
            ],
            response_format=CHUNK_SCHEMA,
            generation_config={"thinking_level": thinking_level},
            store=False,
        )
        return _extract_interaction_text(interaction)

    # Direct REST call to the identical v1beta/interactions endpoint if SDK is not installed in Python
    url = "https://generativelanguage.googleapis.com/v1beta/interactions"
    payload = {
        "model": model,
        "system_instruction": DETECTOR_PROMPT,
        "input": [
            {"type": "audio", "data": wav_b64, "mime_type": "audio/wav"},
            {"type": "text", "text": context_block},
        ],
        "response_format": CHUNK_SCHEMA,
        "generation_config": {"thinking_level": thinking_level},
        "store": False,
    }
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "x-goog-api-key": api_key,
            "User-Agent": "aistudio-build",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout_s) as resp:
        body = json.loads(resp.read().decode("utf-8"))
        return _extract_interaction_text(body)


def analyze_chunk(
    wav_bytes: bytes,
    context_block: str,
    model: Optional[str] = None,
    thinking_level: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Analyze a single audio chunk with Gemini Interactions API.
    10s timeout, one retry, backoff on 429.
    On failure return status="unavailable", never a made-up verdict.
    Records latency_ms per request.
    """
    resolved_model = model or os.getenv("MODEL", "gemini-3.8-flash")
    resolved_thinking = thinking_level or os.getenv("THINKING_LEVEL", "low")
    # 3.8 Flash rejects "minimal"
    if "3.8-flash" in resolved_model and resolved_thinking == "minimal":
        resolved_thinking = "low"

    wav_b64 = base64.b64encode(wav_bytes).decode("ascii")
    t0 = time.perf_counter()
    last_error = ""

    for attempt in range(2):
        try:
            output_text = _call_interactions_api(
                wav_b64=wav_b64,
                context_block=context_block,
                model=resolved_model,
                thinking_level=resolved_thinking,
                timeout_s=15.0,
            )
            cleaned = output_text.strip()
            if cleaned.startswith("```"):
                lines = cleaned.splitlines()
                cleaned = "\n".join(lines[1:-1] if lines[-1].startswith("```") else lines[1:]).strip()
            raw_json = json.loads(cleaned)
            validated = validate_chunk_payload(raw_json)
            latency_ms = int(round((time.perf_counter() - t0) * 1000))
            return {
                "status": "ok",
                "latency_ms": latency_ms,
                "model": resolved_model,
                **validated,
            }
        except Exception as exc:
            last_error = str(exc)
            if attempt == 0:
                if "429" in last_error or "RESOURCE_EXHAUSTED" in last_error:
                    time.sleep(2.0)
                else:
                    time.sleep(0.5)

    latency_ms = int(round((time.perf_counter() - t0) * 1000))
    return {
        "status": "unavailable",
        "error": last_error,
        "latency_ms": latency_ms,
        "model": resolved_model,
    }


def create_empty_session(call_id: str, session_id: str) -> Dict[str, Any]:
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


def verdict_from_risk(risk: int) -> str:
    if risk < 30:
        return "SAFE"
    if risk < 70:
        return "SUSPICIOUS"
    return "SCAM"


def apply_session_rules(
    session: Dict[str, Any],
    chunk_index: int,
    start_s: float,
    end_s: float,
    chunk_result: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Apply deterministic server rules on top of the model's chunk result and update session state:
    - new OTP_OR_CREDENTIALS, MONEY_REQUEST, REMOTE_ACCESS_OR_LINK, SECRECY or HANDOFF_TO_OFFICIAL -> risk >= 75
    - accumulated AUTHORITY_CLAIM + THREAT + URGENCY -> risk >= 70
    - once SCAM, risk never drops below 70; SUSPICIOUS may fall back to SAFE
    - displayed verdict comes from final risk: <30 SAFE, 30-69 SUSPICIOUS, >=70 SCAM
    - if a server rule raises the verdict and the warnings are empty, use the fallback texts
    """
    if chunk_result.get("status") != "ok":
        unavailable_record = {
            "chunk_index": chunk_index,
            "start_s": start_s,
            "end_s": end_s,
            "status": "unavailable",
            "error": chunk_result.get("error", "Analysis unavailable"),
            "latency_ms": chunk_result.get("latency_ms", 0),
            "verdict": "unavailable",
            "risk_score": session["risk"],
            "transcript": [],
            "new_red_flags": [],
            "new_genuine_signals": [],
            "warning_gu": session.get("warning_gu", ""),
            "warning_hi": session.get("warning_hi", ""),
            "warning_en": session.get("warning_en", ""),
        }
        session["chunks"].append(unavailable_record)
        return unavailable_record

    # Append transcript turns with chunk timing
    chunk_turns = []
    for turn in chunk_result.get("transcript", []):
        entry = {
            "speaker": turn["speaker"],
            "text": turn["text"],
            "chunk_index": chunk_index,
            "start_s": start_s,
            "end_s": end_s,
        }
        session["transcript"].append(entry)
        chunk_turns.append(entry)

    # Append new red flags with chunk timing and formatted mm:ss
    new_flags = chunk_result.get("new_red_flags", [])
    existing_flag_keys = {(f["type"], f["quote"]) for f in session["red_flags"]}
    added_flags = []
    for flag in new_flags:
        key = (flag["type"], flag["quote"])
        enriched = {
            "type": flag["type"],
            "quote": flag["quote"],
            "why": flag["why"],
            "chunk_index": chunk_index,
            "start_s": start_s,
            "end_s": end_s,
            "time_mm_ss": format_mm_ss(end_s),
        }
        added_flags.append(enriched)
        if key not in existing_flag_keys:
            session["red_flags"].append(enriched)
            existing_flag_keys.add(key)

    # Append new genuine signals
    new_signals = chunk_result.get("new_genuine_signals", [])
    added_signals = []
    for sig in new_signals:
        enriched_sig = {
            "quote": sig["quote"],
            "why": sig["why"],
            "chunk_index": chunk_index,
            "start_s": start_s,
            "end_s": end_s,
            "time_mm_ss": format_mm_ss(end_s),
        }
        session["genuine_signals"].append(enriched_sig)
        added_signals.append(enriched_sig)

    model_risk = int(chunk_result.get("risk_score", 0))
    model_verdict = verdict_from_risk(model_risk)
    final_risk = model_risk

    # Rule 1: new hard red flag -> risk >= 75
    if any(f["type"] in HARD_RED_FLAG_TYPES for f in new_flags):
        final_risk = max(final_risk, 75)

    # Rule 2: accumulated AUTHORITY_CLAIM + THREAT + URGENCY -> risk >= 70
    accumulated_types = {f["type"] for f in session["red_flags"]}
    if TRIO_RED_FLAG_TYPES.issubset(accumulated_types):
        final_risk = max(final_risk, 70)

    # Rule 3: once SCAM, risk never drops below 70; SUSPICIOUS may fall back to SAFE
    if session.get("ever_scam"):
        final_risk = max(final_risk, 70)

    # Rule 4: displayed verdict comes from final risk: <30 SAFE, 30-69 SUSPICIOUS, >=70 SCAM
    final_verdict = verdict_from_risk(final_risk)

    if final_verdict == "SCAM":
        session["ever_scam"] = True
        if session.get("first_scam_at") is None:
            session["first_scam_at"] = round(end_s, 2)

    if chunk_result.get("scam_type") and chunk_result["scam_type"] != "NONE":
        session["scam_type"] = chunk_result["scam_type"]

    # Rule 5: if a server rule raises the verdict and the warnings are empty, use the fallback texts
    warning_gu = (chunk_result.get("warning_gu") or "").strip().replace("सावधान!", "સાવધાન!").replace("सापवधान!", "સાવધાન!").replace("સાપવધાન!", "સાવધાન!")
    warning_hi = (chunk_result.get("warning_hi") or "").strip()
    warning_en = (chunk_result.get("warning_en") or "").strip()

    verdict_rank = {"SAFE": 0, "SUSPICIOUS": 1, "SCAM": 2}
    rule_raised_verdict = verdict_rank[final_verdict] > verdict_rank[model_verdict]

    if final_verdict == "SCAM" and (rule_raised_verdict or not warning_gu or not warning_hi):
        if not warning_gu:
            warning_gu = SCAM_FALLBACK_GU
        if not warning_hi:
            warning_hi = SCAM_FALLBACK_HI
        if not warning_en:
            warning_en = SCAM_FALLBACK_EN
    elif final_verdict == "SUSPICIOUS" and rule_raised_verdict:
        if not warning_gu:
            warning_gu = SUSPICIOUS_FALLBACK_GU
        if not warning_hi:
            warning_hi = SUSPICIOUS_FALLBACK_HI
        if not warning_en:
            warning_en = SUSPICIOUS_FALLBACK_EN

    # Ensure every SCAM warning names at least one red flag quote that appears in the transcript
    if final_verdict == "SCAM" and session["red_flags"]:
        all_quotes = [f["quote"] for f in session["red_flags"] if f.get("quote")]
        latest_flag = added_flags[-1] if added_flags else session["red_flags"][-1]
        quote_to_cite = latest_flag["quote"]
        if all_quotes and not any(q in warning_gu for q in all_quotes):
            warning_gu = f'{warning_gu} ("{quote_to_cite}")'
        if all_quotes and not any(q in warning_hi for q in all_quotes):
            warning_hi = f'{warning_hi} ("{quote_to_cite}")'
        if all_quotes and not any(q in warning_en for q in all_quotes):
            warning_en = f'{warning_en} ("{quote_to_cite}")'

    session["risk"] = final_risk
    session["verdict"] = final_verdict
    if warning_gu:
        session["warning_gu"] = warning_gu
    if warning_hi:
        session["warning_hi"] = warning_hi
    if warning_en:
        session["warning_en"] = warning_en

    processed_chunk = {
        "chunk_index": chunk_index,
        "start_s": start_s,
        "end_s": end_s,
        "status": "ok",
        "latency_ms": chunk_result.get("latency_ms", 0),
        "model": chunk_result.get("model", ""),
        "transcript": chunk_turns,
        "new_red_flags": added_flags,
        "new_genuine_signals": added_signals,
        "scam_type": session["scam_type"],
        "model_risk_score": model_risk,
        "risk_score": final_risk,
        "verdict": final_verdict,
        "warning_gu": warning_gu or session.get("warning_gu", ""),
        "warning_hi": warning_hi or session.get("warning_hi", ""),
        "warning_en": warning_en or session.get("warning_en", ""),
    }
    session["chunks"].append(processed_chunk)
    return processed_chunk
