"""Gemini Interactions API scam detector for a single audio chunk.

The response JSON schema is shared with the Node server (shared/chunk_schema.json) and every model
response is validated with Pydantic before it can influence a verdict.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import re
import time
from typing import Any, Literal

from dotenv import load_dotenv
from google import genai
from pydantic import BaseModel, Field, ValidationError

from app.config import (
    DEFAULT_MODEL,
    DEFAULT_THINKING_LEVEL,
    ROOT_DIR,
    SHARED_DIR,
    api_key_from_env,
)

load_dotenv()
logger = logging.getLogger(__name__)

PROMPT_PATH = ROOT_DIR / "prompts" / "detector_system.md"
DETECTOR_PROMPT = PROMPT_PATH.read_text(encoding="utf-8")
CHUNK_SCHEMA: dict[str, Any] = json.loads(
    (SHARED_DIR / "chunk_schema.json").read_text(encoding="utf-8")
)

REQUEST_TIMEOUT_S = 15.0
MAX_ATTEMPTS = 2
RETRY_DELAY_S = 0.5
RATE_LIMITED_RETRY_DELAY_S = 2.0

Speaker = Literal["CALLER", "RECEIVER", "UNKNOWN"]
RedFlagType = Literal[
    "AUTHORITY_CLAIM",
    "URGENCY",
    "THREAT",
    "OTP_OR_CREDENTIALS",
    "MONEY_REQUEST",
    "REMOTE_ACCESS_OR_LINK",
    "SECRECY",
    "HANDOFF_TO_OFFICIAL",
]
ScamType = Literal["DIGITAL_ARREST", "FAKE_KYC", "FAKE_COURIER", "OTHER_FRAUD", "NONE"]
ModelVerdict = Literal["SAFE", "SUSPICIOUS", "SCAM"]


class TranscriptTurn(BaseModel):
    speaker: Speaker
    text: str


class RedFlagItem(BaseModel):
    type: RedFlagType
    quote: str
    why: str


class GenuineSignalItem(BaseModel):
    quote: str
    why: str


class ChunkAnalysis(BaseModel):
    """Structured output for one chunk; field order puts evidence before the verdict."""

    transcript: list[TranscriptTurn]
    new_red_flags: list[RedFlagItem]
    new_genuine_signals: list[GenuineSignalItem]
    scam_type: ScamType
    risk_score: int = Field(ge=0, le=100)
    verdict: ModelVerdict
    warning_gu: str
    warning_hi: str
    warning_en: str


def validate_chunk_payload(raw: dict[str, Any]) -> dict[str, Any]:
    """Validates model JSON against ChunkAnalysis; raises pydantic.ValidationError."""
    return ChunkAnalysis.model_validate(raw).model_dump()


def strip_code_fence(text: str) -> str:
    """Removes a ```json fence some models wrap around structured output."""
    cleaned = text.strip()
    if not cleaned.startswith("```"):
        return cleaned
    lines = cleaned.splitlines()
    body = lines[1:-1] if lines[-1].startswith("```") else lines[1:]
    return "\n".join(body).strip()


def normalize_thinking_level(model: str, level: str) -> str:
    """Gemini 3.8 Flash rejects the "minimal" thinking level."""
    return "low" if "3.8-flash" in model and level == "minimal" else level


def _field(obj: Any, name: str) -> Any:
    return obj.get(name) if isinstance(obj, dict) else getattr(obj, name, None)


def extract_interaction_text(interaction: Any) -> str:
    """Reads output_text from an SDK Interaction (or REST dict), else the first text part of the
    last model_output step, else the last text output."""
    if text := _field(interaction, "output_text"):
        return str(text)
    for step in reversed(_field(interaction, "steps") or []):
        if _field(step, "type") != "model_output":
            continue
        for part in _field(step, "content") or []:
            if _field(part, "type") == "text" and _field(part, "text"):
                return str(_field(part, "text"))
    for output in reversed(_field(interaction, "outputs") or []):
        if _field(output, "type") == "text" and _field(output, "text"):
            return str(_field(output, "text"))
    raise ValueError("Empty output_text from Gemini Interaction")


def _call_interactions_api(
    wav_b64: str, context_block: str, model: str, thinking_level: str, api_key: str
) -> str:
    client = genai.Client(api_key=api_key, http_options={"timeout": int(REQUEST_TIMEOUT_S * 1000)})
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
    return extract_interaction_text(interaction)


def _is_rate_limited(error: Exception) -> bool:
    return bool(re.search(r"\b429\b|RESOURCE_EXHAUSTED", str(error)))


def describe_failure(error: Exception) -> str:
    """Maps any failure to a short message that is safe to show in the UI."""
    text = f"{type(error).__name__}: {error}"
    if re.search(r"timeout|timed out", text, re.IGNORECASE):
        return "Gemini request timed out"
    if _is_rate_limited(error):
        return "Gemini rate limit reached"
    if isinstance(error, (json.JSONDecodeError, ValidationError)):
        return "Gemini returned an invalid response"
    return "Gemini request failed"


def analyze_chunk(
    wav_bytes: bytes,
    context_block: str,
    model: str | None = None,
    thinking_level: str | None = None,
) -> dict[str, Any]:
    """Analyzes one audio chunk: 15 s timeout, one retry (longer back-off on 429).

    Never invents a verdict: on failure returns status="unavailable". Unlike the Node server,
    the evaluator never switches models, so model comparisons stay honest.
    """
    resolved_model = model or os.getenv("MODEL") or DEFAULT_MODEL
    resolved_thinking = normalize_thinking_level(
        resolved_model, thinking_level or os.getenv("THINKING_LEVEL") or DEFAULT_THINKING_LEVEL
    )
    api_key = api_key_from_env()
    if api_key is None:
        return {
            "status": "unavailable",
            "error": "GEMINI_API_KEY is not configured",
            "latency_ms": 0,
            "model": resolved_model,
        }

    wav_b64 = base64.b64encode(wav_bytes).decode("ascii")
    started = time.perf_counter()
    last_error: Exception = RuntimeError("No attempts made")
    for attempt in range(MAX_ATTEMPTS):
        try:
            output_text = _call_interactions_api(
                wav_b64, context_block, resolved_model, resolved_thinking, api_key
            )
            validated = validate_chunk_payload(json.loads(strip_code_fence(output_text)))
            return {
                "status": "ok",
                "latency_ms": round((time.perf_counter() - started) * 1000),
                "model": resolved_model,
                **validated,
            }
        except Exception as exc:  # any upstream failure becomes "unavailable", never a guess
            last_error = exc
            logger.warning("%s attempt %d failed: %s", resolved_model, attempt + 1, exc)
            if attempt < MAX_ATTEMPTS - 1:
                time.sleep(RATE_LIMITED_RETRY_DELAY_S if _is_rate_limited(exc) else RETRY_DELAY_S)

    return {
        "status": "unavailable",
        "error": describe_failure(last_error),
        "latency_ms": round((time.perf_counter() - started) * 1000),
        "model": resolved_model,
    }
