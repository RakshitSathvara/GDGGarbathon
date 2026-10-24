"""FastAPI server for Saavdhan. Implements the same HTTP contract as the Node server (server/).

`app` at module level is the ASGI entrypoint for `uvicorn app.main:app` and serverless hosts.
"""

from __future__ import annotations

import base64
import binascii
import copy
import logging
import time
import uuid
from collections.abc import Callable
from typing import Any, Literal

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app.chunker import slice_wav_bytes
from app.config import MAX_UPLOAD_BYTES, Settings, load_settings
from app.detector import analyze_chunk
from app.replay import replay_chunk
from app.rules import apply_session_rules, build_context_block, create_empty_session
from app.security import BodySizeLimitMiddleware, RateLimiter, SecurityHeadersMiddleware, rate_limit
from app.sessions import SessionStore
from app.storage import AUDIO_FILE_RE, CallStore, UploadError

logger = logging.getLogger("saavdhan")

UUID_PATTERN = r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
MAX_UPLOAD_BASE64_CHARS = -(-MAX_UPLOAD_BYTES // 3) * 4
JSON_BODY_LIMIT = 16 * 1024
UPLOAD_BODY_LIMIT = 16 * 1024 * 1024  # 10 MB of audio is ~13.4 MB once base64-encoded

Analyzer = Callable[[bytes, str], dict[str, Any]]


class CreateSessionRequest(BaseModel):
    call_id: str = Field(min_length=1, max_length=128)


class AnalyzeChunkRequest(BaseModel):
    session_id: str = Field(pattern=UUID_PATTERN)
    chunk_index: int = Field(ge=0, le=10_000)
    replay: bool | None = None


class UploadWavRequest(BaseModel):
    filename: str = Field(min_length=1, max_length=255)
    data_base64: str = Field(min_length=1, max_length=MAX_UPLOAD_BASE64_CHARS)
    title: str | None = Field(default=None, max_length=120)
    expected: Literal["SCAM", "SAFE"] | None = "SCAM"


def _gemini_analyzer(wav_bytes: bytes, context_block: str) -> dict[str, Any]:
    return analyze_chunk(wav_bytes=wav_bytes, context_block=context_block)


def create_app(
    settings: Settings | None = None,
    analyzer: Analyzer = _gemini_analyzer,
    store: CallStore | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> FastAPI:
    settings = settings or load_settings()
    store = store or CallStore(settings)
    sessions: SessionStore[dict[str, Any]] = SessionStore(
        settings.session_ttl_s, settings.max_sessions
    )
    read_limit = rate_limit(RateLimiter(settings.read_limit.limit, settings.read_limit.window_s))
    session_limit = rate_limit(
        RateLimiter(settings.session_limit.limit, settings.session_limit.window_s)
    )
    analyze_limit = rate_limit(
        RateLimiter(settings.analyze_limit.limit, settings.analyze_limit.window_s)
    )
    upload_limit = rate_limit(
        RateLimiter(settings.upload_limit.limit, settings.upload_limit.window_s)
    )

    # Interactive API docs are disabled: they would need third-party scripts blocked by the CSP.
    app = FastAPI(title="Saavdhan API", docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(
        BodySizeLimitMiddleware,
        default_limit=JSON_BODY_LIMIT,
        path_limits={"/api/upload": UPLOAD_BODY_LIMIT},
    )
    app.add_middleware(SecurityHeadersMiddleware, frame_ancestors=settings.frame_ancestors)

    @app.exception_handler(RequestValidationError)
    async def validation_error(_request: Request, exc: RequestValidationError) -> JSONResponse:
        errors = exc.errors()
        first = errors[0] if errors else {}
        if first.get("type") == "json_invalid":
            return JSONResponse(status_code=400, content={"detail": "Malformed request."})
        field = ".".join(str(part) for part in first.get("loc", ()) if part != "body")
        prefix = f"{field}: " if field else ""
        detail = f"Invalid request — {prefix}{first.get('msg', 'malformed body')}"
        return JSONResponse(status_code=400, content={"detail": detail})

    def live_result(call: dict[str, Any], state: dict[str, Any], chunk: dict[str, Any]) -> dict:
        wav_path = store.resolve_wav_path(call["file"])
        if not wav_path.exists():
            raise HTTPException(status_code=404, detail=f"Audio file missing: {call['file']}")
        wav_bytes = slice_wav_bytes(wav_path, chunk["start_s"], chunk["end_s"])
        context_block = build_context_block(
            chunk_num=chunk["index"] + 1,
            total_chunks=len(call["chunks"]),
            start_s=chunk["start_s"],
            end_s=chunk["end_s"],
            session=state,
        )
        return analyzer(wav_bytes, context_block)

    def replay_result(call: dict[str, Any], chunk: dict[str, Any]) -> dict[str, Any]:
        cache_name = f"cache/{call['id']}.json"
        try:
            cache = store.read_replay_cache(call["id"])
        except (OSError, ValueError) as exc:
            raise HTTPException(500, f"Replay cache {cache_name} is unreadable.") from exc
        if cache is None:
            raise HTTPException(404, f"Replay cache {cache_name} not found. Run scripts/eval.py.")
        replay = replay_chunk(cache, chunk["index"], settings.max_replay_delay_s)
        if replay is None:
            raise HTTPException(status_code=404, detail="Chunk missing from replay cache")
        result, delay_s = replay
        sleep(delay_s)
        return result

    @app.get("/api/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/api/calls", dependencies=[Depends(read_limit)])
    def list_calls() -> dict[str, Any]:
        return {
            "calls": store.list_calls(),
            "demo_replay": settings.demo_replay,
            "model": settings.model,
        }

    @app.post("/api/upload", dependencies=[Depends(upload_limit)])
    def upload_wav(req: UploadWavRequest) -> dict[str, Any]:
        try:
            audio = base64.b64decode(req.data_base64, validate=True)
        except (binascii.Error, ValueError):
            raise HTTPException(400, "Invalid base64 audio payload.") from None
        try:
            entry = store.store_upload(req.filename, audio, req.title, req.expected)
        except UploadError as exc:
            raise HTTPException(exc.status_code, exc.detail) from exc
        return {"call": store.describe(entry), "calls": store.list_calls()}

    @app.post("/api/session", dependencies=[Depends(session_limit)])
    def create_session(req: CreateSessionRequest) -> dict[str, Any]:
        call_id = req.call_id.strip()
        entry = store.find_entry(call_id)
        if entry is None:
            raise HTTPException(status_code=404, detail=f"Unknown call_id: {call_id}")
        call = store.describe(entry)
        session_id = str(uuid.uuid4())
        sessions.set(
            session_id, {"state": create_empty_session(call["id"], session_id), "call": call}
        )
        return {"session_id": session_id, "call": call}

    @app.post("/api/analyze", dependencies=[Depends(analyze_limit)])
    def analyze(req: AnalyzeChunkRequest) -> dict[str, Any]:
        """Plain def so FastAPI runs the blocking Gemini call in its threadpool."""
        stored = sessions.get(req.session_id)
        lock = sessions.lock(req.session_id)
        if stored is None or lock is None:
            raise HTTPException(status_code=404, detail="Session not found")
        call, state = stored["call"], stored["state"]
        if req.chunk_index >= len(call["chunks"]):
            raise HTTPException(status_code=400, detail=f"Invalid chunk_index {req.chunk_index}")
        chunk = call["chunks"][req.chunk_index]

        # Serialized per session: the context block for chunk N must include chunks 0..N-1.
        with lock:
            record = next((c for c in state["chunks"] if c["chunk_index"] == chunk["index"]), None)
            if record is None:
                use_replay = settings.demo_replay if req.replay is None else req.replay
                result = (
                    replay_result(call, chunk) if use_replay else live_result(call, state, chunk)
                )
                record = apply_session_rules(
                    session=state,
                    chunk_index=chunk["index"],
                    start_s=chunk["start_s"],
                    end_s=chunk["end_s"],
                    chunk_result=result,
                )
                record["mode"] = "REPLAY" if use_replay else "LIVE"
            return copy.deepcopy({"chunk": record, "session": state})

    # Only top-level call recordings are served; raw uploads and the manifest stay private.
    @app.get("/calls/{file_name}")
    def serve_call_audio(file_name: str) -> FileResponse:
        wav_path = store.resolve_wav_path(file_name)
        if AUDIO_FILE_RE.fullmatch(file_name) is None or not wav_path.exists():
            raise HTTPException(status_code=404, detail="Call audio not found")
        return FileResponse(wav_path, media_type="audio/wav")

    if settings.static_dir.is_dir():
        app.mount("/static", StaticFiles(directory=settings.static_dir), name="static")

    @app.get("/", include_in_schema=False)
    def serve_index() -> FileResponse:
        return FileResponse(settings.static_dir / "index.html")

    return app


app = create_app()
