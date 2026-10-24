"""FastAPI server for Saavdhan."""
from __future__ import annotations

import json
import os
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from app.chunker import compute_chunks, slice_wav_bytes
from app.detector import (
    analyze_chunk,
    apply_session_rules,
    build_context_block,
    create_empty_session,
)

ROOT_DIR = Path(__file__).resolve().parent.parent
CALLS_DIR = ROOT_DIR / "calls"
CACHE_DIR = ROOT_DIR / "cache"
STATIC_DIR = ROOT_DIR / "static"
MANIFEST_PATH = CALLS_DIR / "manifest.json"

app = FastAPI(title="Saavdhan API")

# In-memory session store and precomputed chunk metadata
SESSIONS: Dict[str, Dict[str, Any]] = {}
CALL_META_CACHE: Dict[str, Dict[str, Any]] = {}


class CreateSessionRequest(BaseModel):
    call_id: str


class AnalyzeChunkRequest(BaseModel):
    session_id: str
    chunk_index: int
    replay: Optional[bool] = None


def load_manifest() -> List[Dict[str, Any]]:
    if not MANIFEST_PATH.exists():
        return []
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def get_call_metadata(entry: Dict[str, Any]) -> Dict[str, Any]:
    file_name = entry["file"]
    call_id = Path(file_name).stem
    wav_path = CALLS_DIR / file_name
    mtime = wav_path.stat().st_mtime if wav_path.exists() else 0.0

    cached = CALL_META_CACHE.get(call_id)
    if cached and cached.get("_mtime") == mtime:
        return cached["data"]

    if wav_path.exists():
        boundaries, duration = compute_chunks(wav_path)
    else:
        boundaries, duration = [], 0.0

    cache_file = CACHE_DIR / f"{call_id}.json"
    data = {
        "id": call_id,
        "file": file_name,
        "title": entry["title"],
        "expected": entry["expected"],
        "first_demand_at": entry.get("first_demand_at"),
        "duration": duration,
        "chunks": [
            {"index": idx, "start_s": b[0], "end_s": b[1]}
            for idx, b in enumerate(boundaries)
        ],
        "has_cache": cache_file.exists(),
    }
    CALL_META_CACHE[call_id] = {"_mtime": mtime, "data": data}
    return data


@app.get("/api/calls")
def list_calls() -> Dict[str, Any]:
    manifest = load_manifest()
    calls = [get_call_metadata(item) for item in manifest]
    demo_replay = os.getenv("DEMO_REPLAY", "0") == "1"
    return {
        "calls": calls,
        "demo_replay": demo_replay,
        "model": os.getenv("MODEL", "gemini-3.8-flash"),
    }


@app.post("/api/session")
def create_session(req: CreateSessionRequest) -> Dict[str, Any]:
    manifest = load_manifest()
    matched = next(
        (
            item
            for item in manifest
            if Path(item["file"]).stem == req.call_id or item["file"] == req.call_id
        ),
        None,
    )
    if not matched:
        raise HTTPException(status_code=404, detail=f"Unknown call_id: {req.call_id}")

    call_meta = get_call_metadata(matched)
    session_id = str(uuid.uuid4())
    session = create_empty_session(call_meta["id"], session_id)
    session["call_meta"] = call_meta
    SESSIONS[session_id] = session
    return {"session_id": session_id, "call": call_meta}


@app.post("/api/analyze")
def analyze(req: AnalyzeChunkRequest) -> Dict[str, Any]:
    """Plain def so FastAPI runs synchronous Gemini calls in the threadpool."""
    session = SESSIONS.get(req.session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    call_meta = session["call_meta"]
    chunks = call_meta["chunks"]
    if req.chunk_index < 0 or req.chunk_index >= len(chunks):
        raise HTTPException(status_code=400, detail=f"Invalid chunk_index {req.chunk_index}")

    # Return already processed chunk if requested again
    for existing in session["chunks"]:
        if existing["chunk_index"] == req.chunk_index:
            return {"chunk": existing, "session": _public_session(session)}

    chunk_info = chunks[req.chunk_index]
    start_s = chunk_info["start_s"]
    end_s = chunk_info["end_s"]
    call_id = call_meta["id"]

    use_replay = req.replay if req.replay is not None else (os.getenv("DEMO_REPLAY", "0") == "1")

    if use_replay:
        cache_path = CACHE_DIR / f"{call_id}.json"
        if not cache_path.exists():
            raise HTTPException(
                status_code=404,
                detail=f"Replay cache cache/{call_id}.json not found. Run scripts/eval.py first.",
            )
        cache_data = json.loads(cache_path.read_text(encoding="utf-8"))
        cached_chunks = cache_data.get("chunks", [])
        if req.chunk_index >= len(cached_chunks):
            raise HTTPException(status_code=404, detail="Chunk missing from replay cache")

        raw_cached = cached_chunks[req.chunk_index]
        # Serve cache/ results at their recorded latency (capped to 2.5s so UI stays snappy)
        sim_delay_s = min(2.5, max(0.05, raw_cached.get("latency_ms", 400) / 1000.0))
        time.sleep(sim_delay_s)
        chunk_result = {
            "status": raw_cached.get("status", "ok"),
            "latency_ms": raw_cached.get("latency_ms", 0),
            "model": raw_cached.get("model", cache_data.get("model", "replay")),
            "transcript": raw_cached.get("raw_transcript", raw_cached.get("transcript", [])),
            "new_red_flags": raw_cached.get("raw_new_red_flags", raw_cached.get("new_red_flags", [])),
            "new_genuine_signals": raw_cached.get(
                "raw_new_genuine_signals", raw_cached.get("new_genuine_signals", [])
            ),
            "scam_type": raw_cached.get("scam_type", "NONE"),
            "risk_score": raw_cached.get("model_risk_score", raw_cached.get("risk_score", 0)),
            "verdict": raw_cached.get("verdict", "SAFE"),
            "warning_gu": raw_cached.get("warning_gu", ""),
            "warning_hi": raw_cached.get("warning_hi", ""),
            "warning_en": raw_cached.get("warning_en", ""),
        }
    else:
        wav_path = CALLS_DIR / call_meta["file"]
        if not wav_path.exists():
            raise HTTPException(status_code=404, detail=f"Audio file missing: {call_meta['file']}")
        wav_bytes = slice_wav_bytes(wav_path, start_s, end_s)
        context_block = build_context_block(
            chunk_num=req.chunk_index + 1,
            total_chunks=len(chunks),
            start_s=start_s,
            end_s=end_s,
            session=session,
        )
        chunk_result = analyze_chunk(wav_bytes=wav_bytes, context_block=context_block)

    processed = apply_session_rules(
        session=session,
        chunk_index=req.chunk_index,
        start_s=start_s,
        end_s=end_s,
        chunk_result=chunk_result,
    )
    processed["mode"] = "REPLAY" if use_replay else "LIVE"
    return {"chunk": processed, "session": _public_session(session)}


def _public_session(session: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "session_id": session["session_id"],
        "call_id": session["call_id"],
        "transcript": session["transcript"],
        "red_flags": session["red_flags"],
        "genuine_signals": session["genuine_signals"],
        "scam_type": session["scam_type"],
        "risk": session["risk"],
        "verdict": session["verdict"],
        "first_scam_at": session["first_scam_at"],
        "warning_gu": session["warning_gu"],
        "warning_hi": session["warning_hi"],
        "warning_en": session["warning_en"],
        "chunks": session["chunks"],
    }


CALLS_DIR.mkdir(parents=True, exist_ok=True)
STATIC_DIR.mkdir(parents=True, exist_ok=True)

app.mount("/calls", StaticFiles(directory=str(CALLS_DIR)), name="calls")
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/")
def serve_index() -> FileResponse:
    return FileResponse(str(STATIC_DIR / "index.html"))
