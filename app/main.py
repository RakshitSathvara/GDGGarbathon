"""FastAPI server for Saavdhan."""
from __future__ import annotations

import base64
import json
import os
import re
import subprocess
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
RAW_CALLS_DIR = CALLS_DIR / "raw"
TMP_CALLS_DIR = Path("/tmp/saavdhan_calls")
TMP_MANIFEST_PATH = TMP_CALLS_DIR / "manifest.json"
CACHE_DIR = ROOT_DIR / "cache"
STATIC_DIR = ROOT_DIR / "static"
MANIFEST_PATH = CALLS_DIR / "manifest.json"
MAX_WAV_UPLOAD_BYTES = 10 * 1024 * 1024  # 10 MB

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


class UploadWavRequest(BaseModel):
    filename: str
    data_base64: str
    title: Optional[str] = None
    expected: Optional[str] = "SCAM"


def resolve_wav_path(file_name: str) -> Path:
    primary = CALLS_DIR / file_name
    if primary.exists():
        return primary
    fallback = TMP_CALLS_DIR / file_name
    if fallback.exists():
        return fallback
    return primary


def load_manifest() -> List[Dict[str, Any]]:
    if TMP_MANIFEST_PATH.exists():
        try:
            return json.loads(TMP_MANIFEST_PATH.read_text(encoding="utf-8"))
        except Exception:
            pass
    if not MANIFEST_PATH.exists():
        return []
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def save_manifest(manifest: List[Dict[str, Any]]) -> None:
    payload = json.dumps(manifest, ensure_ascii=False, indent=2)
    try:
        MANIFEST_PATH.write_text(payload, encoding="utf-8")
    except OSError:
        TMP_CALLS_DIR.mkdir(parents=True, exist_ok=True)
        TMP_MANIFEST_PATH.write_text(payload, encoding="utf-8")


def get_call_metadata(entry: Dict[str, Any]) -> Dict[str, Any]:
    file_name = entry["file"]
    call_id = Path(file_name).stem
    wav_path = resolve_wav_path(file_name)
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


@app.post("/api/upload")
def upload_wav(req: UploadWavRequest) -> Dict[str, Any]:
    filename = (req.filename or "").strip()
    if not filename.lower().endswith(".wav"):
        raise HTTPException(status_code=400, detail="Only .wav files are allowed.")

    try:
        raw_bytes = base64.b64decode(req.data_base64, validate=True)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid base64 audio payload.")

    if len(raw_bytes) <= 44:
        raise HTTPException(status_code=400, detail="The .wav file is empty or corrupted.")
    if len(raw_bytes) > MAX_WAV_UPLOAD_BYTES:
        size_mb = len(raw_bytes) / (1024 * 1024)
        raise HTTPException(
            status_code=400,
            detail=f"File size ({size_mb:.2f} MB) exceeds the 10 MB maximum limit.",
        )

    if raw_bytes[:4] != b"RIFF" or raw_bytes[8:12] != b"WAVE":
        raise HTTPException(status_code=400, detail="Invalid WAV file header (expected RIFF/WAVE).")

    stem = re.sub(r"[^a-z0-9_-]+", "_", Path(filename).stem.lower()).strip("_")[:48] or "uploaded_call"
    out_filename = f"{stem}.wav"

    # Write to CALLS_DIR if writable (local macOS/Linux), otherwise fallback to /tmp/saavdhan_calls (Vercel serverless)
    try:
        RAW_CALLS_DIR.mkdir(parents=True, exist_ok=True)
        CALLS_DIR.mkdir(parents=True, exist_ok=True)
        raw_path = RAW_CALLS_DIR / out_filename
        dest_path = CALLS_DIR / out_filename
        raw_path.write_bytes(raw_bytes)
    except OSError:
        TMP_CALLS_DIR.mkdir(parents=True, exist_ok=True)
        raw_path = TMP_CALLS_DIR / f"raw_{out_filename}"
        dest_path = TMP_CALLS_DIR / out_filename
        raw_path.write_bytes(raw_bytes)

    # Convert to 16 kHz mono 16-bit PCM WAV via ffmpeg (matching scripts/prep.sh)
    try:
        subprocess.run(
            [
                "ffmpeg",
                "-y",
                "-hide_banner",
                "-loglevel",
                "error",
                "-i",
                str(raw_path),
                "-ar",
                "16000",
                "-ac",
                "1",
                "-c:a",
                "pcm_s16le",
                str(dest_path),
            ],
            check=True,
        )
    except Exception:
        dest_path.write_bytes(raw_bytes)

    CALL_META_CACHE.pop(stem, None)
    manifest = load_manifest()
    expected = req.expected if req.expected in ("SCAM", "SAFE") else "SCAM"
    title = (req.title or "").strip() or f"Uploaded — {Path(filename).stem}"

    existing_entry = next((m for m in manifest if m["file"] == out_filename), None)
    if existing_entry:
        existing_entry["title"] = title
        existing_entry["expected"] = expected
        entry = existing_entry
    else:
        entry = {"file": out_filename, "title": title, "expected": expected}
        manifest.append(entry)

    save_manifest(manifest)
    call_meta = get_call_metadata(entry)
    calls = [get_call_metadata(item) for item in manifest]
    return {"call": call_meta, "calls": calls}


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
        wav_path = resolve_wav_path(call_meta["file"])
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


@app.get("/calls/{file_name}")
def serve_call_audio(file_name: str) -> FileResponse:
    safe_name = Path(file_name).name
    wav_path = resolve_wav_path(safe_name)
    if not wav_path.exists():
        raise HTTPException(status_code=404, detail=f"Call audio not found: {safe_name}")
    return FileResponse(str(wav_path), media_type="audio/wav")


try:
    CALLS_DIR.mkdir(parents=True, exist_ok=True)
    STATIC_DIR.mkdir(parents=True, exist_ok=True)
except OSError:
    pass

if CALLS_DIR.exists():
    app.mount("/calls", StaticFiles(directory=str(CALLS_DIR)), name="calls")
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/")
def serve_index() -> FileResponse:
    return FileResponse(str(STATIC_DIR / "index.html"))
