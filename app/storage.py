"""Call catalog and storage: manifest, call metadata, replay caches and uploaded recordings.

Falls back to a temp directory when calls/ is read-only (e.g. Vercel serverless functions).
Uploads are namespaced with "upload_" so they can never overwrite the curated demo calls.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import uuid
import wave
from collections.abc import Callable
from pathlib import Path
from typing import Any

from app.chunker import WavHeader, compute_chunks, read_wav_header
from app.config import Settings

logger = logging.getLogger(__name__)

UPLOAD_PREFIX = "upload_"
AUDIO_FILE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\.wav")
MAX_STEM_LENGTH = 48
MAX_TITLE_LENGTH = 120
EXPECTED_VALUES = ("SCAM", "SAFE")

AudioConverter = Callable[[Path, Path], None]


class UploadError(Exception):
    """A rejected upload whose message is safe to return to the client."""

    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def sanitize_call_stem(filename: str) -> str:
    """ "../My Call (1).wav" -> "my_call_1"; never empty, never contains path separators."""
    base_name = re.split(r"[\\/]", filename.strip())[-1]
    stem = re.sub(r"\.wav$", "", base_name, flags=re.IGNORECASE).lower()
    stem = re.sub(r"[^a-z0-9_-]+", "_", stem).strip("_")[:MAX_STEM_LENGTH]
    return stem or "uploaded_call"


def _display_name(filename: str) -> str:
    base_name = re.split(r"[\\/]", filename)[-1]
    return re.sub(r"\.wav$", "", base_name, flags=re.IGNORECASE)[:80]


def _is_valid_entry(entry: Any) -> bool:
    return (
        isinstance(entry, dict)
        and isinstance(entry.get("file"), str)
        and AUDIO_FILE_RE.fullmatch(entry["file"]) is not None
        and isinstance(entry.get("title"), str)
        and entry.get("expected") in EXPECTED_VALUES
    )


def _atomic_write(path: Path, data: bytes) -> None:
    """Writes via a temp file + rename so readers never see a partially written file."""
    temp_path = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    temp_path.write_bytes(data)
    os.replace(temp_path, path)


def ffmpeg_converter(timeout_s: float) -> AudioConverter:
    """Converts any input ffmpeg understands to 16 kHz mono 16-bit PCM (same as prep.sh)."""

    def convert(source: Path, destination: Path) -> None:
        ffmpeg = shutil.which("ffmpeg")
        if ffmpeg is None:
            raise FileNotFoundError("ffmpeg is not installed")
        args = [ffmpeg, "-y", "-hide_banner", "-loglevel", "error", "-i", str(source)]
        args += ["-ar", "16000", "-ac", "1", "-c:a", "pcm_s16le", str(destination)]
        # Fixed argument list and server-generated paths: no shell, no user-controlled flags.
        subprocess.run(args, check=True, capture_output=True, timeout=timeout_s)  # noqa: S603

    return convert


class CallStore:
    def __init__(self, settings: Settings, converter: AudioConverter | None = None) -> None:
        self.settings = settings
        self._convert = converter or ffmpeg_converter(settings.ffmpeg_timeout_s)
        self._chunk_cache: dict[str, tuple[float, float, list[dict[str, Any]]]] = {}

    # Manifest -----------------------------------------------------------------------------
    def load_manifest(self) -> list[dict[str, Any]]:
        for path in (self.settings.tmp_manifest_path, self.settings.manifest_path):
            if not path.exists():
                continue
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                logger.warning("Ignoring unreadable manifest %s: %s", path, exc)
                continue
            if not isinstance(data, list):
                continue
            entries = [entry for entry in data if _is_valid_entry(entry)]
            if len(entries) != len(data):
                logger.warning("Skipped %d invalid manifest entries", len(data) - len(entries))
            return entries
        return []

    def save_manifest(self, manifest: list[dict[str, Any]]) -> None:
        payload = (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
        try:
            _atomic_write(self.settings.manifest_path, payload)
        except OSError:
            self.settings.tmp_calls_dir.mkdir(parents=True, exist_ok=True)
            _atomic_write(self.settings.tmp_manifest_path, payload)

    def find_entry(self, call_id: str) -> dict[str, Any] | None:
        return next(
            (
                entry
                for entry in self.load_manifest()
                if Path(entry["file"]).stem == call_id or entry["file"] == call_id
            ),
            None,
        )

    # Calls --------------------------------------------------------------------------------
    def resolve_wav_path(self, file_name: str) -> Path:
        name = Path(file_name).name
        primary = self.settings.calls_dir / name
        if primary.exists():
            return primary
        fallback = self.settings.tmp_calls_dir / name
        return fallback if fallback.exists() else primary

    def describe(self, entry: dict[str, Any]) -> dict[str, Any]:
        file_name = entry["file"]
        call_id = Path(file_name).stem
        duration, chunks = self._chunk_plan(file_name)
        return {
            "id": call_id,
            "file": file_name,
            "title": entry["title"],
            "expected": entry["expected"],
            "first_demand_at": entry.get("first_demand_at"),
            "duration": duration,
            "chunks": chunks,
            "has_cache": (self.settings.cache_dir / f"{call_id}.json").exists(),
        }

    def list_calls(self) -> list[dict[str, Any]]:
        return [self.describe(entry) for entry in self.load_manifest()]

    def read_replay_cache(self, call_id: str) -> Any:
        path = self.settings.cache_dir / f"{Path(call_id).name}.json"
        if not path.exists():
            return None
        return json.loads(path.read_text(encoding="utf-8"))

    def _chunk_plan(self, file_name: str) -> tuple[float, list[dict[str, Any]]]:
        wav_path = self.resolve_wav_path(file_name)
        mtime = wav_path.stat().st_mtime if wav_path.exists() else 0.0
        cached = self._chunk_cache.get(file_name)
        if cached and cached[0] == mtime:
            return cached[1], cached[2]

        duration, chunks = 0.0, []
        if wav_path.exists():
            try:
                boundaries, duration = compute_chunks(wav_path, self.settings.chunk_sec)
                chunks = [
                    {"index": idx, "start_s": start, "end_s": end}
                    for idx, (start, end) in enumerate(boundaries)
                ]
            except (wave.Error, EOFError, ValueError) as exc:
                logger.warning("Cannot chunk %s: %s", file_name, exc)
        self._chunk_cache[file_name] = (mtime, duration, chunks)
        return duration, chunks

    # Uploads ------------------------------------------------------------------------------
    def store_upload(
        self, filename: str, audio: bytes, title: str | None, expected: str | None
    ) -> dict[str, Any]:
        header = self._validate_upload(filename, audio)
        file_name = f"{UPLOAD_PREFIX}{sanitize_call_stem(filename)}.wav"
        manifest = self.load_manifest()
        existing = next((entry for entry in manifest if entry["file"] == file_name), None)
        uploaded = sum(1 for entry in manifest if entry.get("uploaded"))
        if existing is None and uploaded >= self.settings.max_uploaded_calls:
            raise UploadError(
                409,
                f"Upload limit reached ({self.settings.max_uploaded_calls} recordings). "
                "Remove older uploads first.",
            )

        self._write_playable_audio(audio, header, file_name)
        self._chunk_cache.pop(file_name, None)

        entry = {
            "file": file_name,
            "title": ((title or "").strip() or f"Uploaded — {_display_name(filename)}")[
                :MAX_TITLE_LENGTH
            ],
            "expected": expected if expected in EXPECTED_VALUES else "SCAM",
            "uploaded": True,
        }
        if existing is not None:
            existing.update(entry)
            entry = existing
        else:
            manifest.append(entry)
        self.save_manifest(manifest)
        return entry

    def _validate_upload(self, filename: str, audio: bytes) -> WavHeader:
        if not filename.strip():
            raise UploadError(400, "Please select a .wav audio file.")
        if not filename.strip().lower().endswith(".wav"):
            raise UploadError(400, "Only .wav files are allowed.")
        if len(audio) <= 44:
            raise UploadError(400, "The .wav file is empty or corrupted.")
        if len(audio) > self.settings.max_upload_bytes:
            size_mb = len(audio) / (1024 * 1024)
            raise UploadError(400, f"File size ({size_mb:.2f} MB) exceeds the 10 MB maximum limit.")
        if audio[:4] != b"RIFF" or audio[8:12] != b"WAVE":
            raise UploadError(400, "Invalid WAV file header (expected RIFF/WAVE).")
        header = read_wav_header(audio)
        if header is None:
            raise UploadError(400, "The .wav file is empty or corrupted.")
        return header

    def _write_playable_audio(self, audio: bytes, header: WavHeader, file_name: str) -> None:
        try:
            out_dir = self.settings.calls_dir
            self.settings.raw_calls_dir.mkdir(parents=True, exist_ok=True)
            out_dir.mkdir(parents=True, exist_ok=True)
            raw_path = self.settings.raw_calls_dir / file_name
            raw_path.write_bytes(audio)
        except OSError:
            out_dir = self.settings.tmp_calls_dir
            out_dir.mkdir(parents=True, exist_ok=True)
            raw_path = out_dir / f"raw_{file_name}"
            raw_path.write_bytes(audio)

        temp_path = out_dir / f".{uuid.uuid4().hex}.converting.wav"
        try:
            self._convert(raw_path, temp_path)
        except (OSError, subprocess.SubprocessError) as exc:
            temp_path.unlink(missing_ok=True)
            if not header.is_pcm16:
                raise UploadError(
                    422,
                    "Could not convert this recording. "
                    "Install ffmpeg or upload a 16-bit PCM .wav file.",
                ) from exc
            logger.warning("ffmpeg unavailable (%s); storing the PCM upload as-is", exc)
            temp_path.write_bytes(audio)
        os.replace(temp_path, out_dir / file_name)
