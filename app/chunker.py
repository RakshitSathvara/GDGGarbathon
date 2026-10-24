"""Silence-aware WAV chunker for Saavdhan.

Mirrors server/wav.ts; tests/fixtures/chunk_boundaries.json pins both to identical boundaries so
replay caches recorded here line up with the Node server.
"""

from __future__ import annotations

import array
import io
import math
import struct
import sys
import wave
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from app.config import DEFAULT_CHUNK_SEC, MIN_CHUNK_SEC, chunk_sec_from_env

try:
    import numpy as np
except ImportError:  # pragma: no cover - numpy is a declared dependency
    np = None

SEARCH_WINDOW_SEC = 1.0
FRAME_MS = 20
PCM_FORMAT = 1
EXTENSIBLE_FORMAT = 0xFFFE

Boundary = tuple[float, float]

__all__ = [
    "DEFAULT_CHUNK_SEC",
    "FRAME_MS",
    "MIN_CHUNK_SEC",
    "SEARCH_WINDOW_SEC",
    "WavHeader",
    "compute_boundaries",
    "compute_chunks",
    "get_chunk_sec",
    "read_wav_header",
    "slice_wav_bytes",
]


@dataclass(frozen=True)
class WavHeader:
    audio_format: int
    channels: int
    sample_rate: int
    bits_per_sample: int

    @property
    def is_pcm16(self) -> bool:
        return self.bits_per_sample == 16 and self.audio_format in (PCM_FORMAT, EXTENSIBLE_FORMAT)


def get_chunk_sec() -> float:
    return chunk_sec_from_env()


def read_wav_header(data: bytes) -> WavHeader | None:
    """Walks the RIFF chunks; returns None unless both a fmt and a data chunk are present."""
    if len(data) < 12 or data[:4] != b"RIFF" or data[8:12] != b"WAVE":
        return None
    header: WavHeader | None = None
    offset = 12
    while offset + 8 <= len(data):
        chunk_id = data[offset : offset + 4]
        (chunk_size,) = struct.unpack_from("<I", data, offset + 4)
        body = offset + 8
        if chunk_id == b"fmt " and chunk_size >= 16 and body + 16 <= len(data):
            audio_format, channels, sample_rate = struct.unpack_from("<HHI", data, body)
            (bits,) = struct.unpack_from("<H", data, body + 14)
            header = WavHeader(audio_format, channels, sample_rate, bits)
        elif chunk_id == b"data":
            valid = header is not None and header.channels >= 1 and header.sample_rate >= 1
            return header if valid else None
        offset = body + chunk_size + (chunk_size % 2)
    return None


def _compute_frame_rms(
    pcm_bytes: bytes, sample_rate: int, sampwidth: int, nchannels: int
) -> list[float]:
    """RMS of each 20 ms frame of 16-bit PCM, with channels averaged (matches server/wav.ts)."""
    if sampwidth != 2:
        raise ValueError("Only 16-bit PCM audio can be chunked")
    frame_samples = max(1, int(sample_rate * FRAME_MS / 1000))

    if np is not None:
        samples = np.frombuffer(pcm_bytes, dtype="<i2").astype(np.float32)
        if nchannels > 1:
            samples = samples[: len(samples) // nchannels * nchannels]
            samples = samples.reshape(-1, nchannels).mean(axis=1)
        n_frames = len(samples) // frame_samples
        if n_frames == 0:
            return [0.0]
        frames = samples[: n_frames * frame_samples].reshape(n_frames, frame_samples)
        return np.sqrt(np.mean(frames * frames, axis=1)).tolist()

    samples_arr = array.array("h")
    samples_arr.frombytes(pcm_bytes[: len(pcm_bytes) // 2 * 2])
    if sys.byteorder == "big":
        samples_arr.byteswap()
    n_frames = len(samples_arr) // nchannels // frame_samples
    if n_frames == 0:
        return [0.0]
    rms: list[float] = []
    for frame in range(n_frames):
        sum_sq = 0.0
        for i in range(frame_samples):
            base = (frame * frame_samples + i) * nchannels
            sample = sum(samples_arr[base : base + nchannels]) / nchannels
            sum_sq += sample * sample
        rms.append(math.sqrt(sum_sq / frame_samples))
    return rms


def compute_boundaries(
    frame_rms: Sequence[float], duration_s: float, target_sec: float
) -> list[Boundary]:
    """Cuts at the quietest 20 ms frame within ±1 s of each target; chunks are >= 3 s and a
    short tail is merged into the previous chunk."""
    target_sec = max(MIN_CHUNK_SEC, float(target_sec))
    if duration_s <= 0:
        return []
    if duration_s <= target_sec:
        return [(0.0, round(duration_s, 3))]

    frame_sec = FRAME_MS / 1000.0
    boundaries: list[Boundary] = []
    cursor_s = 0.0
    while cursor_s < duration_s:
        if duration_s - cursor_s <= target_sec:
            boundaries.append((round(cursor_s, 3), round(duration_s, 3)))
            break

        ideal_cut_s = cursor_s + target_sec
        win_start_s = max(cursor_s + MIN_CHUNK_SEC, ideal_cut_s - SEARCH_WINDOW_SEC)
        win_end_s = min(duration_s, ideal_cut_s + SEARCH_WINDOW_SEC)
        start_idx = max(0, round(win_start_s / frame_sec))
        end_idx = min(len(frame_rms) - 1, round(win_end_s / frame_sec))

        if start_idx <= end_idx:
            quietest = min(range(start_idx, end_idx + 1), key=lambda idx: frame_rms[idx])
            cut_s = round(quietest * frame_sec, 3)
        else:
            cut_s = round(ideal_cut_s, 3)
        if cut_s - cursor_s < MIN_CHUNK_SEC:
            cut_s = round(min(duration_s, cursor_s + target_sec), 3)

        boundaries.append((round(cursor_s, 3), cut_s))
        cursor_s = cut_s

    if len(boundaries) >= 2 and boundaries[-1][1] - boundaries[-1][0] < MIN_CHUNK_SEC:
        last_end = boundaries.pop()[1]
        boundaries[-1] = (boundaries[-1][0], last_end)
    return boundaries


def compute_chunks(
    wav_path: str | Path, target_sec: float | None = None
) -> tuple[list[Boundary], float]:
    """Returns ([(start_s, end_s), ...], total_duration_s) for a 16-bit PCM WAV file."""
    target = get_chunk_sec() if target_sec is None else max(MIN_CHUNK_SEC, float(target_sec))
    with wave.open(str(wav_path), "rb") as wf:
        sample_rate = wf.getframerate()
        n_frames = wf.getnframes()
        sampwidth = wf.getsampwidth()
        nchannels = wf.getnchannels()
        pcm_bytes = wf.readframes(n_frames)

    duration_s = round(n_frames / float(sample_rate), 3) if sample_rate > 0 else 0.0
    needs_cuts = duration_s > target
    frame_rms = (
        _compute_frame_rms(pcm_bytes, sample_rate, sampwidth, nchannels) if needs_cuts else []
    )
    return compute_boundaries(frame_rms, duration_s, target), duration_s


def slice_wav_bytes(wav_path: str | Path, start_s: float, end_s: float) -> bytes:
    """Returns [start_s, end_s] of wav_path as standalone in-memory WAV bytes."""
    with wave.open(str(wav_path), "rb") as wf:
        params = wf.getparams()
        total_frames = wf.getnframes()
        start_frame = max(0, min(total_frames, round(start_s * params.framerate)))
        end_frame = max(start_frame, min(total_frames, round(end_s * params.framerate)))
        wf.setpos(start_frame)
        raw_frames = wf.readframes(end_frame - start_frame)

    buf = io.BytesIO()
    with wave.open(buf, "wb") as out:
        out.setnchannels(params.nchannels)
        out.setsampwidth(params.sampwidth)
        out.setframerate(params.framerate)
        out.writeframes(raw_frames)
    return buf.getvalue()
