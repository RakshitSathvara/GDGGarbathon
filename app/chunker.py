"""Silence-aware WAV audio chunker for Saavdhan."""
from __future__ import annotations

import array
import io
import math
import os
import wave
from pathlib import Path
from typing import List, Tuple

try:
    import numpy as np  # type: ignore
except ImportError:
    np = None  # Fallback to stdlib array if numpy is unavailable


DEFAULT_CHUNK_SEC = 6.0
MIN_CHUNK_SEC = 3.0
SEARCH_WINDOW_SEC = 1.0
FRAME_MS = 20


def get_chunk_sec() -> float:
    try:
        val = float(os.getenv("CHUNK_SEC", str(DEFAULT_CHUNK_SEC)))
        return max(MIN_CHUNK_SEC, val)
    except ValueError:
        return DEFAULT_CHUNK_SEC


def _compute_frame_rms(pcm_bytes: bytes, sample_rate: int, sampwidth: int, nchannels: int) -> List[float]:
    """Compute RMS for each 20 ms frame across the audio stream."""
    frame_samples = max(1, int(sample_rate * FRAME_MS / 1000))
    samples_per_frame = frame_samples * nchannels

    if np is not None and sampwidth == 2:
        samples = np.frombuffer(pcm_bytes, dtype=np.int16).astype(np.float32)
        if nchannels > 1:
            samples = samples.reshape(-1, nchannels).mean(axis=1)
        n_frames = len(samples) // frame_samples
        if n_frames == 0:
            return [0.0]
        trimmed = samples[: n_frames * frame_samples].reshape(n_frames, frame_samples)
        rms = np.sqrt(np.mean(trimmed * trimmed, axis=1))
        return rms.tolist()

    # Standard library fallback for 16-bit PCM
    arr = array.array("h")
    arr.frombytes(pcm_bytes[: (len(pcm_bytes) // 2) * 2])
    total_samples = len(arr)
    n_frames = total_samples // samples_per_frame
    if n_frames == 0:
        return [0.0]
    rms_list: List[float] = []
    for i in range(n_frames):
        start = i * samples_per_frame
        end = start + samples_per_frame
        chunk = arr[start:end]
        mean_sq = sum(float(s) * float(s) for s in chunk) / len(chunk)
        rms_list.append(math.sqrt(mean_sq))
    return rms_list


def compute_chunks(wav_path: str | Path, target_sec: float | None = None) -> Tuple[List[Tuple[float, float]], float]:
    """
    Compute [(start_s, end_s)] chunk boundaries for a WAV file.
    Places each cut at the lowest-RMS 20 ms frame within +-1.0 s of target_sec.
    Minimum chunk is 3.0 s; merges a short tail (<3.0 s) into the previous chunk.
    Returns (boundaries, total_duration_sec).
    """
    if target_sec is None:
        target_sec = get_chunk_sec()
    target_sec = max(MIN_CHUNK_SEC, float(target_sec))

    with wave.open(str(wav_path), "rb") as wf:
        sample_rate = wf.getframerate()
        n_frames_total = wf.getnframes()
        sampwidth = wf.getsampwidth()
        nchannels = wf.getnchannels()
        pcm_bytes = wf.readframes(n_frames_total)

    duration_s = n_frames_total / float(sample_rate) if sample_rate > 0 else 0.0
    if duration_s <= target_sec + MIN_CHUNK_SEC:
        if duration_s <= target_sec:
            return ([(0.0, round(duration_s, 3))] if duration_s > 0 else []), round(duration_s, 3)

    frame_rms = _compute_frame_rms(pcm_bytes, sample_rate, sampwidth, nchannels)
    frame_sec = FRAME_MS / 1000.0
    total_rms_frames = len(frame_rms)

    boundaries: List[Tuple[float, float]] = []
    cursor_s = 0.0

    while cursor_s < duration_s:
        remaining = duration_s - cursor_s
        if remaining <= target_sec:
            boundaries.append((round(cursor_s, 3), round(duration_s, 3)))
            break

        ideal_cut_s = cursor_s + target_sec
        # Search window [ideal_cut_s - 1.0, ideal_cut_s + 1.0], respecting min chunk size
        win_start_s = max(cursor_s + MIN_CHUNK_SEC, ideal_cut_s - SEARCH_WINDOW_SEC)
        win_end_s = min(duration_s, ideal_cut_s + SEARCH_WINDOW_SEC)

        start_idx = max(0, int(round(win_start_s / frame_sec)))
        end_idx = min(total_rms_frames - 1, int(round(win_end_s / frame_sec)))

        if start_idx <= end_idx and total_rms_frames > 0:
            best_idx = min(range(start_idx, end_idx + 1), key=lambda idx: frame_rms[idx])
            cut_s = round(best_idx * frame_sec, 3)
        else:
            cut_s = round(ideal_cut_s, 3)

        # Ensure progress and minimum chunk length
        if cut_s - cursor_s < MIN_CHUNK_SEC:
            cut_s = round(min(duration_s, cursor_s + target_sec), 3)

        boundaries.append((round(cursor_s, 3), cut_s))
        cursor_s = cut_s

    # Merge short tail (< 3.0 s) into the previous chunk
    if len(boundaries) >= 2:
        last_start, last_end = boundaries[-1]
        if (last_end - last_start) < MIN_CHUNK_SEC:
            prev_start, _ = boundaries[-2]
            boundaries[-2] = (prev_start, last_end)
            boundaries.pop()

    return boundaries, round(duration_s, 3)


def slice_wav_bytes(wav_path: str | Path, start_s: float, end_s: float) -> bytes:
    """Slice [start_s, end_s] from wav_path and return in-memory WAV bytes using wave."""
    with wave.open(str(wav_path), "rb") as wf:
        params = wf.getparams()
        sample_rate = wf.getframerate()
        total_frames = wf.getnframes()

        start_frame = max(0, min(total_frames, int(round(start_s * sample_rate))))
        end_frame = max(start_frame, min(total_frames, int(round(end_s * sample_rate))))

        wf.setpos(start_frame)
        raw_frames = wf.readframes(end_frame - start_frame)

    buf = io.BytesIO()
    with wave.open(buf, "wb") as out_wf:
        out_wf.setnchannels(params.nchannels)
        out_wf.setsampwidth(params.sampwidth)
        out_wf.setframerate(params.framerate)
        out_wf.writeframes(raw_frames)
    return buf.getvalue()
