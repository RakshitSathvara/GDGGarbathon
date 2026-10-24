from __future__ import annotations

import io
import wave
from pathlib import Path
from typing import Any

import pytest

from app import chunker
from app.chunker import (
    WavHeader,
    compute_boundaries,
    compute_chunks,
    get_chunk_sec,
    read_wav_header,
    slice_wav_bytes,
)

from .conftest import REPO_ROOT, load_fixture, make_wav

FIXTURE = load_fixture("chunk_boundaries.json")
HEADER_BYTES = 44


@pytest.mark.parametrize("case", FIXTURE["rms_cases"], ids=lambda case: case["name"])
def test_boundaries_match_shared_fixture(case: dict[str, Any]) -> None:
    rms = [case["fill"]] * case["frames"]
    for index, value in case["dips"].items():
        rms[int(index)] = value
    boundaries = compute_boundaries(rms, case["duration"], case["target_sec"])
    assert [list(boundary) for boundary in boundaries] == case["expected"]


@pytest.mark.parametrize("call", FIXTURE["demo_calls"], ids=lambda call: call["file"])
def test_demo_calls_match_golden_boundaries(call: dict[str, Any]) -> None:
    boundaries, duration = compute_chunks(REPO_ROOT / "calls" / call["file"], call["target_sec"])
    assert duration == call["duration"]
    assert [list(boundary) for boundary in boundaries] == call["boundaries"]


def test_empty_audio_has_no_chunks() -> None:
    assert compute_boundaries([], 0.0, 6.0) == []


def test_cut_lands_in_the_pause_between_phrases(tmp_path: Path) -> None:
    path = tmp_path / "speech.wav"
    path.write_bytes(make_wav([(5.5, 6000), (0.4, 0), (5.5, 6000)]))
    boundaries, _ = compute_chunks(path, 6)
    assert 5.5 <= boundaries[0][1] <= 5.9


def test_default_target_comes_from_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("CHUNK_SEC", raising=False)
    path = tmp_path / "short.wav"
    path.write_bytes(make_wav([(4.0, 1000)]))
    assert compute_chunks(path) == ([(0.0, 4.0)], 4.0)


def test_get_chunk_sec_parses_and_clamps(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CHUNK_SEC", "8")
    assert get_chunk_sec() == 8.0
    monkeypatch.setenv("CHUNK_SEC", "abc")
    assert get_chunk_sec() == 6.0
    monkeypatch.setenv("CHUNK_SEC", "1")
    assert get_chunk_sec() == 3.0


def test_stereo_is_averaged_like_mono() -> None:
    mono = make_wav([(0.3, 4000)])[HEADER_BYTES:]
    stereo = make_wav([(0.3, 4000)], channels=2)[HEADER_BYTES:]
    stereo_rms = chunker._compute_frame_rms(stereo, 16_000, 2, 2)
    assert stereo_rms == pytest.approx(chunker._compute_frame_rms(mono, 16_000, 2, 1))


def test_stdlib_fallback_matches_numpy(monkeypatch: pytest.MonkeyPatch) -> None:
    pcm = make_wav([(0.4, 5000), (0.2, 0)], channels=2)[HEADER_BYTES:]
    with_numpy = chunker._compute_frame_rms(pcm, 16_000, 2, 2)
    monkeypatch.setattr(chunker, "np", None)
    assert chunker._compute_frame_rms(pcm, 16_000, 2, 2) == pytest.approx(with_numpy, rel=1e-4)


def test_audio_shorter_than_a_frame_is_silent(monkeypatch: pytest.MonkeyPatch) -> None:
    pcm = make_wav([(0.005, 4000)])[HEADER_BYTES:]
    assert chunker._compute_frame_rms(pcm, 16_000, 2, 1) == [0.0]
    monkeypatch.setattr(chunker, "np", None)
    assert chunker._compute_frame_rms(pcm, 16_000, 2, 1) == [0.0]


def test_only_16_bit_audio_can_be_chunked() -> None:
    with pytest.raises(ValueError, match="16-bit"):
        chunker._compute_frame_rms(b"\x80" * 400, 16_000, 1, 1)


def test_read_wav_header() -> None:
    header = read_wav_header(make_wav([(0.1, 100)]))
    assert header == WavHeader(audio_format=1, channels=1, sample_rate=16_000, bits_per_sample=16)
    assert header.is_pcm16
    assert read_wav_header(make_wav([(0.1, 100)], extra_chunk=(b"LIST", b"odd"))) is not None
    eight_bit = read_wav_header(make_wav([(0.1, 100)], bits_per_sample=8))
    assert eight_bit is not None
    assert not eight_bit.is_pcm16
    assert read_wav_header(b"ID3\x03 definitely not audio") is None
    assert read_wav_header(make_wav([(0.1, 0)])[:36]) is None


def test_slice_wav_bytes(tmp_path: Path) -> None:
    path = tmp_path / "tone.wav"
    path.write_bytes(make_wav([(2.0, 3000)]))

    def frames(start: float, end: float) -> int:
        with wave.open(io.BytesIO(slice_wav_bytes(path, start, end))) as wf:
            assert wf.getframerate() == 16_000
            return wf.getnframes()

    assert frames(0.5, 1.5) == 16_000
    assert frames(1.5, 99) == 8_000
    assert frames(1.5, 1.0) == 0
