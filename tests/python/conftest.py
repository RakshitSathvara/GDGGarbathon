"""Shared pytest fixtures: synthetic WAVs, an isolated temp project and a test client."""

from __future__ import annotations

import dataclasses
import json
import math
import shutil
import struct
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.config import Settings, load_settings
from app.main import create_app
from app.storage import CallStore

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures"


def load_fixture(name: str) -> Any:
    return json.loads((FIXTURES_DIR / name).read_text(encoding="utf-8"))


def make_wav(
    segments: list[tuple[float, int]],
    sample_rate: int = 16_000,
    channels: int = 1,
    bits_per_sample: int = 16,
    audio_format: int = 1,
    extra_chunk: tuple[bytes, bytes] | None = None,
) -> bytes:
    """Builds a PCM WAV from (seconds, amplitude) tone segments; amplitude 0 = silence."""
    frames: list[int] = []
    for seconds, amplitude in segments:
        start = len(frames)
        count = round(seconds * sample_rate)
        frames.extend(
            round(amplitude * math.sin(2 * math.pi * 440 * (start + i) / sample_rate))
            for i in range(count)
        )
    if bits_per_sample == 16:
        data = b"".join(struct.pack("<h", value) * channels for value in frames)
    else:
        data = b"".join(bytes([128 + round(value / 256)]) * channels for value in frames)
    block_align = channels * bits_per_sample // 8
    fmt = struct.pack(
        "<4sIHHIIHH",
        b"fmt ",
        16,
        audio_format,
        channels,
        sample_rate,
        sample_rate * block_align,
        block_align,
        bits_per_sample,
    )
    extra = b""
    if extra_chunk:
        chunk_id, body = extra_chunk
        extra = struct.pack("<4sI", chunk_id, len(body)) + body + (b"\0" if len(body) % 2 else b"")
    data_chunk = struct.pack("<4sI", b"data", len(data)) + data
    riff_size = 4 + len(fmt) + len(extra) + len(data_chunk)
    return struct.pack("<4sI4s", b"RIFF", riff_size, b"WAVE") + fmt + extra + data_chunk


def analysis(**overrides: Any) -> dict[str, Any]:
    result = {
        "transcript": [],
        "new_red_flags": [],
        "new_genuine_signals": [],
        "scam_type": "NONE",
        "risk_score": 0,
        "verdict": "SAFE",
        "warning_gu": "",
        "warning_hi": "",
        "warning_en": "",
    }
    result.update(overrides)
    return result


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    """Settings rooted in a temp copy of the project with one demo call (fake_kyc)."""
    root = tmp_path / "project"
    (root / "calls" / "raw").mkdir(parents=True)
    (root / "cache").mkdir()
    shutil.copytree(REPO_ROOT / "static", root / "static")
    shutil.copy(REPO_ROOT / "calls" / "fake_kyc.wav", root / "calls" / "fake_kyc.wav")
    manifest = json.loads((REPO_ROOT / "calls" / "manifest.json").read_text(encoding="utf-8"))
    (root / "calls" / "manifest.json").write_text(
        json.dumps([m for m in manifest if m["file"] == "fake_kyc.wav"]), encoding="utf-8"
    )
    return dataclasses.replace(
        load_settings({}, root_dir=root), tmp_calls_dir=tmp_path / "tmp_calls"
    )


@pytest.fixture
def converter_calls() -> list[tuple[Path, Path]]:
    return []


@pytest.fixture
def copy_converter(converter_calls: list[tuple[Path, Path]]) -> Callable[[Path, Path], None]:
    """Stands in for ffmpeg: copies the input unchanged."""

    def convert(source: Path, destination: Path) -> None:
        converter_calls.append((source, destination))
        shutil.copy(source, destination)

    return convert


@pytest.fixture
def store(settings: Settings, copy_converter: Callable[[Path, Path], None]) -> CallStore:
    return CallStore(settings, converter=copy_converter)


class ScriptedAnalyzer:
    """Replies from a script keyed by chunk number and records every context block."""

    def __init__(self, script: Callable[[int], dict[str, Any]]) -> None:
        self.script = script
        self.context_blocks: list[str] = []

    def __call__(self, wav_bytes: bytes, context_block: str) -> dict[str, Any]:
        self.context_blocks.append(context_block)
        chunk_number = int(context_block.split("/", 1)[0].removeprefix("CHUNK "))
        return self.script(chunk_number)


@pytest.fixture
def analyzer() -> ScriptedAnalyzer:
    def script(chunk_number: int) -> dict[str, Any]:
        if chunk_number == 2:
            return {
                "status": "ok",
                "latency_ms": 420,
                "model": "test-model",
                **analysis(
                    transcript=[{"speaker": "CALLER", "text": "તમારો OTP આપો"}],
                    new_red_flags=[
                        {"type": "OTP_OR_CREDENTIALS", "quote": "તમારો OTP આપો", "why": "OTP"}
                    ],
                    scam_type="FAKE_KYC",
                    risk_score=40,
                    verdict="SUSPICIOUS",
                ),
            }
        return {
            "status": "ok",
            "latency_ms": 300,
            "model": "test-model",
            **analysis(transcript=[{"speaker": "CALLER", "text": "નમસ્તે"}], risk_score=10),
        }

    return ScriptedAnalyzer(script)


@pytest.fixture
def client(
    settings: Settings, store: CallStore, analyzer: ScriptedAnalyzer
) -> Iterator[TestClient]:
    app = create_app(settings, analyzer=analyzer, store=store, sleep=lambda _seconds: None)
    with TestClient(app) as test_client:
        yield test_client
