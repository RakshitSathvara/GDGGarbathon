from __future__ import annotations

import base64
import dataclasses
import json
import logging
import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path

import pytest

from app import storage
from app.config import Settings
from app.storage import CallStore, UploadError, ffmpeg_converter, sanitize_call_stem

from .conftest import load_fixture, make_wav

WAV = make_wav([(1.0, 2000)])


def failing_converter(_source: Path, _destination: Path) -> None:
    raise FileNotFoundError("ffmpeg is not installed")


def test_lists_the_demo_call_with_golden_chunks(store: CallStore) -> None:
    golden = next(
        c
        for c in load_fixture("chunk_boundaries.json")["demo_calls"]
        if c["file"] == "fake_kyc.wav"
    )
    [call] = store.list_calls()
    assert call["id"] == "fake_kyc"
    assert [[c["start_s"], c["end_s"]] for c in call["chunks"]] == golden["boundaries"]
    assert call["has_cache"] is False


def test_manifest_validation_and_fallbacks(
    store: CallStore, settings: Settings, caplog: pytest.LogCaptureFixture
) -> None:
    settings.manifest_path.write_text(
        json.dumps(
            [
                {"file": "fake_kyc.wav", "title": "ok", "expected": "SCAM"},
                {"file": "../escape.wav", "title": "bad", "expected": "SCAM"},
                "not an entry",
            ]
        ),
        encoding="utf-8",
    )
    with caplog.at_level(logging.WARNING):
        assert len(store.load_manifest()) == 1
    assert "Skipped 2 invalid manifest entries" in caplog.text

    settings.tmp_calls_dir.mkdir(parents=True)
    settings.tmp_manifest_path.write_text("{corrupt", encoding="utf-8")
    assert len(store.load_manifest()) == 1
    settings.tmp_manifest_path.write_text('[{"file": "a.wav", "title": "t", "expected": "SAFE"}]')
    assert store.load_manifest()[0]["file"] == "a.wav"
    settings.tmp_manifest_path.write_text('{"not": "a list"}')
    assert len(store.load_manifest()) == 1


def test_missing_manifest_means_no_calls(store: CallStore, settings: Settings) -> None:
    settings.manifest_path.unlink()
    assert store.list_calls() == []


def test_save_manifest_falls_back_to_tmp_when_read_only(
    store: CallStore, settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_write = storage._atomic_write

    def read_only(path: Path, data: bytes) -> None:
        if path == settings.manifest_path:
            raise OSError("read-only file system")
        real_write(path, data)

    monkeypatch.setattr(storage, "_atomic_write", read_only)
    store.save_manifest([{"file": "a.wav", "title": "Ä", "expected": "SAFE"}])
    assert json.loads(settings.tmp_manifest_path.read_text(encoding="utf-8"))[0]["title"] == "Ä"
    assert store.find_entry("a")["file"] == "a.wav"


def test_find_and_resolve(store: CallStore, settings: Settings) -> None:
    assert store.find_entry("fake_kyc")["expected"] == "SCAM"
    assert store.find_entry("fake_kyc.wav") is not None
    assert store.find_entry("nope") is None
    settings.tmp_calls_dir.mkdir(parents=True)
    (settings.tmp_calls_dir / "late.wav").write_bytes(WAV)
    assert store.resolve_wav_path("late.wav").parent == settings.tmp_calls_dir
    assert store.resolve_wav_path("../../etc/passwd").parent == settings.calls_dir


def test_describe_handles_missing_and_corrupt_audio(
    store: CallStore, settings: Settings, caplog: pytest.LogCaptureFixture
) -> None:
    missing = store.describe({"file": "ghost.wav", "title": "Ghost", "expected": "SAFE"})
    assert (missing["duration"], missing["chunks"]) == (0.0, [])
    (settings.calls_dir / "broken.wav").write_bytes(b"RIFF....WAVEjunk")
    with caplog.at_level(logging.WARNING):
        broken = store.describe({"file": "broken.wav", "title": "Broken", "expected": "SAFE"})
    assert broken["chunks"] == []
    assert "Cannot chunk broken.wav" in caplog.text


def test_chunk_plans_are_cached_until_the_file_changes(
    store: CallStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[Path] = []
    real = storage.compute_chunks

    def counting(path: Path, target: float):
        calls.append(path)
        return real(path, target)

    monkeypatch.setattr(storage, "compute_chunks", counting)
    store.list_calls()
    store.list_calls()
    assert len(calls) == 1


def test_replay_cache(store: CallStore, settings: Settings) -> None:
    assert store.read_replay_cache("fake_kyc") is None
    (settings.cache_dir / "fake_kyc.json").write_text('{"chunks": []}', encoding="utf-8")
    assert store.read_replay_cache("fake_kyc") == {"chunks": []}
    assert store.list_calls()[0]["has_cache"] is True


def test_upload_creates_a_namespaced_playable_call(
    store: CallStore, settings: Settings, converter_calls: list
) -> None:
    entry = store.store_upload("Mom Call.wav", WAV, None, "SAFE")
    assert entry == {
        "file": "upload_mom_call.wav",
        "title": "Uploaded — Mom Call",
        "expected": "SAFE",
        "uploaded": True,
    }
    assert (settings.raw_calls_dir / entry["file"]).exists()
    assert (settings.calls_dir / entry["file"]).read_bytes() == WAV
    assert len(converter_calls) == 1
    assert not list(settings.calls_dir.glob(".*.converting.wav"))
    assert store.find_entry("upload_mom_call")["title"] == "Uploaded — Mom Call"


def test_upload_cannot_overwrite_demo_calls(store: CallStore) -> None:
    entry = store.store_upload("fake_kyc.wav", WAV, "Mine", "SCAM")
    assert entry["file"] == "upload_fake_kyc.wav"
    assert store.find_entry("fake_kyc")["title"].startswith("Fake Bank KYC")


def test_reupload_updates_the_existing_entry(store: CallStore) -> None:
    store.store_upload("a.wav", WAV, "First", "SCAM")
    manifest = store.load_manifest()
    manifest[-1]["first_demand_at"] = 3
    store.save_manifest(manifest)
    entry = store.store_upload("a.wav", WAV, "Second", "MAYBE")
    assert (entry["title"], entry["expected"], entry["first_demand_at"]) == ("Second", "SCAM", 3)
    assert sum(1 for e in store.load_manifest() if e["file"] == "upload_a.wav") == 1


@pytest.mark.parametrize(
    ("filename", "audio", "message"),
    [
        (" ", WAV, "select a .wav"),
        ("a.mp3", WAV, "Only .wav"),
        ("a.wav", WAV[:40], "empty or corrupted"),
        ("a.wav", b"\0" * 100, "RIFF/WAVE"),
        ("a.wav", WAV[:36] + b"junk" + WAV[40:60], "empty or corrupted"),
    ],
)
def test_upload_validation(store: CallStore, filename: str, audio: bytes, message: str) -> None:
    with pytest.raises(UploadError, match=message) as error:
        store.store_upload(filename, audio, None, "SCAM")
    assert error.value.status_code == 400


def test_upload_size_limit(settings: Settings, copy_converter: Callable) -> None:
    small = CallStore(dataclasses.replace(settings, max_upload_bytes=100), copy_converter)
    with pytest.raises(UploadError, match="exceeds the 10 MB"):
        small.store_upload("a.wav", WAV, None, "SCAM")


def test_upload_count_limit(settings: Settings, copy_converter: Callable) -> None:
    capped = CallStore(dataclasses.replace(settings, max_uploaded_calls=1), copy_converter)
    capped.store_upload("one.wav", WAV, None, "SCAM")
    with pytest.raises(UploadError, match="Upload limit reached") as error:
        capped.store_upload("two.wav", WAV, None, "SCAM")
    assert error.value.status_code == 409
    capped.store_upload("one.wav", WAV, None, "SCAM")


def test_pcm_upload_survives_missing_ffmpeg(settings: Settings) -> None:
    entry = CallStore(settings, failing_converter).store_upload("pcm.wav", WAV, None, "SCAM")
    assert (settings.calls_dir / entry["file"]).read_bytes() == WAV


def test_unconvertible_upload_is_rejected(settings: Settings) -> None:
    eight_bit = make_wav([(1.0, 2000)], bits_per_sample=8)
    with pytest.raises(UploadError, match="Could not convert") as error:
        CallStore(settings, failing_converter).store_upload("old.wav", eight_bit, None, "SCAM")
    assert error.value.status_code == 422
    assert not (settings.calls_dir / "upload_old.wav").exists()


def test_upload_falls_back_to_tmp_on_read_only_calls_dir(
    store: CallStore, settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_write_bytes = Path.write_bytes

    def guarded(path: Path, data: bytes) -> int:
        if path.parent == settings.raw_calls_dir:
            raise OSError("read-only file system")
        return real_write_bytes(path, data)

    monkeypatch.setattr(Path, "write_bytes", guarded)
    entry = store.store_upload("cloud.wav", WAV, None, "SCAM")
    assert (settings.tmp_calls_dir / entry["file"]).exists()
    assert (settings.tmp_calls_dir / f"raw_{entry['file']}").exists()


def test_sanitize_call_stem() -> None:
    assert sanitize_call_stem("../../etc/passwd.wav") == "passwd"
    assert sanitize_call_stem("C:\\calls\\Mom (1).WAV") == "mom_1"
    assert sanitize_call_stem("ગુજરાતી.wav") == "uploaded_call"
    assert len(sanitize_call_stem("x" * 80 + ".wav")) == 48


def test_ffmpeg_converter_requires_ffmpeg(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(storage.shutil, "which", lambda _name: None)
    with pytest.raises(FileNotFoundError):
        ffmpeg_converter(5)(tmp_path / "in.wav", tmp_path / "out.wav")


@pytest.mark.skipif(shutil.which("ffmpeg") is None, reason="ffmpeg is not installed")
def test_ffmpeg_converter_normalises_audio(tmp_path: Path) -> None:
    source = tmp_path / "in.wav"
    source.write_bytes(make_wav([(1.0, 3000)], sample_rate=8_000, channels=2))
    destination = tmp_path / "out.wav"
    ffmpeg_converter(30)(source, destination)
    header = storage.read_wav_header(destination.read_bytes())
    assert header is not None
    assert (header.sample_rate, header.channels, header.bits_per_sample) == (16_000, 1, 16)
    with pytest.raises(subprocess.CalledProcessError):
        ffmpeg_converter(30)(tmp_path / "missing.wav", tmp_path / "never.wav")


def test_base64_roundtrip_matches_client_encoding() -> None:
    assert base64.b64decode(base64.b64encode(WAV), validate=True) == WAV
