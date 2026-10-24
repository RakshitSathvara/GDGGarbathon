from __future__ import annotations

import importlib
import json
import shutil
from pathlib import Path
from typing import Any

import pytest

from app.config import (
    DEFAULT_MODEL,
    api_key_from_env,
    chunk_sec_from_env,
    load_settings,
)

from .conftest import REPO_ROOT, analysis

eval_script = importlib.import_module("scripts.eval")


@pytest.fixture
def calls_dir(tmp_path: Path) -> Path:
    directory = tmp_path / "calls"
    directory.mkdir()
    shutil.copy(REPO_ROOT / "calls" / "fake_kyc.wav", directory / "fake_kyc.wav")
    manifest = json.loads((REPO_ROOT / "calls" / "manifest.json").read_text(encoding="utf-8"))
    (directory / "manifest.json").write_text(
        json.dumps([m for m in manifest if m["file"] == "fake_kyc.wav"]), encoding="utf-8"
    )
    return directory


def scripted_detector(monkeypatch: pytest.MonkeyPatch, detects_scam: bool) -> list[str]:
    models: list[str] = []

    def fake(wav_bytes: bytes, context_block: str, model: str, thinking_level: str) -> dict:
        models.append(model)
        flags = (
            [{"type": "OTP_OR_CREDENTIALS", "quote": "તમારો OTP આપો", "why": "OTP"}]
            if detects_scam
            else []
        )
        return {
            "status": "ok",
            "latency_ms": 250,
            "model": model,
            **analysis(
                transcript=[{"speaker": "CALLER", "text": "તમારો OTP આપો"}],
                new_red_flags=flags,
                risk_score=20,
            ),
        }

    monkeypatch.setattr(eval_script, "analyze_chunk", fake)
    return models


def test_evaluate_call_passes_and_writes_replay_cache(
    calls_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scripted_detector(monkeypatch, detects_scam=True)
    entry = json.loads((calls_dir / "manifest.json").read_text(encoding="utf-8"))[0]
    row = eval_script.evaluate_call(
        entry, "test-model", "low", calls_dir=calls_dir, cache_dir=tmp_path / "cache"
    )
    assert row["passed"] is True
    assert row["final_verdict"] == "SCAM"
    assert row["delta_demand"] == "9.3s before"  # demand at 16 s, warned at 6.66 s
    assert row["flags"] == ["OTP_OR_CREDENTIALS"]
    cache = json.loads((tmp_path / "cache" / "fake_kyc.json").read_text(encoding="utf-8"))
    assert cache["chunks"][0]["raw_new_red_flags"][0]["quote"] == "તમારો OTP આપો"


def test_evaluate_call_reports_a_miss(
    calls_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scripted_detector(monkeypatch, detects_scam=False)
    entry = json.loads((calls_dir / "manifest.json").read_text(encoding="utf-8"))[0]
    row = eval_script.evaluate_call(
        entry, "test-model", "low", calls_dir=calls_dir, cache_dir=tmp_path / "cache"
    )
    assert row["passed"] is False
    assert row["quote_verified"] is False


def test_evaluate_call_requires_prepared_audio(calls_dir: Path) -> None:
    entry = {"file": "missing.wav", "title": "Missing", "expected": "SCAM"}
    with pytest.raises(FileNotFoundError, match=r"Run scripts/prep\.sh"):
        eval_script.evaluate_call(entry, "m", "low", calls_dir=calls_dir)


def test_main_prints_a_summary_and_exit_code(
    calls_dir: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(eval_script, "CACHE_DIR", tmp_path / "cache")
    monkeypatch.setattr(eval_script.evaluate_call, "__defaults__", (False, calls_dir, tmp_path))
    models = scripted_detector(monkeypatch, detects_scam=True)
    assert eval_script.main(["--call", "fake_kyc", "--model", "m1"], calls_dir=calls_dir) == 0
    output = capsys.readouterr().out
    assert "EVAL PASSED" in output
    assert "=== TRANSCRIPT: fake_kyc" in output
    assert set(models) == {"m1"}

    scripted_detector(monkeypatch, detects_scam=False)
    assert eval_script.main([], calls_dir=calls_dir) == 1
    assert "EVAL FAILED" in capsys.readouterr().err

    assert eval_script.main(["--call", "nope"], calls_dir=calls_dir) == 1


def test_demand_delta_and_quote_checks() -> None:
    assert eval_script.demand_delta(24.1, 11.5) == "12.6s before"
    assert eval_script.demand_delta(10.0, 12.0) == "2.0s after"
    assert eval_script.demand_delta(None, 3.0) == "—"
    session = {"transcript": [{"text": "Send OTP now"}], "red_flags": [{"quote": "send otp"}]}
    assert eval_script.quotes_appear_in_transcript(session) is True
    assert eval_script.quotes_appear_in_transcript({"transcript": [], "red_flags": []}) is False


def test_settings_from_environment(tmp_path: Path) -> None:
    defaults = load_settings({}, root_dir=tmp_path)
    assert defaults.manifest_path == tmp_path / "calls" / "manifest.json"
    assert defaults.model == DEFAULT_MODEL
    assert defaults.demo_replay is False
    assert defaults.frame_ancestors is None
    custom = load_settings(
        {
            "DEMO_REPLAY": "1",
            "MODEL": "gemini-3.5-flash-lite",
            "CHUNK_SEC": "7.5",
            "FRAME_ANCESTORS": "'self', https://aistudio.google.com",
        },
        root_dir=tmp_path,
    )
    assert custom.demo_replay is True
    assert custom.model == "gemini-3.5-flash-lite"
    assert custom.chunk_sec == 7.5
    assert custom.frame_ancestors == ("'self'", "https://aistudio.google.com")
    assert custom.tmp_manifest_path.name == "manifest.json"


def test_chunk_sec_and_api_key_parsing() -> None:
    assert chunk_sec_from_env({"CHUNK_SEC": "99"}) == 30.0
    assert chunk_sec_from_env({"CHUNK_SEC": "x"}) == 6.0
    assert chunk_sec_from_env({}) == 6.0
    assert api_key_from_env({"GEMINI_API_KEY": "MY_GEMINI_API_KEY"}) is None
    assert api_key_from_env({"GEMINI_API_KEY": " key "}) == "key"
    assert api_key_from_env({}) is None


def test_default_model_matches_documentation() -> None:
    readme = (REPO_ROOT / ".env.example").read_text(encoding="utf-8")
    assert f'MODEL="{DEFAULT_MODEL}"' in readme


def test_analysis_helper_is_complete() -> None:
    expected: dict[str, Any] = analysis()
    assert set(expected) == {
        "transcript",
        "new_red_flags",
        "new_genuine_signals",
        "scam_type",
        "risk_score",
        "verdict",
        "warning_gu",
        "warning_hi",
        "warning_en",
    }
