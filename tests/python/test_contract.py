"""Contract tests: the Python backend must agree with shared/*.json and with the Node backend.

tests/node/contract.test.ts replays the same fixtures through server/rules.ts.
"""

from __future__ import annotations

import json
import re
import typing
from typing import Any

import pytest

from app import detector
from app.rules import (
    FALLBACK_WARNINGS,
    POLICY,
    apply_session_rules,
    build_context_block,
    create_empty_session,
)

from .conftest import REPO_ROOT, load_fixture

FIXTURE = load_fixture("session_rules_cases.json")
PLACEHOLDER = re.compile(r"\{\{(SCAM|SUSPICIOUS)\.(gu|hi|en)\}\}")


def expand(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    return PLACEHOLDER.sub(lambda m: FALLBACK_WARNINGS[m.group(1)][m.group(2)], value)


def assert_matches(actual: dict[str, Any], expected: dict[str, Any], label: str) -> None:
    for key, want in expected.items():
        if key in ("flag_times", "signal_times"):
            items_key = "new_red_flags" if key == "flag_times" else "new_genuine_signals"
            assert [item["time_mm_ss"] for item in actual[items_key]] == want, f"{label}: {key}"
            continue
        got = actual[key]
        if isinstance(got, list):
            assert len(got) == want, f"{label}: {key} count"
        else:
            assert got == expand(want), f"{label}: {key}"


def test_shared_schema_is_the_response_format_sent_to_gemini() -> None:
    shared = json.loads((REPO_ROOT / "shared" / "chunk_schema.json").read_text(encoding="utf-8"))
    assert shared == detector.CHUNK_SCHEMA


def test_schema_enums_match_pydantic_models() -> None:
    props = detector.CHUNK_SCHEMA["properties"]
    assert (
        list(typing.get_args(detector.Speaker))
        == (props["transcript"]["items"]["properties"]["speaker"]["enum"])
    )
    assert (
        list(typing.get_args(detector.RedFlagType))
        == (props["new_red_flags"]["items"]["properties"]["type"]["enum"])
    )
    assert list(typing.get_args(detector.ScamType)) == props["scam_type"]["enum"]
    assert list(typing.get_args(detector.ModelVerdict)) == props["verdict"]["enum"]


def test_policy_red_flags_are_known_types() -> None:
    known = set(typing.get_args(detector.RedFlagType))
    assert set(POLICY["hard_red_flags"]) <= known
    assert set(POLICY["trio_red_flags"]) <= known
    assert all(
        floor >= POLICY["verdict_thresholds"]["SCAM"] for floor in POLICY["risk_floors"].values()
    )


@pytest.mark.parametrize("case", FIXTURE["cases"], ids=lambda case: case["name"])
def test_session_rules_parity(case: dict[str, Any]) -> None:
    session = create_empty_session(case["call_id"], "parity")
    for number, step in enumerate(case["steps"], start=1):
        label = f"{case['name']} / step {number}"
        record = apply_session_rules(
            session=session,
            chunk_index=step["chunk"]["index"],
            start_s=step["chunk"]["start_s"],
            end_s=step["chunk"]["end_s"],
            chunk_result=step["result"],
        )
        assert_matches(record, step["expect"]["chunk"], f"{label} chunk")
        assert_matches(session, step["expect"]["session"], f"{label} session")


@pytest.mark.parametrize("case", FIXTURE["context_blocks"], ids=lambda case: case["name"])
def test_context_block_parity(case: dict[str, Any]) -> None:
    block = build_context_block(
        chunk_num=case["chunk_num"],
        total_chunks=case["total_chunks"],
        start_s=case["start_s"],
        end_s=case["end_s"],
        session=case["session"],
    )
    assert block == case["expected"]
