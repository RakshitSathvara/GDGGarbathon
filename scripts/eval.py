#!/usr/bin/env python3
"""Evaluation CLI for Saavdhan.

Runs every call in calls/manifest.json (or one call with --call) through the same chunker,
detector and session rules as the servers, saves per-chunk results to cache/<call>.json for
replay mode, prints a summary table and exits non-zero on any miss.
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
from pathlib import Path
from typing import Any

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from app.chunker import compute_chunks, slice_wav_bytes  # noqa: E402
from app.config import DEFAULT_MODEL, DEFAULT_THINKING_LEVEL, chunk_sec_from_env  # noqa: E402
from app.detector import analyze_chunk  # noqa: E402
from app.rules import apply_session_rules, build_context_block, create_empty_session  # noqa: E402

CALLS_DIR = ROOT_DIR / "calls"
CACHE_DIR = ROOT_DIR / "cache"
TABLE_WIDTH = 118


def demand_delta(first_demand_at: float | None, first_scam_at: float | None) -> str:
    """How long before (or after) the caller's first demand the SCAM warning fired."""
    if first_demand_at is None or first_scam_at is None:
        return "—"
    diff = round(first_demand_at - first_scam_at, 1)
    return f"{diff:.1f}s before" if diff >= 0 else f"{abs(diff):.1f}s after"


def quotes_appear_in_transcript(session: dict[str, Any]) -> bool:
    """Every SCAM verdict must be backed by at least one quote that was actually heard."""
    transcript = " ".join(turn["text"] for turn in session["transcript"])
    quotes = [flag["quote"] for flag in session["red_flags"] if flag.get("quote")]
    return bool(quotes) and any(
        quote in transcript or quote.lower() in transcript.lower() for quote in quotes
    )


def print_call_transcript(call_id: str, title: str, chunks: list[dict[str, Any]]) -> None:
    print(f"\n=== TRANSCRIPT: {call_id} ({title}) ===")
    for chunk in chunks:
        print(
            f"\n[Chunk {chunk['chunk_index'] + 1}/{len(chunks)} | "
            f"{chunk['start_s']:.1f}s–{chunk['end_s']:.1f}s | "
            f"Risk {chunk['risk_score']} {chunk['verdict']} | {chunk['latency_ms']} ms]"
        )
        for turn in chunk.get("transcript", []):
            print(f"  {turn['speaker']}: {turn['text']}")
        for flag in chunk.get("new_red_flags", []):
            print(f'  + RED FLAG [{flag["type"]}]: "{flag["quote"]}" ({flag["why"]})')
        for lang in ("gu", "hi", "en"):
            if chunk.get(f"warning_{lang}"):
                print(f"  ! {lang.upper()}: {chunk[f'warning_{lang}']}")


def evaluate_call(
    entry: dict[str, Any],
    model: str,
    thinking_level: str,
    print_transcript: bool = False,
    calls_dir: Path = CALLS_DIR,
    cache_dir: Path = CACHE_DIR,
) -> dict[str, Any]:
    file_name = entry["file"]
    call_id = Path(file_name).stem
    wav_path = calls_dir / file_name
    if not wav_path.exists():
        raise FileNotFoundError(f"Missing audio file: {wav_path}. Run scripts/prep.sh first.")

    boundaries, duration = compute_chunks(wav_path)
    session = create_empty_session(call_id=call_id, session_id=f"eval-{call_id}")
    cache_chunks: list[dict[str, Any]] = []
    latencies: list[int] = []
    max_risk = 0
    ever_reached_scam = False

    for idx, (start_s, end_s) in enumerate(boundaries):
        context_block = build_context_block(
            chunk_num=idx + 1,
            total_chunks=len(boundaries),
            start_s=start_s,
            end_s=end_s,
            session=session,
        )
        raw_result = analyze_chunk(
            wav_bytes=slice_wav_bytes(wav_path, start_s, end_s),
            context_block=context_block,
            model=model,
            thinking_level=thinking_level,
        )
        processed = apply_session_rules(
            session=session,
            chunk_index=idx,
            start_s=start_s,
            end_s=end_s,
            chunk_result=raw_result,
        )
        latencies.append(processed.get("latency_ms", 0))
        max_risk = max(max_risk, session["risk"])
        ever_reached_scam = ever_reached_scam or session["verdict"] == "SCAM"
        # Raw model output is kept so replay mode can re-run the session rules faithfully.
        cache_chunks.append(
            {
                **processed,
                "raw_transcript": raw_result.get("transcript", []),
                "raw_new_red_flags": raw_result.get("new_red_flags", []),
                "raw_new_genuine_signals": raw_result.get("new_genuine_signals", []),
            }
        )

    if print_transcript:
        print_call_transcript(call_id, entry["title"], cache_chunks)

    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_payload = {
        "call_id": call_id,
        "file": file_name,
        "title": entry["title"],
        "expected": entry["expected"],
        "first_demand_at": entry.get("first_demand_at"),
        "duration": duration,
        "model": model,
        "final_verdict": session["verdict"],
        "max_risk": max_risk,
        "first_scam_at": session["first_scam_at"],
        "red_flags": session["red_flags"],
        "genuine_signals": session["genuine_signals"],
        "transcript": session["transcript"],
        "chunks": cache_chunks,
    }
    (cache_dir / f"{call_id}.json").write_text(
        json.dumps(cache_payload, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    expected = entry["expected"]
    if expected == "SCAM":
        passed = ever_reached_scam and session["verdict"] == "SCAM"
        quote_verified = quotes_appear_in_transcript(session)
    else:
        passed = not ever_reached_scam and session["verdict"] == "SAFE"
        quote_verified = True

    return {
        "call_id": call_id,
        "expected": expected,
        "final_verdict": session["verdict"],
        "ever_reached_scam": ever_reached_scam,
        "max_risk": max_risk,
        "first_scam_at": session["first_scam_at"],
        "delta_demand": demand_delta(entry.get("first_demand_at"), session["first_scam_at"]),
        "mean_latency_ms": round(statistics.mean(latencies)) if latencies else 0,
        "median_latency_ms": round(statistics.median(latencies)) if latencies else 0,
        "max_latency_ms": max(latencies, default=0),
        "all_latencies_ms": latencies,
        "flags": sorted({flag["type"] for flag in session["red_flags"]}),
        "passed": passed and quote_verified,
        "quote_verified": quote_verified,
    }


def print_summary(rows: list[dict[str, Any]]) -> None:
    print("\n" + "=" * TABLE_WIDTH)
    print(
        f"{'CALL':<18} | {'EXP':<5} | {'FINAL':<10} | {'MAX RISK':<8} | "
        f"{'1ST SCAM':<8} | {'VS DEMAND':<13} | {'MEAN/MAX LAT':<15} | {'STATUS':<6} | FLAGS"
    )
    print("-" * TABLE_WIDTH)
    for row in rows:
        first_scam = f"{row['first_scam_at']:.1f}s" if row["first_scam_at"] is not None else "—"
        latency = f"{row['mean_latency_ms']}/{row['max_latency_ms']} ms"
        status = "PASS" if row["passed"] else "MISS"
        flags = ", ".join(row["flags"]) or "none"
        print(
            f"{row['call_id']:<18} | {row['expected']:<5} | {row['final_verdict']:<10} | "
            f"{row['max_risk']:<8} | {first_scam:<8} | {row['delta_demand']:<13} | "
            f"{latency:<15} | {status:<6} | {flags}"
        )
    print("=" * TABLE_WIDTH)


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate the Saavdhan scam detector.")
    parser.add_argument(
        "--model",
        default=os.getenv("MODEL", DEFAULT_MODEL),
        help=f"Gemini model name (default: env MODEL or {DEFAULT_MODEL})",
    )
    parser.add_argument(
        "--thinking-level",
        default=os.getenv("THINKING_LEVEL", DEFAULT_THINKING_LEVEL),
        help="Thinking level (minimal, low, medium, high)",
    )
    parser.add_argument("--call", default=None, help="Single call ID or file, e.g. digital_arrest")
    parser.add_argument(
        "--print-transcript",
        action="store_true",
        help="Print per-chunk Gujarati/Hindi transcript and warnings",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None, calls_dir: Path = CALLS_DIR) -> int:
    args = parse_args(argv)
    manifest = json.loads((calls_dir / "manifest.json").read_text(encoding="utf-8"))
    if args.call:
        manifest = [m for m in manifest if args.call in (Path(m["file"]).stem, m["file"])]
        if not manifest:
            print(f"No call matching '{args.call}' in calls/manifest.json", file=sys.stderr)
            return 1

    print(f"Running Saavdhan Eval | model={args.model} | thinking={args.thinking_level}")
    rows = [
        evaluate_call(
            entry=entry,
            model=args.model,
            thinking_level=args.thinking_level,
            print_transcript=args.print_transcript or args.call is not None,
            calls_dir=calls_dir,
        )
        for entry in manifest
    ]
    print_summary(rows)

    all_latencies = [latency for row in rows for latency in row["all_latencies_ms"]]
    median_ms = round(statistics.median(all_latencies)) if all_latencies else 0
    target_ms = chunk_sec_from_env() * 1000
    print(f"Overall Median Chunk Latency: {median_ms} ms (target < {target_ms:.0f} ms)")

    misses = [row for row in rows if not row["passed"]]
    if misses:
        print(f"\nEVAL FAILED: {len(misses)} call(s) missed target criteria.", file=sys.stderr)
        return 1
    print("\nEVAL PASSED: All scam calls reached SCAM and genuine calls remained SAFE.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
