#!/usr/bin/env python3
"""
Evaluation CLI for Saavdhan.
Runs every call (or a single call with --call) through the same chunker, detector, and session rules.
Saves per-chunk results to cache/<call>.json and exits non-zero on any miss.
"""
from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
from pathlib import Path
from typing import Any, Dict, List

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from app.chunker import compute_chunks, slice_wav_bytes  # noqa: E402
from app.detector import (  # noqa: E402
    analyze_chunk,
    apply_session_rules,
    build_context_block,
    create_empty_session,
)


def evaluate_call(
    entry: Dict[str, Any],
    model: str,
    thinking_level: str,
    print_transcript: bool = False,
) -> Dict[str, Any]:
    file_name = entry["file"]
    call_id = Path(file_name).stem
    wav_path = ROOT_DIR / "calls" / file_name
    if not wav_path.exists():
        raise FileNotFoundError(f"Missing audio file: {wav_path}. Run scripts/prep.sh first.")

    boundaries, duration = compute_chunks(wav_path)
    session = create_empty_session(call_id=call_id, session_id=f"eval-{call_id}")

    cache_chunks: List[Dict[str, Any]] = []
    latencies: List[int] = []
    max_risk = 0
    ever_reached_scam = False

    for idx, (start_s, end_s) in enumerate(boundaries):
        wav_bytes = slice_wav_bytes(wav_path, start_s, end_s)
        context_block = build_context_block(
            chunk_num=idx + 1,
            total_chunks=len(boundaries),
            start_s=start_s,
            end_s=end_s,
            session=session,
        )
        raw_res = analyze_chunk(
            wav_bytes=wav_bytes,
            context_block=context_block,
            model=model,
            thinking_level=thinking_level,
        )
        processed = apply_session_rules(
            session=session,
            chunk_index=idx,
            start_s=start_s,
            end_s=end_s,
            chunk_result=raw_res,
        )
        latencies.append(processed.get("latency_ms", 0))
        max_risk = max(max_risk, session["risk"])
        if session["verdict"] == "SCAM":
            ever_reached_scam = True

        cache_chunks.append(
            {
                **processed,
                "raw_transcript": raw_res.get("transcript", []),
                "raw_new_red_flags": raw_res.get("new_red_flags", []),
                "raw_new_genuine_signals": raw_res.get("new_genuine_signals", []),
            }
        )

    if print_transcript:
        print(f"\n=== TRANSCRIPT: {call_id} ({entry['title']}) ===")
        for chunk in cache_chunks:
            c_idx = chunk["chunk_index"] + 1
            print(
                f"\n[Chunk {c_idx}/{len(cache_chunks)} | {chunk['start_s']:.1f}s–{chunk['end_s']:.1f}s "
                f"| Risk {chunk['risk_score']} {chunk['verdict']} | {chunk['latency_ms']} ms]"
            )
            for turn in chunk.get("transcript", []):
                print(f"  {turn['speaker']}: {turn['text']}")
            for rf in chunk.get("new_red_flags", []):
                print(f"  + RED FLAG [{rf['type']}]: \"{rf['quote']}\" ({rf['why']})")
            if chunk.get("warning_gu"):
                print(f"  ! GU: {chunk['warning_gu']}")
            if chunk.get("warning_hi"):
                print(f"  ! HI: {chunk['warning_hi']}")
            if chunk.get("warning_en"):
                print(f"  ! EN: {chunk['warning_en']}")

    # Save per-chunk results to cache/<call>.json
    cache_dir = ROOT_DIR / "cache"
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
        json.dumps(cache_payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    first_demand_at = entry.get("first_demand_at")
    first_scam_at = session["first_scam_at"]
    delta_demand_str = "—"
    if first_demand_at is not None and first_scam_at is not None:
        diff = round(first_demand_at - first_scam_at, 1)
        if diff >= 0:
            delta_demand_str = f"{diff:.1f}s before"
        else:
            delta_demand_str = f"{abs(diff):.1f}s after"

    expected = entry["expected"]
    if expected == "SCAM":
        passed = ever_reached_scam and session["verdict"] == "SCAM"
    else:
        passed = (not ever_reached_scam) and session["verdict"] == "SAFE"

    # Also verify every SCAM warning names at least one red flag quote in transcript
    full_transcript_text = " ".join(t["text"] for t in session["transcript"])
    flag_quotes = [f["quote"] for f in session["red_flags"] if f.get("quote")]
    quote_verified = True
    if expected == "SCAM":
        quote_verified = bool(flag_quotes) and any(
            q in full_transcript_text or q.lower() in full_transcript_text.lower()
            for q in flag_quotes
        )

    mean_lat = int(round(statistics.mean(latencies))) if latencies else 0
    median_lat = int(round(statistics.median(latencies))) if latencies else 0
    max_lat = max(latencies) if latencies else 0
    unique_flag_types = sorted({f["type"] for f in session["red_flags"]})

    return {
        "call_id": call_id,
        "expected": expected,
        "final_verdict": session["verdict"],
        "ever_reached_scam": ever_reached_scam,
        "max_risk": max_risk,
        "first_scam_at": first_scam_at,
        "delta_demand": delta_demand_str,
        "mean_latency_ms": mean_lat,
        "median_latency_ms": median_lat,
        "max_latency_ms": max_lat,
        "all_latencies_ms": latencies,
        "flags": unique_flag_types,
        "passed": passed and quote_verified,
        "quote_verified": quote_verified,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate Saavdhan scam detector on recorded calls.")
    parser.add_argument(
        "--model",
        default=os.getenv("MODEL", "gemini-3.8-flash"),
        help="Gemini model name (default: env MODEL or gemini-3.8-flash)",
    )
    parser.add_argument(
        "--thinking-level",
        default=os.getenv("THINKING_LEVEL", "low"),
        help="Thinking level (minimal, low, medium, high)",
    )
    parser.add_argument(
        "--call",
        default=None,
        help="Optional single call ID or filename to run (e.g. digital_arrest)",
    )
    parser.add_argument(
        "--print-transcript",
        action="store_true",
        help="Print per-chunk Gujarati/Hindi transcript and warnings",
    )
    args = parser.parse_args()

    manifest_path = ROOT_DIR / "calls" / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    if args.call:
        manifest = [
            m
            for m in manifest
            if Path(m["file"]).stem == args.call or m["file"] == args.call
        ]
        if not manifest:
            print(f"No call matching '{args.call}' in calls/manifest.json", file=sys.stderr)
            return 1

    print(f"Running Saavdhan Eval | model={args.model} | thinking={args.thinking_level}")
    rows: List[Dict[str, Any]] = []
    all_latencies: List[int] = []

    for entry in manifest:
        row = evaluate_call(
            entry=entry,
            model=args.model,
            thinking_level=args.thinking_level,
            print_transcript=args.print_transcript or (args.call is not None),
        )
        rows.append(row)
        all_latencies.extend(row["all_latencies_ms"])

    print("\n" + "=" * 118)
    header = (
        f"{'CALL':<18} | {'EXP':<5} | {'FINAL':<10} | {'MAX RISK':<8} | "
        f"{'1ST SCAM':<8} | {'VS DEMAND':<13} | {'MEAN/MAX LAT':<15} | {'STATUS':<6} | FLAGS"
    )
    print(header)
    print("-" * 118)
    for r in rows:
        first_scam_str = f"{r['first_scam_at']:.1f}s" if r["first_scam_at"] is not None else "—"
        lat_str = f"{r['mean_latency_ms']}/{r['max_latency_ms']} ms"
        status_str = "PASS" if r["passed"] else "MISS"
        flags_str = ", ".join(r["flags"]) if r["flags"] else "none"
        print(
            f"{r['call_id']:<18} | {r['expected']:<5} | {r['final_verdict']:<10} | "
            f"{r['max_risk']:<8} | {first_scam_str:<8} | {r['delta_demand']:<13} | "
            f"{lat_str:<15} | {status_str:<6} | {flags_str}"
        )
    print("=" * 118)

    overall_median_ms = int(round(statistics.median(all_latencies))) if all_latencies else 0
    print(f"Overall Median Chunk Latency: {overall_median_ms} ms (target < {float(os.getenv('CHUNK_SEC', '6.0')) * 1000:.0f} ms)")

    misses = [r for r in rows if not r["passed"]]
    if misses:
        print(f"\nEVAL FAILED: {len(misses)} call(s) missed target criteria.", file=sys.stderr)
        return 1

    print("\nEVAL PASSED: All scam calls reached SCAM and genuine calls remained SAFE.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
