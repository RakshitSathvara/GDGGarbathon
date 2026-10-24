#!/usr/bin/env bash
set -euo pipefail

# Convert all recordings in calls/raw/* to 16 kHz mono 16-bit PCM WAV in calls/
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
RAW_DIR="$ROOT_DIR/calls/raw"
OUT_DIR="$ROOT_DIR/calls"

mkdir -p "$RAW_DIR" "$OUT_DIR"

shopt -s nullglob
files=("$RAW_DIR"/*)
if [ ${#files[@]} -eq 0 ]; then
  echo "No files found in $RAW_DIR"
  exit 0
fi

for src in "${files[@]}"; do
  base="$(basename "$src")"
  name="${base%.*}"
  dest="$OUT_DIR/${name}.wav"
  echo "Converting $base -> calls/${name}.wav (16kHz mono 16-bit PCM)..."
  ffmpeg -y -hide_banner -loglevel error \
    -i "$src" \
    -ar 16000 \
    -ac 1 \
    -c:a pcm_s16le \
    "$dest"
done

echo "Done preparing $(ls -1 "$OUT_DIR"/*.wav 2>/dev/null | wc -l | tr -d ' ') WAV files in $OUT_DIR."
