# Saavdhan (સાવધાન / सावधान)

Real-time laptop demo that plays recorded phone calls and warns elderly and first-time smartphone users mid-call when a call is a scam, in simple **Gujarati** or **Hindi**, naming the exact red flags it heard.

Designed for protecting elders alone on **"Digital Arrest"**, **Fake Bank KYC**, or **Fake Courier** scam calls.

---

## Architecture & Files

- `scripts/prep.sh` — Converts `calls/raw/*` to 16 kHz, mono, 16-bit PCM WAV files in `calls/` using `ffmpeg`.
- `app/chunker.py` — Silence-aware chunker targeting `CHUNK_SEC` (default `6.0 s`), placing cuts at the lowest-RMS 20 ms frame within `±1.0 s` of target (min `3.0 s`, merging short tails) and slicing in-memory WAV bytes with `wave`.
- `app/detector.py` — Loads `prompts/detector_system.md` verbatim, calls `client.interactions.create` (`store=False`, `CHUNK_SCHEMA` in strict evidence-before-verdict field order), validates output with Pydantic, and applies deterministic server floor rules.
- `app/main.py` — FastAPI server serving `GET /api/calls`, `POST /api/session`, threadpool `POST /api/analyze`, `/calls/*`, and `static/index.html`.
- `static/index.html` — Dual-pane UI: Elder phone screen with high-contrast ≥28 px Gujarati/Hindi warnings, Web Audio SCAM beep, and localized red-flag chips on the left; Judge console with highlighted transcript, risk meter, chunk timeline, per-chunk latency, and timing lead before first demand on the right.
- `scripts/eval.py` — CLI evaluator that runs all calls (or a single call) through the chunker, detector, and session rules, saves per-chunk outputs to `cache/<call>.json`, prints a summary table, and exits non-zero on any miss.

---

## 1. Setup

```bash
# macOS prerequisites
brew install ffmpeg

# Python virtual environment & dependencies
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Configure API key
cp .env.example .env
# Set GEMINI_API_KEY in .env
```

---

## 2. Audio Prep

Place raw recordings (any format) in `calls/raw/` and run:

```bash
bash scripts/prep.sh
```

This converts every file in `calls/raw/` to 16 kHz mono 16-bit PCM WAV in `calls/`.

---

## 3. CLI Evaluation

Evaluate a single call and print the Gujarati/Hindi transcript:

```bash
python3 scripts/eval.py --call digital_arrest --print-transcript
```

Evaluate all four calls in `calls/manifest.json` and populate `cache/<call>.json`:

```bash
python3 scripts/eval.py
```

Compare models (e.g., `gemini-3.5-flash-lite` vs `gemini-3.8-flash`):

```bash
python3 scripts/eval.py --model gemini-3.5-flash-lite --thinking-level minimal
```

---

## 4. Run the Demo Server

### Live Mode (calls Gemini API as playhead crosses each chunk boundary)

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

### Replay Mode (serves `cache/<call>.json` at recorded latency with REPLAY badge)

```bash
DEMO_REPLAY=1 uvicorn app.main:app --host 0.0.0.0 --port 8000
```
