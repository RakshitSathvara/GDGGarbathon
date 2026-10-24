"""Runtime settings for the Python backend, resolved once from environment variables."""

from __future__ import annotations

import os
import re
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
SHARED_DIR = ROOT_DIR / "shared"

DEFAULT_MODEL = "gemini-3.8-flash"
DEFAULT_THINKING_LEVEL = "low"
DEFAULT_CHUNK_SEC = 6.0
MIN_CHUNK_SEC = 3.0
MAX_CHUNK_SEC = 30.0
MAX_UPLOAD_BYTES = 10 * 1024 * 1024
PLACEHOLDER_API_KEY = "MY_GEMINI_API_KEY"


@dataclass(frozen=True)
class RateLimit:
    """Allow at most `limit` requests per client IP in any rolling `window_s` seconds."""

    limit: int
    window_s: float


@dataclass(frozen=True)
class Settings:
    calls_dir: Path
    raw_calls_dir: Path
    tmp_calls_dir: Path
    cache_dir: Path
    static_dir: Path
    manifest_path: Path
    demo_replay: bool
    model: str
    chunk_sec: float
    frame_ancestors: tuple[str, ...] | None
    max_upload_bytes: int = MAX_UPLOAD_BYTES
    max_uploaded_calls: int = 20
    session_ttl_s: float = 30 * 60
    max_sessions: int = 1_000
    ffmpeg_timeout_s: float = 30.0
    max_replay_delay_s: float = 1.2
    read_limit: RateLimit = RateLimit(limit=120, window_s=60)
    session_limit: RateLimit = RateLimit(limit=60, window_s=60)
    analyze_limit: RateLimit = RateLimit(limit=120, window_s=60)
    upload_limit: RateLimit = RateLimit(limit=10, window_s=15 * 60)

    @property
    def tmp_manifest_path(self) -> Path:
        """Manifest copy used when calls/ is read-only (e.g. Vercel serverless)."""
        return self.tmp_calls_dir / "manifest.json"


def chunk_sec_from_env(env: Mapping[str, str] | None = None) -> float:
    """CHUNK_SEC clamped to [3, 30] s; invalid values fall back to 6 s."""
    raw = (os.environ if env is None else env).get("CHUNK_SEC", "")
    try:
        value = float(raw) if raw.strip() else DEFAULT_CHUNK_SEC
    except ValueError:
        return DEFAULT_CHUNK_SEC
    return min(MAX_CHUNK_SEC, max(MIN_CHUNK_SEC, value))


def api_key_from_env(env: Mapping[str, str] | None = None) -> str | None:
    key = (os.environ if env is None else env).get("GEMINI_API_KEY", "").strip()
    return key if key and key != PLACEHOLDER_API_KEY else None


def load_settings(env: Mapping[str, str] | None = None, root_dir: Path = ROOT_DIR) -> Settings:
    env = os.environ if env is None else env
    calls_dir = root_dir / "calls"
    ancestors = tuple(item for item in re.split(r"[\s,]+", env.get("FRAME_ANCESTORS", "")) if item)
    return Settings(
        calls_dir=calls_dir,
        raw_calls_dir=calls_dir / "raw",
        tmp_calls_dir=Path(tempfile.gettempdir()) / "saavdhan_calls",
        cache_dir=root_dir / "cache",
        static_dir=root_dir / "static",
        manifest_path=calls_dir / "manifest.json",
        demo_replay=env.get("DEMO_REPLAY", "0") == "1",
        model=env.get("MODEL", "").strip() or DEFAULT_MODEL,
        chunk_sec=chunk_sec_from_env(env),
        frame_ancestors=ancestors or None,
    )
