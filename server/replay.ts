/**
 * Replay mode: serves results recorded by scripts/eval.py (cache/<call>.json) instead of calling
 * Gemini, so the demo works offline. Raw model output is re-run through the same session rules.
 */
import type { DetectorResult } from './types.ts';
import { chunkAnalysisSchema } from './validation.ts';

const MIN_REPLAY_DELAY_MS = 80;
const DEFAULT_REPLAY_LATENCY_MS = 350;

export interface ReplayChunk {
  result: DetectorResult;
  /** Recorded latency, clamped so playback stays responsive. */
  delayMs: number;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function text(value: unknown): string {
  return typeof value === 'string' ? value : '';
}

/** Returns null when the cache has no entry for this chunk. */
export function replayChunk(
  cache: unknown,
  chunkIndex: number,
  maxDelayMs: number,
): ReplayChunk | null {
  if (!isRecord(cache) || !Array.isArray(cache.chunks)) return null;
  const raw: unknown = cache.chunks[chunkIndex];
  if (!isRecord(raw)) return null;

  const recorded = typeof raw.latency_ms === 'number' && raw.latency_ms > 0 ? raw.latency_ms : 0;
  const delayMs = Math.min(
    maxDelayMs,
    Math.max(MIN_REPLAY_DELAY_MS, recorded || DEFAULT_REPLAY_LATENCY_MS),
  );
  const latency_ms = recorded || delayMs;
  const model = text(raw.model) || text(cache.model) || 'replay';

  if (raw.status === 'unavailable') {
    const error = text(raw.error) || 'Analysis unavailable';
    return { delayMs, result: { status: 'unavailable', error, latency_ms, model } };
  }

  const parsed = chunkAnalysisSchema.safeParse({
    transcript: raw.raw_transcript ?? raw.transcript ?? [],
    new_red_flags: raw.raw_new_red_flags ?? raw.new_red_flags ?? [],
    new_genuine_signals: raw.raw_new_genuine_signals ?? raw.new_genuine_signals ?? [],
    scam_type: raw.scam_type ?? 'NONE',
    risk_score: raw.model_risk_score ?? raw.risk_score ?? 0,
    verdict: raw.verdict ?? 'SAFE',
    warning_gu: raw.warning_gu ?? '',
    warning_hi: raw.warning_hi ?? '',
    warning_en: raw.warning_en ?? '',
  });
  if (!parsed.success) {
    const error = 'Replay cache entry is invalid';
    return { delayMs, result: { status: 'unavailable', error, latency_ms, model } };
  }
  return { delayMs, result: { status: 'ok', latency_ms, model, ...parsed.data } };
}
