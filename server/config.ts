/**
 * Typed runtime configuration for the Node server, resolved once from environment variables.
 * Every limit that protects the server (body sizes, rate limits, session caps) lives here.
 */
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const ROOT_DIR = fileURLToPath(new URL('..', import.meta.url));

export const THINKING_LEVELS = ['minimal', 'low', 'medium', 'high'] as const;
export type ThinkingLevel = (typeof THINKING_LEVELS)[number];

/** Latency-first default for the live demo; the eval CLI (Python) defaults to gemini-3.8-flash. */
export const DEFAULT_MODEL = 'gemini-3.5-flash-lite';
/** Model retried once when the preferred model errors or times out. */
export const FALLBACK_MODEL = 'gemini-3.5-flash-lite';
export const PLACEHOLDER_API_KEY = 'MY_GEMINI_API_KEY';

export const MIN_CHUNK_SEC = 3;
export const MAX_UPLOAD_BYTES = 10 * 1024 * 1024;

export interface RateLimitRule {
  windowMs: number;
  limit: number;
}

export interface AppConfig {
  paths: {
    root: string;
    calls: string;
    rawCalls: string;
    cache: string;
    static: string;
    manifest: string;
    prompt: string;
  };
  server: {
    port: number;
    host: string;
    /** Number of reverse-proxy hops to trust for client IPs (Cloud Run / AI Studio = 1). */
    trustProxy: number;
    /** CSP frame-ancestors allow-list; null leaves embedding unrestricted (AI Studio preview iframe). */
    frameAncestors: string[] | null;
  };
  gemini: {
    apiKey: string | null;
    model: string;
    fallbackModel: string;
    thinkingLevel: ThinkingLevel;
    timeoutMs: number;
  };
  analysis: {
    chunkSec: number;
    demoReplay: boolean;
    maxReplayDelayMs: number;
  };
  limits: {
    maxUploadBytes: number;
    maxUploadedCalls: number;
    sessionTtlMs: number;
    maxSessions: number;
    ffmpegTimeoutMs: number;
    audioCacheEntries: number;
  };
  rateLimits: {
    read: RateLimitRule;
    session: RateLimitRule;
    analyze: RateLimitRule;
    upload: RateLimitRule;
  };
}

type Env = Readonly<Record<string, string | undefined>>;

function readString(value: string | undefined, fallback: string): string {
  const trimmed = value?.trim();
  return trimmed ? trimmed : fallback;
}

function readNumber(value: string | undefined, fallback: number, min: number, max: number): number {
  if (value === undefined || value.trim() === '') return fallback;
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, parsed));
}

function readThinkingLevel(value: string | undefined, model: string): ThinkingLevel {
  const candidate = value?.trim().toLowerCase();
  if (THINKING_LEVELS.some((level) => level === candidate)) return candidate as ThinkingLevel;
  return model.includes('3.8-flash') ? 'low' : 'minimal';
}

function readApiKey(value: string | undefined): string | null {
  const key = value?.trim();
  return key && key !== PLACEHOLDER_API_KEY ? key : null;
}

function readList(value: string | undefined): string[] | null {
  const items = (value ?? '').split(/[\s,]+/).filter(Boolean);
  return items.length > 0 ? items : null;
}

export function loadConfig(env: Env = process.env, rootDir: string = ROOT_DIR): AppConfig {
  const callsDir = path.join(rootDir, 'calls');
  const model = readString(env.MODEL, DEFAULT_MODEL);

  return {
    paths: {
      root: rootDir,
      calls: callsDir,
      rawCalls: path.join(callsDir, 'raw'),
      cache: path.join(rootDir, 'cache'),
      static: path.join(rootDir, 'static'),
      manifest: path.join(callsDir, 'manifest.json'),
      prompt: path.join(rootDir, 'prompts', 'detector_system.md'),
    },
    server: {
      port: readNumber(env.PORT, 3000, 0, 65_535),
      host: readString(env.HOST, '0.0.0.0'),
      trustProxy: readNumber(env.TRUST_PROXY, 1, 0, 10),
      frameAncestors: readList(env.FRAME_ANCESTORS),
    },
    gemini: {
      apiKey: readApiKey(env.GEMINI_API_KEY),
      model,
      fallbackModel: FALLBACK_MODEL,
      thinkingLevel: readThinkingLevel(env.THINKING_LEVEL, model),
      timeoutMs: 12_000,
    },
    analysis: {
      chunkSec: readNumber(env.CHUNK_SEC, 6, MIN_CHUNK_SEC, 30),
      demoReplay: env.DEMO_REPLAY === '1',
      maxReplayDelayMs: 1_200,
    },
    limits: {
      maxUploadBytes: MAX_UPLOAD_BYTES,
      maxUploadedCalls: 20,
      sessionTtlMs: 30 * 60 * 1000,
      maxSessions: 1_000,
      ffmpegTimeoutMs: 30_000,
      audioCacheEntries: 8,
    },
    rateLimits: {
      read: { windowMs: 60_000, limit: 120 },
      session: { windowMs: 60_000, limit: 60 },
      analyze: { windowMs: 60_000, limit: 120 },
      upload: { windowMs: 15 * 60_000, limit: 10 },
    },
  };
}
