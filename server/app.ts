/**
 * Express application factory. Dependencies (config, detector, audio converter, clock) are injected
 * so the full HTTP surface can be exercised in tests without network access or ffmpeg.
 */
import { randomUUID } from 'node:crypto';
import { existsSync } from 'node:fs';
import path from 'node:path';
import express, { type ErrorRequestHandler, type Express } from 'express';
import { ZodError, type z } from 'zod';
import { CallCatalog } from './calls.ts';
import type { AppConfig } from './config.ts';
import type { Detector } from './detector.ts';
import { HttpError } from './errors.ts';
import { replayChunk } from './replay.ts';
import { applySessionRules, buildContextBlock, createEmptySession } from './rules.ts';
import { createRateLimiter, noStore, securityHeaders } from './security.ts';
import { SessionStore } from './sessions.ts';
import type { CallMeta, ChunkRecord, ChunkSpan, DetectorResult, SessionState } from './types.ts';
import { type AudioConverter, createFfmpegConverter, storeUpload } from './upload.ts';
import {
  analyzeRequestSchema,
  describeValidationError,
  sessionRequestSchema,
  uploadRequestSchema,
} from './validation.ts';
import { InvalidWavError, sliceWav } from './wav.ts';

const AUDIO_FILE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}\.wav$/;
/** 10 MB of audio is ~13.4 MB once base64-encoded inside JSON. */
const UPLOAD_BODY_LIMIT = '16mb';
const JSON_BODY_LIMIT = '16kb';
const CLIENT_ERROR_MESSAGES: Record<number, string> = {
  404: 'Not found',
  413: 'Request body is too large.',
  415: 'Unsupported request encoding.',
};

interface StoredSession {
  state: SessionState;
  call: CallMeta;
}

type Logger = Pick<Console, 'warn' | 'error'>;

export interface AppDependencies {
  config: AppConfig;
  detector: Detector;
  convertAudio?: AudioConverter;
  sleep?: (ms: number) => Promise<void>;
  logger?: Logger;
}

function parseBody<T>(schema: z.ZodType<T>, body: unknown): T {
  return schema.parse(body ?? {});
}

function clientErrorStatus(error: unknown): number | null {
  if (typeof error !== 'object' || error === null || !('status' in error)) return null;
  const { status } = error;
  return typeof status === 'number' && status >= 400 && status < 500 ? status : null;
}

function errorHandler(logger: Logger): ErrorRequestHandler {
  return (error: unknown, _req, res, next) => {
    if (res.headersSent) {
      next(error);
      return;
    }
    if (error instanceof HttpError) {
      res.status(error.status).json({ detail: error.message });
      return;
    }
    if (error instanceof ZodError) {
      res.status(400).json({ detail: describeValidationError(error) });
      return;
    }
    const status = clientErrorStatus(error);
    if (status !== null) {
      res.status(status).json({ detail: CLIENT_ERROR_MESSAGES[status] ?? 'Malformed request.' });
      return;
    }
    logger.error('[server] Unhandled error', error);
    res.status(500).json({ detail: 'Internal server error' });
  };
}

export function createApp(deps: AppDependencies): Express {
  const { config, detector, logger = console } = deps;
  const convertAudio = deps.convertAudio ?? createFfmpegConverter(config.limits.ffmpegTimeoutMs);
  const sleep =
    deps.sleep ?? ((ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)));
  const catalog = new CallCatalog({
    callsDir: config.paths.calls,
    cacheDir: config.paths.cache,
    manifestPath: config.paths.manifest,
    chunkSec: config.analysis.chunkSec,
    audioCacheEntries: config.limits.audioCacheEntries,
    logger,
  });
  const sessions = new SessionStore<StoredSession>({
    ttlMs: config.limits.sessionTtlMs,
    maxSessions: config.limits.maxSessions,
  });

  async function analyzeLive(stored: StoredSession, span: ChunkSpan): Promise<DetectorResult> {
    let audio: ReturnType<CallCatalog['readAudio']>;
    try {
      audio = catalog.readAudio(stored.call.file);
    } catch (error) {
      if (error instanceof InvalidWavError) {
        throw new HttpError(422, `Audio file is not a valid WAV: ${stored.call.file}`);
      }
      throw error;
    }
    if (!audio) throw new HttpError(404, `Audio file missing: ${stored.call.file}`);

    const wav = sliceWav(audio.buffer, audio.info, span.start_s, span.end_s);
    const context = buildContextBlock(
      span.chunk_index + 1,
      stored.call.chunks.length,
      span.start_s,
      span.end_s,
      stored.state,
    );
    return detector.analyze(wav, context);
  }

  async function analyzeReplay(stored: StoredSession, span: ChunkSpan): Promise<DetectorResult> {
    const callId = stored.call.id;
    let cache: unknown;
    try {
      cache = catalog.readReplayCache(callId);
    } catch {
      throw new HttpError(500, `Replay cache cache/${callId}.json is unreadable.`);
    }
    if (cache === null) {
      throw new HttpError(
        404,
        `Replay cache cache/${callId}.json not found. Run scripts/eval.py first.`,
      );
    }
    const replay = replayChunk(cache, span.chunk_index, config.analysis.maxReplayDelayMs);
    if (!replay) throw new HttpError(404, 'Chunk missing from replay cache');
    await sleep(replay.delayMs);
    return replay.result;
  }

  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', config.server.trustProxy);
  app.use(securityHeaders(config.server.frameAncestors));

  const api = express.Router();
  api.use(noStore);

  api.get('/health', (_req, res) => {
    res.json({ status: 'ok' });
  });

  api.get('/calls', createRateLimiter(config.rateLimits.read), (_req, res) => {
    res.json({
      calls: catalog.list(),
      demo_replay: config.analysis.demoReplay,
      model: config.gemini.model,
    });
  });

  api.post(
    '/upload',
    createRateLimiter(config.rateLimits.upload),
    express.json({ limit: UPLOAD_BODY_LIMIT }),
    async (req, res) => {
      const body = parseBody(uploadRequestSchema, req.body);
      const entry = await storeUpload(body, {
        catalog,
        rawCallsDir: config.paths.rawCalls,
        maxUploadedCalls: config.limits.maxUploadedCalls,
        convert: convertAudio,
        logger,
      });
      res.json({ call: catalog.describe(entry), calls: catalog.list() });
    },
  );

  api.post(
    '/session',
    createRateLimiter(config.rateLimits.session),
    express.json({ limit: JSON_BODY_LIMIT }),
    (req, res) => {
      const { call_id } = parseBody(sessionRequestSchema, req.body);
      const entry = catalog.findEntry(call_id);
      if (!entry) throw new HttpError(404, `Unknown call_id: ${call_id}`);

      const call = catalog.describe(entry);
      const sessionId = randomUUID();
      sessions.set(sessionId, { state: createEmptySession(call.id, sessionId), call });
      res.json({ session_id: sessionId, call });
    },
  );

  api.post(
    '/analyze',
    createRateLimiter(config.rateLimits.analyze),
    express.json({ limit: JSON_BODY_LIMIT }),
    async (req, res) => {
      const body = parseBody(analyzeRequestSchema, req.body);
      const stored = sessions.get(body.session_id);
      if (!stored) throw new HttpError(404, 'Session not found');
      const chunk = stored.call.chunks[body.chunk_index];
      if (!chunk) throw new HttpError(400, `Invalid chunk_index ${body.chunk_index}`);

      // Serialized per session: the context block for chunk N must include chunks 0..N-1.
      const record = await sessions.runExclusive(
        body.session_id,
        async (): Promise<ChunkRecord> => {
          const existing = stored.state.chunks.find((item) => item.chunk_index === chunk.index);
          if (existing) return existing;

          const span = { chunk_index: chunk.index, start_s: chunk.start_s, end_s: chunk.end_s };
          const useReplay = body.replay ?? config.analysis.demoReplay;
          const result = useReplay
            ? await analyzeReplay(stored, span)
            : await analyzeLive(stored, span);
          const processed = applySessionRules(stored.state, span, result);
          processed.mode = useReplay ? 'REPLAY' : 'LIVE';
          return processed;
        },
      );
      res.json({ chunk: record, session: stored.state });
    },
  );

  api.use((_req, res) => {
    res.status(404).json({ detail: 'Not found' });
  });
  app.use('/api', api);

  // Only top-level call recordings are served; raw uploads and the manifest stay private.
  app.get('/calls/:file', (req, res) => {
    const { file } = req.params;
    const filePath = catalog.wavPath(file);
    if (!AUDIO_FILE_PATTERN.test(file) || !existsSync(filePath)) {
      throw new HttpError(404, 'Call audio not found');
    }
    res.sendFile(filePath, { headers: { 'Content-Type': 'audio/wav' } });
  });

  app.use('/static', express.static(config.paths.static, { index: false }));
  app.get('/', (_req, res) => {
    res.sendFile(path.join(config.paths.static, 'index.html'));
  });

  app.use(errorHandler(logger));
  return app;
}
