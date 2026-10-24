/** HTTP integration tests: the real Express app on an ephemeral port with a scripted detector. */
import assert from 'node:assert/strict';
import { copyFileSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { after, before, describe, test } from 'node:test';
import { createApp } from '../../server/app.ts';
import type { AppConfig } from '../../server/config.ts';
import type { Detector } from '../../server/detector.ts';
import type { DetectorResult } from '../../server/types.ts';
import {
  analysis,
  createTempProject,
  makeWav,
  scriptedDetector,
  silentLogger,
  startServer,
} from './support.ts';

const SCAM_CHUNK: DetectorResult = {
  status: 'ok',
  latency_ms: 400,
  model: 'test-model',
  ...analysis({
    transcript: [{ speaker: 'CALLER', text: 'તમારો OTP આપો' }],
    new_red_flags: [{ type: 'OTP_OR_CREDENTIALS', quote: 'તમારો OTP આપો', why: 'OTP' }],
    scam_type: 'FAKE_KYC',
    risk_score: 40,
    verdict: 'SUSPICIOUS',
  }),
};
const CALM_CHUNK: DetectorResult = {
  status: 'ok',
  latency_ms: 300,
  model: 'test-model',
  ...analysis({ transcript: [{ speaker: 'CALLER', text: 'નમસ્તે' }], risk_score: 10 }),
};

interface Harness {
  url: string;
  config: AppConfig;
  calls: { contextBlock: string }[];
  close(): Promise<void>;
}

async function harness(
  options: {
    env?: Record<string, string>;
    detector?: Detector;
    tweak?: (c: AppConfig) => void;
  } = {},
): Promise<Harness> {
  const project = createTempProject(['fake_kyc.wav'], options.env);
  options.tweak?.(project.config);
  const scripted = scriptedDetector((chunk) => (chunk === 2 ? SCAM_CHUNK : CALM_CHUNK));
  const app = createApp({
    config: project.config,
    detector: options.detector ?? scripted.detector,
    convertAudio: async (input, output) => copyFileSync(input, output),
    sleep: async () => {},
    logger: silentLogger,
  });
  const server = await startServer(app);
  return {
    url: server.url,
    config: project.config,
    calls: scripted.calls,
    async close() {
      await server.close();
      project.cleanup();
    },
  };
}

const json = (body: unknown) => ({
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(body),
});

interface ChunkBody {
  chunk: {
    verdict: string;
    mode: string;
    model: string;
    risk_score: number;
    model_risk_score: number;
  };
  session: { verdict: string; warning_gu: string };
}
interface CallsBody {
  calls: { id: string; title: string; chunks: unknown[] }[];
  demo_replay: boolean;
}
interface UploadBody {
  call: { id: string; title: string };
  calls: unknown[];
}
interface ErrorBody {
  detail: string;
}

async function readJson<T>(response: Response | Promise<Response>): Promise<T> {
  return (await (await response).json()) as T;
}

async function newSession(url: string, callId = 'fake_kyc') {
  const response = await fetch(`${url}/api/session`, json({ call_id: callId }));
  assert.equal(response.status, 200);
  return (await response.json()) as { session_id: string; call: { chunks: unknown[] } };
}

describe('API', () => {
  let h: Harness;
  before(async () => {
    h = await harness();
  });
  after(() => h.close());

  test('GET /api/health and /api/calls', async () => {
    assert.deepEqual(await readJson(fetch(`${h.url}/api/health`)), { status: 'ok' });
    const body = await readJson<CallsBody>(fetch(`${h.url}/api/calls`));
    assert.equal(body.calls.length, 1);
    assert.equal(body.calls[0]?.id, 'fake_kyc');
    assert.equal(body.calls[0]?.chunks.length, 4);
    assert.equal(body.demo_replay, false);
  });

  test('live analysis applies the server rules and feeds context forward', async () => {
    const { session_id } = await newSession(h.url);
    const first = await readJson<ChunkBody>(
      fetch(`${h.url}/api/analyze`, json({ session_id, chunk_index: 0 })),
    );
    assert.equal(first.chunk.verdict, 'SAFE');
    assert.equal(first.chunk.mode, 'LIVE');

    const second = await readJson<ChunkBody>(
      fetch(`${h.url}/api/analyze`, json({ session_id, chunk_index: 1 })),
    );
    assert.equal(second.chunk.model_risk_score, 40);
    assert.equal(second.chunk.risk_score, 75);
    assert.equal(second.session.verdict, 'SCAM');
    assert.match(second.session.warning_gu, /તમારો OTP આપો/);
    assert.match(h.calls.at(-1)?.contextBlock ?? '', /CALL SO FAR:\nCALLER: નમસ્તે/);
  });

  test('re-requesting a chunk returns the stored result without re-analysis', async () => {
    const { session_id } = await newSession(h.url);
    const before = h.calls.length;
    const [a, b] = await Promise.all([
      readJson<ChunkBody>(fetch(`${h.url}/api/analyze`, json({ session_id, chunk_index: 0 }))),
      readJson<ChunkBody>(fetch(`${h.url}/api/analyze`, json({ session_id, chunk_index: 0 }))),
    ]);
    assert.deepEqual(a.chunk, b.chunk);
    assert.equal(h.calls.length, before + 1);
  });

  test('validates requests', async () => {
    const { session_id } = await newSession(h.url);
    const cases: [unknown, number, RegExp][] = [
      [{ session_id, chunk_index: 99 }, 400, /Invalid chunk_index 99/],
      [{ session_id, chunk_index: -1 }, 400, /chunk_index/],
      [{ session_id: 'not-a-uuid', chunk_index: 0 }, 400, /session_id/],
      [{ session_id: crypto.randomUUID(), chunk_index: 0 }, 404, /Session not found/],
    ];
    for (const [body, status, detail] of cases) {
      const response = await fetch(`${h.url}/api/analyze`, json(body));
      assert.equal(response.status, status, JSON.stringify(body));
      assert.match((await readJson<ErrorBody>(response)).detail, detail);
    }
    const unknown = await fetch(`${h.url}/api/session`, json({ call_id: 'nope' }));
    assert.equal(unknown.status, 404);
    const malformed = await fetch(`${h.url}/api/session`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{bad',
    });
    assert.equal(malformed.status, 400);
    const huge = await fetch(`${h.url}/api/session`, json({ call_id: 'x'.repeat(20_000) }));
    assert.equal(huge.status, 413);
    const missing = await fetch(`${h.url}/api/nope`);
    assert.equal(missing.status, 404);
  });

  test('uploads become playable calls', async () => {
    const wav = makeWav([{ seconds: 7, amplitude: 3000 }]);
    const response = await fetch(
      `${h.url}/api/upload`,
      json({ filename: 'Grandpa.wav', data_base64: wav.toString('base64'), title: 'Grandpa' }),
    );
    assert.equal(response.status, 200);
    const body = await readJson<UploadBody>(response);
    assert.equal(body.call.id, 'upload_grandpa');
    assert.equal(body.call.title, 'Grandpa');
    assert.equal(body.calls.length, 2);
    const audio = await fetch(`${h.url}/calls/upload_grandpa.wav`);
    assert.equal(audio.status, 200);

    const bad = await fetch(`${h.url}/api/upload`, json({ filename: 'x.wav', data_base64: '!!' }));
    assert.equal(bad.status, 400);
  });

  test('serves only top-level call recordings and the static app', async () => {
    const audio = await fetch(`${h.url}/calls/fake_kyc.wav`);
    assert.equal(audio.status, 200);
    assert.equal(audio.headers.get('content-type'), 'audio/wav');
    for (const blocked of [
      '/calls/manifest.json',
      '/calls/raw',
      '/calls/..%2Fpackage.json',
      '/calls/missing.wav',
    ]) {
      assert.equal((await fetch(`${h.url}${blocked}`)).status, 404, blocked);
    }
    const index = await fetch(`${h.url}/`);
    assert.match(await index.text(), /<h1 class="brand">/);
    const script = await fetch(`${h.url}/static/js/app.js`);
    assert.match(script.headers.get('content-type') ?? '', /javascript/);
  });

  test('sends security headers and no-store on API responses', async () => {
    const page = await fetch(`${h.url}/`);
    const csp = page.headers.get('content-security-policy') ?? '';
    assert.match(csp, /default-src 'self'/);
    assert.match(csp, /script-src 'self'/);
    assert.match(csp, /object-src 'none'/);
    assert.doesNotMatch(csp, /unsafe-inline/);
    assert.equal(page.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(page.headers.get('x-powered-by'), null);
    assert.match(page.headers.get('permissions-policy') ?? '', /microphone=\(\)/);
    const api = await fetch(`${h.url}/api/calls`);
    assert.equal(api.headers.get('cache-control'), 'no-store');
  });
});

describe('replay mode', () => {
  let h: Harness;
  before(async () => {
    h = await harness({ env: { DEMO_REPLAY: '1' } });
  });
  after(() => h.close());

  test('serves cached raw output through the same rules', async () => {
    const cachePath = path.join(h.config.paths.cache, 'fake_kyc.json');
    writeFileSync(
      cachePath,
      JSON.stringify({
        model: 'recorded-model',
        chunks: [
          {
            ...analysis({ risk_score: 20 }),
            raw_new_red_flags: [{ type: 'SECRECY', quote: 'shh', why: 'x' }],
          },
        ],
      }),
    );
    const { session_id } = await newSession(h.url);
    const body = await readJson<ChunkBody>(
      fetch(`${h.url}/api/analyze`, json({ session_id, chunk_index: 0 })),
    );
    assert.equal(body.chunk.mode, 'REPLAY');
    assert.equal(body.chunk.model, 'recorded-model');
    assert.equal(body.chunk.risk_score, 75);
    assert.equal(h.calls.length, 0);

    const missingChunk = await fetch(`${h.url}/api/analyze`, json({ session_id, chunk_index: 3 }));
    assert.equal(missingChunk.status, 404);
    writeFileSync(cachePath, '{corrupt');
    const corrupt = await fetch(`${h.url}/api/analyze`, json({ session_id, chunk_index: 2 }));
    assert.equal(corrupt.status, 500);
  });

  test('explains how to create a missing cache', async () => {
    rmSync(path.join(h.config.paths.cache, 'fake_kyc.json'), { force: true });
    const { session_id } = await newSession(h.url);
    const response = await fetch(
      `${h.url}/api/analyze`,
      json({ session_id, chunk_index: 1, replay: true }),
    );
    assert.equal(response.status, 404);
    assert.match((await readJson<ErrorBody>(response)).detail, /Run scripts\/eval\.py/);
  });
});

describe('hardening', () => {
  test('rate limits each client per endpoint', async () => {
    const h = await harness({
      tweak: (config) => (config.rateLimits.read = { windowMs: 60_000, limit: 2 }),
    });
    try {
      const statuses = [];
      for (let i = 0; i < 3; i++) statuses.push((await fetch(`${h.url}/api/calls`)).status);
      assert.deepEqual(statuses, [200, 200, 429]);
    } finally {
      await h.close();
    }
  });

  test('restricts framing when FRAME_ANCESTORS is set', async () => {
    const h = await harness({ env: { FRAME_ANCESTORS: "'self' https://aistudio.google.com" } });
    try {
      const csp = (await fetch(`${h.url}/`)).headers.get('content-security-policy') ?? '';
      assert.match(csp, /frame-ancestors 'self' https:\/\/aistudio\.google\.com/);
    } finally {
      await h.close();
    }
  });

  test('hides unexpected errors behind a generic 500', async () => {
    const detector: Detector = {
      async analyze() {
        throw new Error('database password is hunter2');
      },
    };
    const h = await harness({ detector });
    try {
      const { session_id } = await newSession(h.url);
      const response = await fetch(`${h.url}/api/analyze`, json({ session_id, chunk_index: 0 }));
      assert.equal(response.status, 500);
      assert.deepEqual(await readJson(response), { detail: 'Internal server error' });
    } finally {
      await h.close();
    }
  });

  test('rejects audio files that cannot be decoded', async () => {
    const h = await harness();
    try {
      const { session_id } = await newSession(h.url);
      writeFileSync(path.join(h.config.paths.calls, 'fake_kyc.wav'), 'garbage');
      const response = await fetch(`${h.url}/api/analyze`, json({ session_id, chunk_index: 0 }));
      assert.equal(response.status, 422);
    } finally {
      await h.close();
    }
  });
});
