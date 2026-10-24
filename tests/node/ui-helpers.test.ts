/** Unit tests for the browser modules that have no DOM dependencies. */
import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { RED_FLAG_TYPES } from '../../server/types.ts';
import { ApiError, api, request } from '../../static/js/api.js';
import {
  analysisLag,
  arrayBufferToBase64,
  chunksReadyToSend,
  describeChunkState,
  detectScriptLang,
  formatClock,
  formatPaddedClock,
  formatSpan,
  hasWavHeader,
  highlightSegments,
  MAX_WAV_BYTES,
  validateWavFile,
  warningLead,
} from '../../static/js/helpers.js';
import { CHIP_LABELS, flagsHeading, speechLocale, VERDICT_BADGES } from '../../static/js/i18n.js';

describe('formatting', () => {
  test('clocks', () => {
    assert.equal(formatClock(75.4), '1:15');
    assert.equal(formatClock(-3), '0:00');
    assert.equal(formatPaddedClock(75.9), '01:15');
    assert.equal(formatPaddedClock(Number.NaN), '00:00');
    assert.equal(formatSpan(0, 6.18), '0.0s–6.2s');
  });
});

describe('validateWavFile', () => {
  test('mirrors the server-side upload checks', () => {
    assert.match(validateWavFile(null) ?? '', /select a \.wav/);
    assert.match(validateWavFile({ name: 'a.mp3', size: 1000 }) ?? '', /Only \.wav/);
    assert.match(validateWavFile({ name: 'a.wav', size: 44 }) ?? '', /empty or corrupted/);
    assert.match(validateWavFile({ name: 'a.wav', size: MAX_WAV_BYTES + 1 }) ?? '', /10 MB/);
    assert.equal(validateWavFile({ name: 'A.WAV', size: 2048 }), null);
  });

  test('hasWavHeader checks the RIFF/WAVE magic', () => {
    assert.equal(hasWavHeader(new TextEncoder().encode('RIFF\0\0\0\0WAVEfmt ')), true);
    assert.equal(hasWavHeader(new TextEncoder().encode('ID3\u0003 not audio')), false);
    assert.equal(hasWavHeader(new Uint8Array(4)), false);
  });

  test('arrayBufferToBase64 handles payloads larger than one slice', () => {
    const bytes = new Uint8Array(100_000).map((_, i) => i % 256);
    assert.equal(arrayBufferToBase64(bytes.buffer), Buffer.from(bytes).toString('base64'));
  });
});

describe('highlightSegments', () => {
  test('marks red-flag and genuine quotes without overlaps', () => {
    const segments = highlightSegments(
      'Send OTP now. Visit the branch. Send OTP now.',
      ['Send OTP now', 'OTP'],
      ['Visit the branch', 'OTP now'],
    );
    assert.deepEqual(segments, [
      { text: 'Send OTP now', kind: 'flag' },
      { text: '. ', kind: 'plain' },
      { text: 'Visit the branch', kind: 'genuine' },
      { text: '. ', kind: 'plain' },
      { text: 'Send OTP now', kind: 'flag' },
      { text: '.', kind: 'plain' },
    ]);
  });

  test('treats quotes as plain text, never markup', () => {
    const segments = highlightSegments('<img src=x onerror=alert(1)>', ['<img'], []);
    assert.deepEqual(segments[0], { text: '<img', kind: 'flag' });
  });

  test('returns one plain segment when nothing matches', () => {
    assert.deepEqual(highlightSegments('', [''], []), [{ text: '', kind: 'plain' }]);
    assert.deepEqual(highlightSegments('hello', ['bye'], []), [{ text: 'hello', kind: 'plain' }]);
  });
});

describe('playback gating', () => {
  const chunks = [
    { index: 0, end_s: 6 },
    { index: 1, end_s: 12 },
    { index: 2, end_s: 15 },
  ];

  test('releases only chunks whose audio has fully played', () => {
    assert.deepEqual(chunksReadyToSend(chunks, 5.9, new Set(), false), []);
    assert.deepEqual(chunksReadyToSend(chunks, 12.1, new Set([0]), false), [1]);
  });

  test('releases the final chunk when playback ends', () => {
    assert.deepEqual(chunksReadyToSend(chunks, 14.98, new Set([0, 1]), true), [2]);
  });

  test('measures how far analysis trails the playhead', () => {
    assert.equal(analysisLag(10, [{ end_s: 6 }]), 4);
    assert.equal(analysisLag(5, [{ end_s: 6 }]), 0);
  });

  test('computes the warning lead over the first demand', () => {
    assert.equal(warningLead(11.5, 24.1), 12.6);
    assert.equal(warningLead(30, 24.1), -5.9);
    assert.equal(warningLead(null, 24.1), null);
  });
});

describe('describeChunkState', () => {
  test('summarises analysed, failed, queued and pending chunks', () => {
    const done = { status: 'ok', verdict: 'SCAM', risk_score: 75, latency_ms: 420 };
    assert.deepEqual(describeChunkState(done, { queued: false, analyzing: false }), {
      verdict: 'SCAM',
      label: 'SCAM (75)',
      latency: '420 ms',
    });
    const failed = { ...done, status: 'unavailable', verdict: 'unavailable' };
    assert.equal(describeChunkState(failed, { queued: false, analyzing: false }).label, 'UNAVAIL');
    assert.equal(
      describeChunkState(undefined, { queued: true, analyzing: true }).label,
      'Analyzing…',
    );
    assert.equal(describeChunkState(undefined, { queued: true, analyzing: false }).label, 'Queued');
    assert.equal(
      describeChunkState(undefined, { queued: false, analyzing: false }).verdict,
      'pending',
    );
  });
});

describe('i18n', () => {
  test('every red-flag type has Gujarati and Hindi chip labels', () => {
    for (const type of RED_FLAG_TYPES) {
      const label = CHIP_LABELS[type];
      assert.ok(label?.gu && label.hi && label.tone, type);
    }
    for (const badge of Object.values(VERDICT_BADGES)) assert.ok(badge.gu && badge.hi);
  });

  test('language helpers', () => {
    assert.match(flagsHeading('gu', 2), /\(2\)$/);
    assert.match(flagsHeading('hi', 0), /\(0\)$/);
    assert.equal(speechLocale('gu'), 'gu-IN');
    assert.equal(speechLocale('hi'), 'hi-IN');
    assert.equal(detectScriptLang('તમારો OTP'), 'gu');
    assert.equal(detectScriptLang('मैं सीबीआई से'), 'hi');
    assert.equal(detectScriptLang('OTP please'), undefined);
  });
});

describe('api request', () => {
  const fakeFetch =
    (response: Response | Error): typeof fetch =>
    async () => {
      if (response instanceof Error) throw response;
      return response;
    };

  test('returns parsed JSON and sends JSON bodies', async () => {
    let sent: RequestInit | undefined;
    const data = await request('/api/session', {
      method: 'POST',
      body: { call_id: 'x' },
      fetchImpl: async (_url, init) => {
        sent = init;
        return Response.json({ ok: true });
      },
    });
    assert.deepEqual(data, { ok: true });
    assert.equal(sent?.body, '{"call_id":"x"}');
  });

  test('surfaces the server detail on errors', async () => {
    const response = Response.json({ detail: 'Session not found' }, { status: 404 });
    await assert.rejects(request('/x', { fetchImpl: fakeFetch(response) }), (error: unknown) => {
      assert.ok(error instanceof ApiError);
      assert.equal(error.status, 404);
      assert.equal(error.message, 'Session not found');
      return true;
    });
    const html = new Response('<html>', { status: 502 });
    await assert.rejects(request('/x', { fetchImpl: fakeFetch(html) }), /HTTP 502/);
  });

  test('endpoint wrappers call the documented routes', async () => {
    const seen: { url: string; method: string; body: unknown }[] = [];
    const realFetch = globalThis.fetch;
    globalThis.fetch = async (url, init) => {
      seen.push({
        url: String(url),
        method: init?.method ?? 'GET',
        body: init?.body ? JSON.parse(String(init.body)) : undefined,
      });
      return Response.json({});
    };
    try {
      await api.listCalls();
      await api.createSession('fake_kyc');
      await api.analyzeChunk('sid', 2, true);
      await api.uploadWav({ filename: 'a.wav', data_base64: 'AAAA', expected: 'SCAM' });
    } finally {
      globalThis.fetch = realFetch;
    }
    assert.deepEqual(seen, [
      { url: '/api/calls', method: 'GET', body: undefined },
      { url: '/api/session', method: 'POST', body: { call_id: 'fake_kyc' } },
      {
        url: '/api/analyze',
        method: 'POST',
        body: { session_id: 'sid', chunk_index: 2, replay: true },
      },
      {
        url: '/api/upload',
        method: 'POST',
        body: { filename: 'a.wav', data_base64: 'AAAA', expected: 'SCAM' },
      },
    ]);
  });

  test('aborts requests that exceed their timeout', async () => {
    const hang: typeof fetch = (_url, init) =>
      new Promise((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () =>
          reject(Object.assign(new Error('aborted'), { name: 'AbortError' })),
        );
      });
    await assert.rejects(request('/slow', { fetchImpl: hang, timeoutMs: 10 }), /took too long/);
  });

  test('reports timeouts and network failures readably', async () => {
    const abort = Object.assign(new Error('aborted'), { name: 'AbortError' });
    await assert.rejects(request('/x', { fetchImpl: fakeFetch(abort) }), /took too long/);
    await assert.rejects(
      request('/x', { fetchImpl: fakeFetch(new TypeError('fetch failed')) }),
      /Network error/,
    );
  });
});
