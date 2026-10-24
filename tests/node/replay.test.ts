import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { replayChunk } from '../../server/replay.ts';
import { analysis } from './support.ts';

const turn = { speaker: 'CALLER', text: 'raw' };

describe('replayChunk', () => {
  test('prefers raw model output over processed fields', () => {
    const cache = {
      model: 'cached-model',
      chunks: [
        {
          ...analysis({ risk_score: 75, verdict: 'SCAM' }),
          model_risk_score: 40,
          latency_ms: 420,
          transcript: [{ speaker: 'CALLER', text: 'processed', chunk_index: 0 }],
          raw_transcript: [turn],
          raw_new_red_flags: [{ type: 'OTP_OR_CREDENTIALS', quote: 'OTP', why: 'asks' }],
        },
      ],
    };
    const replay = replayChunk(cache, 0, 1_200);
    assert.ok(replay);
    assert.equal(replay.delayMs, 420);
    assert.equal(replay.result.status, 'ok');
    if (replay.result.status !== 'ok') return;
    assert.equal(replay.result.model, 'cached-model');
    assert.equal(replay.result.risk_score, 40);
    assert.deepEqual(replay.result.transcript, [turn]);
    assert.equal(replay.result.new_red_flags.length, 1);
  });

  test('clamps the simulated latency', () => {
    const fast = replayChunk({ chunks: [{ ...analysis(), latency_ms: 5 }] }, 0, 1_200);
    const slow = replayChunk({ chunks: [{ ...analysis(), latency_ms: 9_000 }] }, 0, 1_200);
    const unknown = replayChunk({ chunks: [analysis()] }, 0, 1_200);
    assert.equal(fast?.delayMs, 80);
    assert.equal(slow?.delayMs, 1_200);
    assert.equal(unknown?.delayMs, 350);
    assert.equal(unknown?.result.latency_ms, 350);
    assert.equal(unknown?.result.model, 'replay');
  });

  test('passes recorded failures through as unavailable', () => {
    const replay = replayChunk({ chunks: [{ status: 'unavailable', error: 'timeout' }] }, 0, 1_200);
    assert.deepEqual(replay?.result, {
      status: 'unavailable',
      error: 'timeout',
      latency_ms: 350,
      model: 'replay',
    });
    const anonymous = replayChunk({ chunks: [{ status: 'unavailable' }] }, 0, 1_200);
    assert.equal(
      anonymous?.result.status === 'unavailable' && anonymous.result.error,
      'Analysis unavailable',
    );
  });

  test('marks malformed entries unavailable instead of trusting them', () => {
    const replay = replayChunk({ chunks: [{ ...analysis(), verdict: 'MAYBE' }] }, 0, 1_200);
    assert.equal(replay?.result.status, 'unavailable');
  });

  test('returns null when the chunk is not cached', () => {
    assert.equal(replayChunk({ chunks: [] }, 0, 1_200), null);
    assert.equal(replayChunk({ chunks: ['bad'] }, 0, 1_200), null);
    assert.equal(replayChunk('not a cache', 0, 1_200), null);
  });
});
