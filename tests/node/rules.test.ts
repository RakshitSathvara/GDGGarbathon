import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import {
  applySessionRules,
  computeFinalRisk,
  createEmptySession,
  FALLBACK_WARNINGS,
  fixGujaratiText,
  formatMmSs,
  formatMmSsTenths,
  verdictFromRisk,
} from '../../server/rules.ts';
import type { DetectorSuccess, RedFlag } from '../../server/types.ts';
import { analysis } from './support.ts';

const ok = (overrides: Parameters<typeof analysis>[0] = {}): DetectorSuccess => ({
  status: 'ok',
  latency_ms: 300,
  model: 'test-model',
  ...analysis(overrides),
});
const span = (index: number, start: number, end: number) => ({
  chunk_index: index,
  start_s: start,
  end_s: end,
});
const flag = (type: RedFlag['type'], quote: string = type): RedFlag => ({
  type,
  quote,
  why: 'test',
});

describe('verdictFromRisk', () => {
  test('maps <30 SAFE, 30-69 SUSPICIOUS, >=70 SCAM', () => {
    assert.equal(verdictFromRisk(0), 'SAFE');
    assert.equal(verdictFromRisk(29), 'SAFE');
    assert.equal(verdictFromRisk(30), 'SUSPICIOUS');
    assert.equal(verdictFromRisk(69), 'SUSPICIOUS');
    assert.equal(verdictFromRisk(70), 'SCAM');
    assert.equal(verdictFromRisk(100), 'SCAM');
  });
});

describe('time formatting', () => {
  test('formatMmSs rounds half up and pads', () => {
    assert.equal(formatMmSs(0), '00:00');
    assert.equal(formatMmSs(12.5), '00:13');
    assert.equal(formatMmSs(12.49), '00:12');
    assert.equal(formatMmSs(75), '01:15');
  });

  test('formatMmSsTenths keeps one decimal', () => {
    assert.equal(formatMmSsTenths(5.8), '00:05.8');
    assert.equal(formatMmSsTenths(68.5), '01:08.5');
  });
});

describe('computeFinalRisk', () => {
  test('keeps the model score when no rule applies', () => {
    assert.equal(computeFinalRisk({ red_flags: [], ever_scam: false }, 42, []), 42);
  });

  test('floors a new hard red flag at 75', () => {
    const risk = computeFinalRisk({ red_flags: [], ever_scam: false }, 10, [flag('MONEY_REQUEST')]);
    assert.equal(risk, 75);
  });

  test('floors the authority + threat + urgency trio at 70', () => {
    const session = createEmptySession('c', 's');
    for (const type of ['AUTHORITY_CLAIM', 'THREAT', 'URGENCY'] as const) {
      session.red_flags.push({ ...flag(type), ...span(0, 0, 6), time_mm_ss: '00:06' });
    }
    assert.equal(computeFinalRisk(session, 20, []), 70);
  });

  test('never lets a SCAM call fall back below 70', () => {
    assert.equal(computeFinalRisk({ red_flags: [], ever_scam: true }, 5, []), 70);
  });

  test('never lowers a higher model score', () => {
    assert.equal(computeFinalRisk({ red_flags: [], ever_scam: true }, 95, [flag('SECRECY')]), 95);
  });
});

describe('fixGujaratiText', () => {
  test('repairs Devanagari and misspelt banner words', () => {
    assert.equal(fixGujaratiText('सावधान! ફોન કાપો'), 'સાવધાન! ફોન કાપો');
    assert.equal(fixGujaratiText('सापवधान! a સાપવધાન! b'), 'સાવધાન! a સાવધાન! b');
    assert.equal(fixGujaratiText('સાવધાન!'), 'સાવધાન!');
  });
});

describe('applySessionRules', () => {
  test('records transcript turns and flags with chunk timing', () => {
    const session = createEmptySession('call', 'session');
    const record = applySessionRules(
      session,
      span(2, 12, 18.4),
      ok({
        transcript: [{ speaker: 'CALLER', text: 'CBI officer here' }],
        new_red_flags: [flag('AUTHORITY_CLAIM', 'CBI officer')],
        risk_score: 35,
      }),
    );
    assert.equal(record.status, 'ok');
    assert.deepEqual(session.transcript[0], {
      speaker: 'CALLER',
      text: 'CBI officer here',
      chunk_index: 2,
      start_s: 12,
      end_s: 18.4,
    });
    assert.equal(session.red_flags[0]?.time_mm_ss, '00:18');
    assert.equal(session.verdict, 'SUSPICIOUS');
  });

  test('keeps the detected scam type when later chunks report NONE', () => {
    const session = createEmptySession('call', 'session');
    applySessionRules(session, span(0, 0, 6), ok({ scam_type: 'FAKE_COURIER', risk_score: 50 }));
    applySessionRules(session, span(1, 6, 12), ok({ scam_type: 'NONE', risk_score: 50 }));
    assert.equal(session.scam_type, 'FAKE_COURIER');
  });

  test('records genuine signals without deduplication', () => {
    const session = createEmptySession('call', 'session');
    const signal = { quote: 'visit the branch', why: 'in person' };
    applySessionRules(session, span(0, 0, 6), ok({ new_genuine_signals: [signal] }));
    applySessionRules(session, span(1, 6, 12), ok({ new_genuine_signals: [signal] }));
    assert.equal(session.genuine_signals.length, 2);
  });

  test('keeps an earlier SUSPICIOUS warning instead of the fallback', () => {
    const session = createEmptySession('call', 'session');
    applySessionRules(
      session,
      span(0, 0, 6),
      ok({ risk_score: 40, warning_gu: 'ગુ', warning_hi: 'हि', warning_en: 'en' }),
    );
    const record = applySessionRules(session, span(1, 6, 12), ok({ risk_score: 45 }));
    assert.equal(record.warning_gu, 'ગુ');
    assert.notEqual(record.warning_en, FALLBACK_WARNINGS.SUSPICIOUS.en);
  });

  test('an unavailable chunk falls back to a default error message', () => {
    const session = createEmptySession('call', 'session');
    const record = applySessionRules(session, span(0, 0, 6), {
      status: 'unavailable',
      error: '',
      latency_ms: 0,
    });
    assert.equal(record.status, 'unavailable');
    assert.equal(record.status === 'unavailable' && record.error, 'Analysis unavailable');
    assert.equal(session.chunks.length, 1);
  });
});
