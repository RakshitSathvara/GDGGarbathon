/**
 * Contract tests: the Node backend must agree with shared/*.json and with the Python backend.
 * tests/python/test_contract.py replays the same fixtures through app/rules.py.
 */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, test } from 'node:test';
import { CHUNK_SCHEMA } from '../../server/detector.ts';
import {
  applySessionRules,
  buildContextBlock,
  type ContextSnapshot,
  createEmptySession,
  FALLBACK_WARNINGS,
  POLICY,
} from '../../server/rules.ts';
import {
  type ChunkRecord,
  type DetectorResult,
  MODEL_VERDICTS,
  RED_FLAG_TYPES,
  SCAM_TYPES,
  type SessionState,
  SPEAKERS,
} from '../../server/types.ts';
import { REPO_ROOT, readFixture } from './support.ts';

interface RuleStep {
  chunk: { index: number; start_s: number; end_s: number };
  result: DetectorResult;
  expect: { chunk: Record<string, unknown>; session: Record<string, unknown> };
}

interface RuleCase {
  name: string;
  call_id: string;
  steps: RuleStep[];
}

interface ContextCase {
  name: string;
  chunk_num: number;
  total_chunks: number;
  start_s: number;
  end_s: number;
  session: ContextSnapshot;
  expected: string;
}

const fixture = readFixture<{ cases: RuleCase[]; context_blocks: ContextCase[] }>(
  'session_rules_cases.json',
);

/** Expands "{{SCAM.gu}}"-style placeholders to the shared fallback warnings. */
function expand(value: unknown): unknown {
  if (typeof value !== 'string') return value;
  return value.replace(
    /\{\{(SCAM|SUSPICIOUS)\.(gu|hi|en)\}\}/g,
    (_match, verdict: 'SCAM' | 'SUSPICIOUS', lang: 'gu' | 'hi' | 'en') =>
      FALLBACK_WARNINGS[verdict][lang],
  );
}

function assertMatches(actual: object, expected: Record<string, unknown>, label: string) {
  const record = actual as Record<string, unknown>;
  for (const [key, want] of Object.entries(expected)) {
    if (key === 'flag_times' || key === 'signal_times') {
      const items = record[key === 'flag_times' ? 'new_red_flags' : 'new_genuine_signals'] as {
        time_mm_ss: string;
      }[];
      assert.deepEqual(
        items.map((item) => item.time_mm_ss),
        want,
        `${label}: ${key}`,
      );
      continue;
    }
    const got = record[key];
    if (Array.isArray(got)) assert.equal(got.length, want, `${label}: ${key} count`);
    else assert.deepEqual(got, expand(want), `${label}: ${key}`);
  }
}

describe('shared chunk schema', () => {
  const schema = JSON.parse(
    readFileSync(path.join(REPO_ROOT, 'shared', 'chunk_schema.json'), 'utf8'),
  );

  test('is the exact response_format sent to Gemini', () => {
    assert.deepEqual(CHUNK_SCHEMA, schema);
  });

  test('enums match the TypeScript domain types', () => {
    const props = schema.properties;
    assert.deepEqual(props.transcript.items.properties.speaker.enum, [...SPEAKERS]);
    assert.deepEqual(props.new_red_flags.items.properties.type.enum, [...RED_FLAG_TYPES]);
    assert.deepEqual(props.scam_type.enum, [...SCAM_TYPES]);
    assert.deepEqual(props.verdict.enum, [...MODEL_VERDICTS]);
  });

  test('lists evidence before the verdict so the model reasons first', () => {
    const order = Object.keys(schema.properties);
    assert.ok(order.indexOf('new_red_flags') < order.indexOf('risk_score'));
    assert.ok(order.indexOf('risk_score') < order.indexOf('verdict'));
  });
});

describe('shared detection policy', () => {
  test('floors push risk into the SCAM band', () => {
    for (const floor of Object.values(POLICY.risk_floors)) {
      assert.ok(floor >= POLICY.verdict_thresholds.SCAM);
    }
  });

  test('every fallback warning tells the elder to call 1930', () => {
    for (const lang of ['gu', 'hi', 'en'] as const) {
      assert.match(FALLBACK_WARNINGS.SCAM[lang], /1930/);
    }
  });
});

describe('session rules parity cases', () => {
  for (const ruleCase of fixture.cases) {
    test(ruleCase.name, () => {
      const session: SessionState = createEmptySession(ruleCase.call_id, 'parity');
      ruleCase.steps.forEach((step, index) => {
        const label = `${ruleCase.name} / step ${index + 1}`;
        const record: ChunkRecord = applySessionRules(
          session,
          { chunk_index: step.chunk.index, start_s: step.chunk.start_s, end_s: step.chunk.end_s },
          step.result,
        );
        assertMatches(record, step.expect.chunk, `${label} chunk`);
        assertMatches(session, step.expect.session, `${label} session`);
      });
    });
  }
});

describe('context block parity cases', () => {
  for (const contextCase of fixture.context_blocks) {
    test(contextCase.name, () => {
      const block = buildContextBlock(
        contextCase.chunk_num,
        contextCase.total_chunks,
        contextCase.start_s,
        contextCase.end_s,
        contextCase.session,
      );
      assert.equal(block, contextCase.expected);
    });
  }
});
