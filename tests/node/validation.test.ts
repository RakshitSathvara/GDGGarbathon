import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { ZodError } from 'zod';
import { MAX_UPLOAD_BYTES } from '../../server/config.ts';
import {
  analyzeRequestSchema,
  decodeBase64Strict,
  describeValidationError,
  MAX_UPLOAD_BASE64_CHARS,
  parseChunkAnalysis,
  sanitizeCallStem,
  stripCodeFence,
  uploadRequestSchema,
  validateWavUpload,
} from '../../server/validation.ts';
import { analysis } from './support.ts';

const RIFF_WAVE = new Uint8Array([0x52, 0x49, 0x46, 0x46, 0, 0, 0, 0, 0x57, 0x41, 0x56, 0x45]);

describe('validateWavUpload', () => {
  test('accepts a .wav up to exactly 10 MB and sanitizes its name', () => {
    const result = validateWavUpload('My Call Recording.wav', 512 * 1024, RIFF_WAVE);
    assert.deepEqual(result, { valid: true, sanitizedStem: 'my_call_recording' });
    assert.equal(validateWavUpload('max.WAV', MAX_UPLOAD_BYTES, RIFF_WAVE).valid, true);
  });

  test('rejects missing names, other extensions, empty and oversized files', () => {
    assert.match(validateWavUpload('  ', 1000).error ?? '', /select a \.wav/);
    assert.match(validateWavUpload('audio.mp3', 10_240, RIFF_WAVE).error ?? '', /Only \.wav/);
    assert.match(validateWavUpload('tiny.wav', 44).error ?? '', /empty or corrupted/);
    assert.match(validateWavUpload('nan.wav', Number.NaN).error ?? '', /empty or corrupted/);
    const huge = validateWavUpload('huge.wav', MAX_UPLOAD_BYTES + 1, RIFF_WAVE);
    assert.equal(huge.valid, false);
    assert.match(huge.error ?? '', /10 MB/);
  });

  test('rejects files whose magic bytes are not RIFF/WAVE', () => {
    const id3 = new Uint8Array([0x49, 0x44, 0x33, 3, 0, 0, 0, 0, 0, 0, 0, 0]);
    assert.match(validateWavUpload('fake.wav', 10_240, id3).error ?? '', /RIFF\/WAVE/);
  });
});

describe('sanitizeCallStem', () => {
  test('strips paths, unsafe characters and surrounding underscores', () => {
    assert.equal(sanitizeCallStem('../../etc/passwd.wav'), 'passwd');
    assert.equal(sanitizeCallStem('C:\\calls\\Mom (1).WAV'), 'mom_1');
    assert.equal(sanitizeCallStem('__a b__.wav'), 'a_b');
  });

  test('falls back for names without usable characters and caps the length', () => {
    assert.equal(sanitizeCallStem('ગુજરાતી.wav'), 'uploaded_call');
    assert.equal(sanitizeCallStem(`${'x'.repeat(80)}.wav`).length, 48);
  });
});

describe('decodeBase64Strict', () => {
  test('decodes valid base64, ignoring line breaks', () => {
    assert.equal(decodeBase64Strict('aGVs\nbG8=')?.toString(), 'hello');
  });

  test('rejects characters outside the alphabet and bad padding', () => {
    assert.equal(decodeBase64Strict('aGVsbG8*'), null);
    assert.equal(decodeBase64Strict('aGVsbG8'), null);
  });
});

describe('model output parsing', () => {
  test('stripCodeFence removes json fences with or without a closing fence', () => {
    assert.equal(stripCodeFence('```json\n{"a":1}\n```'), '{"a":1}');
    assert.equal(stripCodeFence('```\n{"a":1}'), '{"a":1}');
    assert.equal(stripCodeFence('  {"a":1} '), '{"a":1}');
  });

  test('parseChunkAnalysis validates enums and ranges and strips unknown keys', () => {
    const valid = { ...analysis({ risk_score: 55, verdict: 'SUSPICIOUS' }), extra: 'dropped' };
    assert.deepEqual(
      parseChunkAnalysis(JSON.stringify(valid)),
      analysis({ risk_score: 55, verdict: 'SUSPICIOUS' }),
    );
    assert.throws(
      () => parseChunkAnalysis(JSON.stringify(analysis({ risk_score: 101 }))),
      ZodError,
    );
    assert.throws(
      () => parseChunkAnalysis(JSON.stringify({ ...analysis(), scam_type: 'LOTTERY' })),
      ZodError,
    );
    assert.throws(() => parseChunkAnalysis('not json'), SyntaxError);
  });
});

describe('request schemas', () => {
  test('analyze requests need a UUID session and an integer chunk index', () => {
    const session_id = '4a8a863b-1d99-408c-9728-d0e8c0811270';
    assert.deepEqual(analyzeRequestSchema.parse({ session_id, chunk_index: 2 }), {
      session_id,
      chunk_index: 2,
    });
    assert.throws(() => analyzeRequestSchema.parse({ session_id, chunk_index: 1.5 }), ZodError);
    assert.throws(() => analyzeRequestSchema.parse({ session_id: 'x', chunk_index: 1 }), ZodError);
  });

  test('uploads are bounded and expected must be SCAM or SAFE', () => {
    const base = { filename: 'a.wav', data_base64: 'AAAA' };
    assert.equal(uploadRequestSchema.parse({ ...base, expected: 'SAFE' }).expected, 'SAFE');
    assert.throws(() => uploadRequestSchema.parse({ ...base, expected: 'MAYBE' }), ZodError);
    assert.throws(
      () =>
        uploadRequestSchema.parse({
          ...base,
          data_base64: 'A'.repeat(MAX_UPLOAD_BASE64_CHARS + 1),
        }),
      ZodError,
    );
  });

  test('describeValidationError names the offending field', () => {
    const error = analyzeRequestSchema.safeParse({ session_id: 'x', chunk_index: 0 }).error;
    assert.ok(error);
    assert.match(describeValidationError(error), /^Invalid request — session_id: /);
    assert.equal(describeValidationError(new ZodError([])), 'Invalid request.');
  });
});
