import assert from 'node:assert/strict';
import path from 'node:path';
import { afterEach, describe, test } from 'node:test';
import {
  CHUNK_SCHEMA,
  createDetector,
  createGeminiGenerate,
  describeFailure,
  extractOutputText,
  type GenerateFn,
  isRateLimited,
  loadDetectorPrompt,
  normalizeThinkingLevel,
  planAttempts,
} from '../../server/detector.ts';
import { analysis, REPO_ROOT, silentLogger } from './support.ts';

const MODEL_OUTPUT = JSON.stringify(analysis({ risk_score: 80, verdict: 'SCAM' }));
const attempts = planAttempts('gemini-3.8-flash', 'low', 'gemini-3.5-flash-lite');

function detectorWith(generate: GenerateFn | null, sleeps: number[] = []) {
  let clock = 1_000;
  return createDetector({
    generate,
    attempts,
    timeoutMs: 1_000,
    sleep: async (ms) => {
      sleeps.push(ms);
    },
    now: () => (clock += 25),
    logger: silentLogger,
  });
}

describe('model planning', () => {
  test('Gemini 3.8 Flash never receives the unsupported "minimal" level', () => {
    assert.equal(normalizeThinkingLevel('gemini-3.8-flash', 'minimal'), 'low');
    assert.equal(normalizeThinkingLevel('gemini-3.8-flash', 'high'), 'high');
    assert.equal(normalizeThinkingLevel('gemini-3.5-flash-lite', 'minimal'), 'minimal');
  });

  test('retries once on the fast fallback model', () => {
    assert.deepEqual(attempts, [
      { model: 'gemini-3.8-flash', thinkingLevel: 'low' },
      { model: 'gemini-3.5-flash-lite', thinkingLevel: 'minimal' },
    ]);
  });
});

describe('extractOutputText', () => {
  test('prefers output_text', () => {
    assert.equal(extractOutputText({ output_text: 'hello', steps: [] }), 'hello');
  });

  test('falls back to text parts of model_output steps', () => {
    const interaction = {
      steps: [
        { type: 'thought', content: [{ type: 'text', text: 'ignored' }] },
        { type: 'model_output', content: [{ type: 'image' }, { type: 'text', text: '{"a":' }] },
        { type: 'model_output', content: [{ type: 'text', text: '1}' }] },
      ],
    };
    assert.equal(extractOutputText(interaction), '{"a":1}');
  });

  test('returns an empty string for unexpected shapes', () => {
    assert.equal(extractOutputText(null), '');
    assert.equal(extractOutputText({ steps: 'nope' }), '');
    assert.equal(extractOutputText({ steps: [null, { type: 'model_output' }] }), '');
  });
});

describe('describeFailure', () => {
  test('maps failures to short, safe messages', () => {
    const abort = Object.assign(new Error('This operation was aborted'), { name: 'AbortError' });
    assert.equal(describeFailure(abort), 'Gemini request timed out');
    assert.equal(describeFailure(new Error('429 RESOURCE_EXHAUSTED')), 'Gemini rate limit reached');
    assert.equal(
      describeFailure(new SyntaxError('Unexpected token')),
      'Gemini returned an invalid response',
    );
    assert.equal(
      describeFailure(new Error('500 internal: secret details')),
      'Gemini request failed',
    );
    assert.equal(describeFailure('plain string'), 'Gemini request failed');
  });

  test('detects rate limiting', () => {
    assert.equal(isRateLimited(new Error('got 429 from upstream')), true);
    assert.equal(isRateLimited(new Error('status 4290')), false);
  });
});

describe('createDetector', () => {
  test('reports unavailable without calling the model when no API key is set', async () => {
    const result = await detectorWith(null).analyze(Buffer.from('wav'), 'CHUNK 1/1');
    assert.deepEqual(result, {
      status: 'unavailable',
      error: 'GEMINI_API_KEY is not configured',
      latency_ms: 0,
    });
  });

  test('returns validated analysis with latency and model on success', async () => {
    const requests: Parameters<GenerateFn>[0][] = [];
    const detector = detectorWith(async (request) => {
      requests.push(request);
      return `\`\`\`json\n${MODEL_OUTPUT}\n\`\`\``;
    });
    const result = await detector.analyze(Buffer.from('abc'), 'CHUNK 1/3');
    assert.equal(result.status, 'ok');
    assert.equal(result.status === 'ok' && result.risk_score, 80);
    assert.equal(result.model, 'gemini-3.8-flash');
    assert.equal(result.latency_ms, 25);
    assert.equal(requests[0]?.audioBase64, Buffer.from('abc').toString('base64'));
    assert.equal(requests[0]?.contextBlock, 'CHUNK 1/3');
  });

  test('falls back to the second model after a failure', async () => {
    const sleeps: number[] = [];
    const models: string[] = [];
    const detector = detectorWith(async ({ attempt }) => {
      models.push(attempt.model);
      if (models.length === 1) throw new Error('503 overloaded');
      return MODEL_OUTPUT;
    }, sleeps);
    const result = await detector.analyze(Buffer.from('abc'), 'CHUNK 1/1');
    assert.equal(result.status, 'ok');
    assert.equal(result.model, 'gemini-3.5-flash-lite');
    assert.deepEqual(models, ['gemini-3.8-flash', 'gemini-3.5-flash-lite']);
    assert.deepEqual(sleeps, [400]);
  });

  test('backs off longer when rate limited and never invents a verdict', async () => {
    const sleeps: number[] = [];
    const detector = detectorWith(async () => {
      throw new Error('429 RESOURCE_EXHAUSTED');
    }, sleeps);
    const result = await detector.analyze(Buffer.from('abc'), 'CHUNK 1/1');
    assert.deepEqual(sleeps, [1_500]);
    assert.equal(result.status, 'unavailable');
    assert.equal(result.status === 'unavailable' && result.error, 'Gemini rate limit reached');
  });

  test('treats schema-violating output as unavailable', async () => {
    const detector = detectorWith(async () => JSON.stringify({ verdict: 'MAYBE' }));
    const result = await detector.analyze(Buffer.from('abc'), 'CHUNK 1/1');
    assert.equal(
      result.status === 'unavailable' && result.error,
      'Gemini returned an invalid response',
    );
  });
});

describe('createGeminiGenerate', () => {
  const realFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = realFetch;
  });

  test('sends the audio, context and shared schema to the Interactions API', async () => {
    let captured: { url: string; apiKey: string | null; body: Record<string, unknown> } | undefined;
    globalThis.fetch = async (input, init) => {
      const request = input instanceof Request ? input : new Request(input, init);
      captured = {
        url: request.url,
        apiKey: request.headers.get('x-goog-api-key'),
        body: JSON.parse(await request.text()),
      };
      return Response.json({ id: 'interaction-1', output_text: MODEL_OUTPUT, steps: [] });
    };

    const generate = createGeminiGenerate('test-key', 'SYSTEM PROMPT');
    const text = await generate({
      attempt: { model: 'gemini-3.5-flash-lite', thinkingLevel: 'minimal' },
      audioBase64: 'QUJD',
      contextBlock: 'CHUNK 1/2',
      timeoutMs: 5_000,
    });

    assert.equal(text, MODEL_OUTPUT);
    assert.ok(captured);
    assert.match(captured.url, /\/interactions$/);
    assert.equal(captured.apiKey, 'test-key');
    assert.equal(captured.body.model, 'gemini-3.5-flash-lite');
    assert.equal(captured.body.system_instruction, 'SYSTEM PROMPT');
    assert.deepEqual(captured.body.input, [
      { type: 'audio', data: 'QUJD', mime_type: 'audio/wav' },
      { type: 'text', text: 'CHUNK 1/2' },
    ]);
    assert.deepEqual(captured.body.response_format, CHUNK_SCHEMA);
    assert.deepEqual(captured.body.generation_config, { thinking_level: 'minimal' });
    assert.equal(captured.body.store, false);
  });
});

describe('loadDetectorPrompt', () => {
  test('reads the system prompt and falls back when it is missing', () => {
    const prompt = loadDetectorPrompt(path.join(REPO_ROOT, 'prompts', 'detector_system.md'));
    assert.match(prompt, /You are Saavdhan/);
    assert.match(loadDetectorPrompt('/nonexistent/prompt.md'), /phone scam detector/);
  });
});
