/**
 * Gemini Interactions API client for per-chunk scam analysis.
 * The network call is injected (GenerateFn) so retry, parsing and error handling are unit-testable.
 */
import { existsSync, readFileSync } from 'node:fs';
import { GoogleGenAI } from '@google/genai';
import { ZodError } from 'zod';
import chunkSchema from '../shared/chunk_schema.json' with { type: 'json' };
import type { ThinkingLevel } from './config.ts';
import type { DetectorResult } from './types.ts';
import { parseChunkAnalysis } from './validation.ts';

export const CHUNK_SCHEMA: Record<string, unknown> = chunkSchema;
const FALLBACK_PROMPT = 'You are Saavdhan, a phone scam detector.';

export interface ModelAttempt {
  model: string;
  thinkingLevel: ThinkingLevel;
}

export interface GenerateRequest {
  attempt: ModelAttempt;
  audioBase64: string;
  contextBlock: string;
  timeoutMs: number;
}

/** Sends one chunk to the model and resolves with its raw text output. */
export type GenerateFn = (request: GenerateRequest) => Promise<string>;

export interface Detector {
  analyze(wav: Buffer, contextBlock: string): Promise<DetectorResult>;
}

export interface DetectorOptions {
  /** null when GEMINI_API_KEY is not configured: every chunk is reported as unavailable. */
  generate: GenerateFn | null;
  attempts: readonly ModelAttempt[];
  timeoutMs: number;
  retryDelayMs?: { rateLimited: number; other: number };
  sleep?: (ms: number) => Promise<void>;
  now?: () => number;
  logger?: Pick<Console, 'warn'>;
}

export function loadDetectorPrompt(promptPath: string): string {
  return existsSync(promptPath) ? readFileSync(promptPath, 'utf8') : FALLBACK_PROMPT;
}

/** Gemini 3.8 Flash rejects the "minimal" thinking level. */
export function normalizeThinkingLevel(model: string, level: ThinkingLevel): ThinkingLevel {
  return model.includes('3.8-flash') && level === 'minimal' ? 'low' : level;
}

/** Preferred model first, then one retry on the fast fallback model. */
export function planAttempts(
  model: string,
  thinkingLevel: ThinkingLevel,
  fallbackModel: string,
): ModelAttempt[] {
  return [
    { model, thinkingLevel: normalizeThinkingLevel(model, thinkingLevel) },
    { model: fallbackModel, thinkingLevel: normalizeThinkingLevel(fallbackModel, 'minimal') },
  ];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

/** Reads output_text, or concatenates the text parts of model_output steps. */
export function extractOutputText(interaction: unknown): string {
  if (!isRecord(interaction)) return '';
  if (typeof interaction.output_text === 'string' && interaction.output_text) {
    return interaction.output_text;
  }
  const steps = Array.isArray(interaction.steps) ? interaction.steps : [];
  let text = '';
  for (const step of steps) {
    if (!isRecord(step) || step.type !== 'model_output' || !Array.isArray(step.content)) continue;
    const part: unknown = step.content.find((item) => isRecord(item) && item.type === 'text');
    if (isRecord(part) && typeof part.text === 'string') text += part.text;
  }
  return text;
}

export function createGeminiGenerate(apiKey: string, systemPrompt: string): GenerateFn {
  const client = new GoogleGenAI({
    apiKey,
    httpOptions: { headers: { 'User-Agent': 'aistudio-build' } },
  });
  return async ({ attempt, audioBase64, contextBlock, timeoutMs }) => {
    const interaction = await client.interactions.create(
      {
        model: attempt.model,
        system_instruction: systemPrompt,
        input: [
          { type: 'audio', data: audioBase64, mime_type: 'audio/wav' },
          { type: 'text', text: contextBlock },
        ],
        response_format: CHUNK_SCHEMA,
        generation_config: { thinking_level: attempt.thinkingLevel },
        store: false,
      },
      { timeout: timeoutMs },
    );
    return extractOutputText(interaction);
  };
}

function errorText(error: unknown): string {
  return error instanceof Error ? `${error.name}: ${error.message}` : String(error);
}

export function isRateLimited(error: unknown): boolean {
  return /\b429\b|RESOURCE_EXHAUSTED/i.test(errorText(error));
}

/** Maps any failure to a short message that is safe to show in the UI (no upstream details). */
export function describeFailure(error: unknown): string {
  const text = errorText(error);
  if (/abort|timeout|timed out/i.test(text)) return 'Gemini request timed out';
  if (isRateLimited(error)) return 'Gemini rate limit reached';
  if (error instanceof SyntaxError || error instanceof ZodError) {
    return 'Gemini returned an invalid response';
  }
  return 'Gemini request failed';
}

const defaultSleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

export function createDetector(options: DetectorOptions): Detector {
  const {
    generate,
    attempts,
    timeoutMs,
    retryDelayMs = { rateLimited: 1_500, other: 400 },
    sleep = defaultSleep,
    now = Date.now,
    logger = console,
  } = options;

  return {
    async analyze(wav, contextBlock) {
      if (!generate) {
        return { status: 'unavailable', error: 'GEMINI_API_KEY is not configured', latency_ms: 0 };
      }
      const audioBase64 = wav.toString('base64');
      const startedAt = now();
      let lastError: unknown = new Error('No model attempts configured');

      for (const [index, attempt] of attempts.entries()) {
        try {
          const text = await generate({ attempt, audioBase64, contextBlock, timeoutMs });
          const analysis = parseChunkAnalysis(text);
          return { status: 'ok', latency_ms: now() - startedAt, model: attempt.model, ...analysis };
        } catch (error) {
          lastError = error;
          logger.warn(
            `[detector] ${attempt.model} attempt ${index + 1} failed: ${errorText(error)}`,
          );
          if (index < attempts.length - 1) {
            await sleep(isRateLimited(error) ? retryDelayMs.rateLimited : retryDelayMs.other);
          }
        }
      }
      return {
        status: 'unavailable',
        error: describeFailure(lastError),
        latency_ms: now() - startedAt,
      };
    },
  };
}
