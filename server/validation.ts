/**
 * Input validation for everything that crosses a trust boundary:
 * HTTP request bodies, the model's JSON output, replay caches, the manifest and uploaded audio.
 */
import { z } from 'zod';
import { MAX_UPLOAD_BYTES } from './config.ts';
import {
  type ChunkAnalysis,
  EXPECTED_OUTCOMES,
  MODEL_VERDICTS,
  RED_FLAG_TYPES,
  SCAM_TYPES,
  SPEAKERS,
} from './types.ts';

/** Base64 inflates 3 bytes into 4 characters. */
export const MAX_UPLOAD_BASE64_CHARS = Math.ceil(MAX_UPLOAD_BYTES / 3) * 4;
const MAX_STEM_LENGTH = 48;
const BASE64_PATTERN = /^[A-Za-z0-9+/]*={0,2}$/;

export const chunkAnalysisSchema = z.object({
  transcript: z.array(z.object({ speaker: z.enum(SPEAKERS), text: z.string() })),
  new_red_flags: z.array(
    z.object({ type: z.enum(RED_FLAG_TYPES), quote: z.string(), why: z.string() }),
  ),
  new_genuine_signals: z.array(z.object({ quote: z.string(), why: z.string() })),
  scam_type: z.enum(SCAM_TYPES),
  risk_score: z.number().int().min(0).max(100),
  verdict: z.enum(MODEL_VERDICTS),
  warning_gu: z.string(),
  warning_hi: z.string(),
  warning_en: z.string(),
}) satisfies z.ZodType<ChunkAnalysis>;

export const sessionRequestSchema = z.object({
  call_id: z.string().trim().min(1).max(128),
});

export const analyzeRequestSchema = z.object({
  session_id: z.uuid(),
  chunk_index: z.number().int().min(0).max(10_000),
  replay: z.boolean().nullish(),
});

export const uploadRequestSchema = z.object({
  filename: z.string().trim().min(1).max(255),
  data_base64: z.string().min(1).max(MAX_UPLOAD_BASE64_CHARS),
  title: z.string().trim().max(120).nullish(),
  expected: z.enum(EXPECTED_OUTCOMES).nullish(),
});

export const manifestEntrySchema = z.object({
  file: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}\.wav$/),
  title: z.string().min(1),
  expected: z.enum(EXPECTED_OUTCOMES),
  first_demand_at: z.number().nonnegative().nullish(),
  uploaded: z.boolean().optional(),
});

export type UploadRequest = z.infer<typeof uploadRequestSchema>;

/** Strips a ```json fence some models wrap around structured output. */
export function stripCodeFence(text: string): string {
  const trimmed = text.trim();
  if (!trimmed.startsWith('```')) return trimmed;
  const lines = trimmed.split('\n');
  const closed = lines.at(-1)?.startsWith('```') ?? false;
  return lines
    .slice(1, closed ? -1 : undefined)
    .join('\n')
    .trim();
}

/** Parses and validates the model's JSON; throws SyntaxError or ZodError on bad output. */
export function parseChunkAnalysis(text: string): ChunkAnalysis {
  return chunkAnalysisSchema.parse(JSON.parse(stripCodeFence(text)));
}

/** Strict base64 decode: rejects characters outside the alphabet instead of silently skipping them. */
export function decodeBase64Strict(data: string): Buffer | null {
  const compact = data.replace(/\s+/g, '');
  if (compact.length % 4 !== 0 || !BASE64_PATTERN.test(compact)) return null;
  return Buffer.from(compact, 'base64');
}

/** "../My Call (1).wav" -> "my_call_1"; never empty, never contains path separators. */
export function sanitizeCallStem(fileName: string): string {
  const baseName = fileName.trim().split(/[\\/]/).at(-1) ?? '';
  const stem = baseName
    .replace(/\.wav$/i, '')
    .toLowerCase()
    .replace(/[^a-z0-9_-]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .slice(0, MAX_STEM_LENGTH);
  return stem || 'uploaded_call';
}

export interface WavValidationResult {
  valid: boolean;
  error?: string;
  sanitizedStem?: string;
}

/** Cheap checks on name, size and magic bytes before any audio is written to disk. */
export function validateWavUpload(
  fileName: string,
  byteLength: number,
  headerBytes?: Uint8Array,
): WavValidationResult {
  const trimmed = String(fileName || '').trim();
  if (!trimmed) return { valid: false, error: 'Please select a .wav audio file.' };
  if (!trimmed.toLowerCase().endsWith('.wav')) {
    return { valid: false, error: 'Only .wav files are allowed.' };
  }
  if (!Number.isFinite(byteLength) || byteLength <= 44) {
    return { valid: false, error: 'The .wav file is empty or corrupted.' };
  }
  if (byteLength > MAX_UPLOAD_BYTES) {
    const sizeMb = (byteLength / (1024 * 1024)).toFixed(2);
    return { valid: false, error: `File size (${sizeMb} MB) exceeds the 10 MB maximum limit.` };
  }
  if (headerBytes && headerBytes.length >= 12) {
    const header = Buffer.from(headerBytes);
    if (header.toString('ascii', 0, 4) !== 'RIFF' || header.toString('ascii', 8, 12) !== 'WAVE') {
      return { valid: false, error: 'Invalid WAV file header (expected RIFF/WAVE).' };
    }
  }
  return { valid: true, sanitizedStem: sanitizeCallStem(trimmed) };
}

/** Human-readable summary of the first validation issue, safe to return to clients. */
export function describeValidationError(error: z.ZodError): string {
  const issue = error.issues[0];
  if (!issue) return 'Invalid request.';
  const field = issue.path.length > 0 ? `${issue.path.join('.')}: ` : '';
  return `Invalid request — ${field}${issue.message}`;
}
