/**
 * Deterministic session rules applied on top of every Gemini chunk verdict.
 * Thresholds, floors and fallback texts come from shared/detection_policy.json, which the
 * Python backend (app/rules.py) loads too; tests/fixtures/session_rules_cases.json keeps both in lockstep.
 */
import { z } from 'zod';
import policyJson from '../shared/detection_policy.json' with { type: 'json' };
import {
  type ChunkRecord,
  type ChunkSpan,
  type DetectorFailure,
  type DetectorResult,
  type DetectorSuccess,
  type GenuineSignal,
  type ModelVerdict,
  RED_FLAG_TYPES,
  type RedFlag,
  type RedFlagType,
  type SessionGenuineSignal,
  type SessionRedFlag,
  type SessionState,
  type SessionTurn,
  type TranscriptTurn,
  type UnavailableChunk,
  type Verdict,
  type WarningLanguage,
} from './types.ts';

type LocalizedText = Record<WarningLanguage, string>;

const localizedTextSchema = z.object({ gu: z.string(), hi: z.string(), en: z.string() });
const policySchema = z.object({
  verdict_thresholds: z.object({ SUSPICIOUS: z.number(), SCAM: z.number() }),
  risk_floors: z.object({
    hard_red_flag: z.number(),
    authority_threat_urgency: z.number(),
    sticky_scam: z.number(),
  }),
  hard_red_flags: z.array(z.enum(RED_FLAG_TYPES)),
  trio_red_flags: z.array(z.enum(RED_FLAG_TYPES)),
  fallback_warnings: z.object({ SCAM: localizedTextSchema, SUSPICIOUS: localizedTextSchema }),
  gujarati_text_fixes: z.array(z.tuple([z.string(), z.string()])),
});

export type DetectionPolicy = z.infer<typeof policySchema>;

/** Validated at import time so a malformed policy file fails fast at startup. */
export const POLICY: DetectionPolicy = policySchema.parse(policyJson);
export const HARD_RED_FLAGS: ReadonlySet<RedFlagType> = new Set(POLICY.hard_red_flags);
export const TRIO_RED_FLAGS: readonly RedFlagType[] = POLICY.trio_red_flags;
export const FALLBACK_WARNINGS = POLICY.fallback_warnings;

const LANGUAGES: readonly WarningLanguage[] = ['gu', 'hi', 'en'];
const VERDICT_RANK: Record<ModelVerdict, number> = { SAFE: 0, SUSPICIOUS: 1, SCAM: 2 };

const warningKey = (lang: WarningLanguage) => `warning_${lang}` as const;
const flagKey = (flag: RedFlag) => `${flag.type}::${flag.quote}`;

/** Fields the context block needs; satisfied by SessionState and by plain fixtures. */
export interface ContextSnapshot {
  transcript: readonly TranscriptTurn[];
  red_flags: readonly RedFlag[];
  genuine_signals: readonly GenuineSignal[];
  risk: number;
  verdict: Verdict;
}

export function verdictFromRisk(risk: number): ModelVerdict {
  if (risk < POLICY.verdict_thresholds.SUSPICIOUS) return 'SAFE';
  if (risk < POLICY.verdict_thresholds.SCAM) return 'SUSPICIOUS';
  return 'SCAM';
}

/** 18.2 -> "00:18.2" */
export function formatMmSsTenths(sec: number): string {
  const minutes = Math.floor(sec / 60);
  const seconds = sec - minutes * 60;
  return `${String(minutes).padStart(2, '0')}:${seconds.toFixed(1).padStart(4, '0')}`;
}

/** 12.5 -> "00:13" (round half up, matching the Python backend). */
export function formatMmSs(sec: number): string {
  const total = Math.round(sec);
  const minutes = Math.floor(total / 60);
  const seconds = total % 60;
  return `${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`;
}

/** Text context sent to Gemini alongside each audio chunk so it can reason across the whole call. */
export function buildContextBlock(
  chunkNum: number,
  totalChunks: number,
  startS: number,
  endS: number,
  session: ContextSnapshot,
): string {
  const header = `CHUNK ${chunkNum}/${totalChunks} | ${formatMmSsTenths(startS)}–${formatMmSsTenths(endS)}`;
  const callSoFar =
    session.transcript.length > 0
      ? session.transcript.map((turn) => `${turn.speaker}: ${turn.text}`).join('\n')
      : '(call just started)';
  const flags =
    session.red_flags.length > 0
      ? session.red_flags.map((flag) => `${flag.type} "${flag.quote}"`).join('; ')
      : 'none';
  const signals =
    session.genuine_signals.length > 0
      ? session.genuine_signals.map((signal) => `"${signal.quote}"`).join('; ')
      : 'none';

  return [
    header,
    'CALL SO FAR:',
    callSoFar,
    `RED FLAGS SO FAR: ${flags}`,
    `GENUINE SIGNALS SO FAR: ${signals}`,
    `CURRENT: risk ${session.risk}, ${session.verdict}`,
  ].join('\n');
}

export function createEmptySession(callId: string, sessionId: string): SessionState {
  return {
    session_id: sessionId,
    call_id: callId,
    transcript: [],
    red_flags: [],
    genuine_signals: [],
    scam_type: 'NONE',
    risk: 0,
    verdict: 'SAFE',
    ever_scam: false,
    first_scam_at: null,
    warning_gu: '',
    warning_hi: '',
    warning_en: '',
    chunks: [],
  };
}

/** Repairs common script mix-ups in the Gujarati banner word "સાવધાન!". */
export function fixGujaratiText(text: string): string {
  return POLICY.gujarati_text_fixes.reduce(
    (out, [wrong, right]) => out.replaceAll(wrong, right),
    text,
  );
}

/**
 * Applies the floors that make the verdict safer than the model alone:
 *  1. a new hard red flag (OTP, money, remote access, secrecy, hand-off) -> risk >= 75
 *  2. authority + threat + urgency heard anywhere in the call            -> risk >= 70
 *  3. once SCAM, the call never drops below SCAM again                   -> risk >= 70
 */
export function computeFinalRisk(
  session: Pick<SessionState, 'red_flags' | 'ever_scam'>,
  modelRisk: number,
  newFlags: readonly RedFlag[],
): number {
  const floors = POLICY.risk_floors;
  let risk = modelRisk;
  if (newFlags.some((flag) => HARD_RED_FLAGS.has(flag.type))) {
    risk = Math.max(risk, floors.hard_red_flag);
  }
  const heard = new Set(session.red_flags.map((flag) => flag.type));
  if (TRIO_RED_FLAGS.every((type) => heard.has(type))) {
    risk = Math.max(risk, floors.authority_threat_urgency);
  }
  if (session.ever_scam) {
    risk = Math.max(risk, floors.sticky_scam);
  }
  return risk;
}

function recordEvidence(session: SessionState, span: ChunkSpan, result: DetectorSuccess) {
  const timeMmSs = formatMmSs(span.end_s);

  const turns: SessionTurn[] = result.transcript.map((turn) => ({
    speaker: turn.speaker,
    text: turn.text,
    ...span,
  }));
  session.transcript.push(...turns);

  const flags: SessionRedFlag[] = result.new_red_flags.map((flag) => ({
    type: flag.type,
    quote: flag.quote,
    why: flag.why,
    ...span,
    time_mm_ss: timeMmSs,
  }));
  const known = new Set(session.red_flags.map(flagKey));
  for (const flag of flags) {
    if (known.has(flagKey(flag))) continue;
    session.red_flags.push(flag);
    known.add(flagKey(flag));
  }

  const signals: SessionGenuineSignal[] = result.new_genuine_signals.map((signal) => ({
    quote: signal.quote,
    why: signal.why,
    ...span,
    time_mm_ss: timeMmSs,
  }));
  session.genuine_signals.push(...signals);

  return { turns, flags, signals };
}

/**
 * Picks the warning shown to the elder for each language:
 *  - SCAM always carries a warning; empty ones fall back to the policy text.
 *  - SUSPICIOUS falls back only when nothing has been said yet (or a rule raised the verdict).
 *  - Every SCAM warning names at least one red-flag quote actually heard on the call.
 */
function resolveWarnings(
  session: SessionState,
  verdict: ModelVerdict,
  ruleRaisedVerdict: boolean,
  candidate: LocalizedText,
  citedQuote: string | undefined,
): LocalizedText {
  const resolved = { ...candidate };
  for (const lang of LANGUAGES) {
    if (resolved[lang]) continue;
    if (verdict === 'SCAM') {
      resolved[lang] = FALLBACK_WARNINGS.SCAM[lang];
    } else if (verdict === 'SUSPICIOUS' && (ruleRaisedVerdict || !session[warningKey(lang)])) {
      resolved[lang] = FALLBACK_WARNINGS.SUSPICIOUS[lang];
    }
  }

  if (verdict === 'SCAM' && citedQuote !== undefined) {
    const quotes = session.red_flags.map((flag) => flag.quote).filter(Boolean);
    for (const lang of LANGUAGES) {
      if (quotes.length > 0 && !quotes.some((quote) => resolved[lang].includes(quote))) {
        resolved[lang] = `${resolved[lang]} ("${citedQuote}")`;
      }
    }
  }
  return resolved;
}

function recordUnavailable(
  session: SessionState,
  span: ChunkSpan,
  result: DetectorFailure,
): UnavailableChunk {
  const record: UnavailableChunk = {
    ...span,
    status: 'unavailable',
    error: result.error || 'Analysis unavailable',
    latency_ms: result.latency_ms || 0,
    verdict: 'unavailable',
    risk_score: session.risk,
    transcript: [],
    new_red_flags: [],
    new_genuine_signals: [],
    warning_gu: session.warning_gu,
    warning_hi: session.warning_hi,
    warning_en: session.warning_en,
  };
  session.chunks.push(record);
  return record;
}

/**
 * Folds one chunk result into the session and returns the processed chunk record.
 * A failed chunk never invents a verdict: it is recorded as "unavailable" and the session is unchanged.
 */
export function applySessionRules(
  session: SessionState,
  span: ChunkSpan,
  result: DetectorResult,
): ChunkRecord {
  if (result.status !== 'ok') return recordUnavailable(session, span, result);

  const evidence = recordEvidence(session, span, result);
  const modelRisk = result.risk_score;
  const finalRisk = computeFinalRisk(session, modelRisk, result.new_red_flags);
  const finalVerdict = verdictFromRisk(finalRisk);

  if (finalVerdict === 'SCAM') {
    session.ever_scam = true;
    session.first_scam_at ??= Number(span.end_s.toFixed(2));
  }
  if (result.scam_type !== 'NONE') session.scam_type = result.scam_type;

  const ruleRaisedVerdict = VERDICT_RANK[finalVerdict] > VERDICT_RANK[verdictFromRisk(modelRisk)];
  const citedQuote = (evidence.flags.at(-1) ?? session.red_flags.at(-1))?.quote;
  const warnings = resolveWarnings(
    session,
    finalVerdict,
    ruleRaisedVerdict,
    {
      gu: fixGujaratiText(result.warning_gu.trim()),
      hi: result.warning_hi.trim(),
      en: result.warning_en.trim(),
    },
    citedQuote,
  );

  session.risk = finalRisk;
  session.verdict = finalVerdict;
  for (const lang of LANGUAGES) {
    if (warnings[lang]) session[warningKey(lang)] = warnings[lang];
  }

  const record: ChunkRecord = {
    ...span,
    status: 'ok',
    latency_ms: result.latency_ms || 0,
    model: result.model || '',
    transcript: evidence.turns,
    new_red_flags: evidence.flags,
    new_genuine_signals: evidence.signals,
    scam_type: session.scam_type,
    model_risk_score: modelRisk,
    risk_score: finalRisk,
    verdict: finalVerdict,
    warning_gu: warnings.gu || session.warning_gu,
    warning_hi: warnings.hi || session.warning_hi,
    warning_en: warnings.en || session.warning_en,
  };
  session.chunks.push(record);
  return record;
}
