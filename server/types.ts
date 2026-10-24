/**
 * Domain types shared by the Saavdhan Node server modules.
 * The model-facing shapes mirror shared/chunk_schema.json (verified by tests/node/contract.test.ts).
 */

export const SPEAKERS = ['CALLER', 'RECEIVER', 'UNKNOWN'] as const;
export const RED_FLAG_TYPES = [
  'AUTHORITY_CLAIM',
  'URGENCY',
  'THREAT',
  'OTP_OR_CREDENTIALS',
  'MONEY_REQUEST',
  'REMOTE_ACCESS_OR_LINK',
  'SECRECY',
  'HANDOFF_TO_OFFICIAL',
] as const;
export const SCAM_TYPES = [
  'DIGITAL_ARREST',
  'FAKE_KYC',
  'FAKE_COURIER',
  'OTHER_FRAUD',
  'NONE',
] as const;
export const MODEL_VERDICTS = ['SAFE', 'SUSPICIOUS', 'SCAM'] as const;
export const EXPECTED_OUTCOMES = ['SCAM', 'SAFE'] as const;

export type Speaker = (typeof SPEAKERS)[number];
export type RedFlagType = (typeof RED_FLAG_TYPES)[number];
export type ScamType = (typeof SCAM_TYPES)[number];
export type ModelVerdict = (typeof MODEL_VERDICTS)[number];
export type Verdict = ModelVerdict | 'unavailable';
export type ExpectedOutcome = (typeof EXPECTED_OUTCOMES)[number];
export type WarningLanguage = 'gu' | 'hi' | 'en';
export type AnalysisMode = 'LIVE' | 'REPLAY';

export interface TranscriptTurn {
  speaker: Speaker;
  text: string;
}

export interface RedFlag {
  type: RedFlagType;
  quote: string;
  why: string;
}

export interface GenuineSignal {
  quote: string;
  why: string;
}

/** Validated structured output for one audio chunk. */
export interface ChunkAnalysis {
  transcript: TranscriptTurn[];
  new_red_flags: RedFlag[];
  new_genuine_signals: GenuineSignal[];
  scam_type: ScamType;
  risk_score: number;
  verdict: ModelVerdict;
  warning_gu: string;
  warning_hi: string;
  warning_en: string;
}

export interface DetectorSuccess extends ChunkAnalysis {
  status: 'ok';
  latency_ms: number;
  model: string;
}

export interface DetectorFailure {
  status: 'unavailable';
  error: string;
  latency_ms: number;
  model?: string;
}

/** What the detector (or the replay cache) produced for one chunk. */
export type DetectorResult = DetectorSuccess | DetectorFailure;

export interface ChunkSpan {
  chunk_index: number;
  start_s: number;
  end_s: number;
}

export interface SessionTurn extends TranscriptTurn, ChunkSpan {}

export interface SessionRedFlag extends RedFlag, ChunkSpan {
  time_mm_ss: string;
}

export interface SessionGenuineSignal extends GenuineSignal, ChunkSpan {
  time_mm_ss: string;
}

export interface Warnings {
  warning_gu: string;
  warning_hi: string;
  warning_en: string;
}

export interface AnalyzedChunk extends ChunkSpan, Warnings {
  status: 'ok';
  latency_ms: number;
  model: string;
  transcript: SessionTurn[];
  new_red_flags: SessionRedFlag[];
  new_genuine_signals: SessionGenuineSignal[];
  scam_type: ScamType;
  model_risk_score: number;
  risk_score: number;
  verdict: ModelVerdict;
  mode?: AnalysisMode;
}

export interface UnavailableChunk extends ChunkSpan, Warnings {
  status: 'unavailable';
  error: string;
  latency_ms: number;
  verdict: 'unavailable';
  risk_score: number;
  transcript: SessionTurn[];
  new_red_flags: SessionRedFlag[];
  new_genuine_signals: SessionGenuineSignal[];
  mode?: AnalysisMode;
}

export type ChunkRecord = AnalyzedChunk | UnavailableChunk;

export interface SessionState extends Warnings {
  session_id: string;
  call_id: string;
  transcript: SessionTurn[];
  red_flags: SessionRedFlag[];
  genuine_signals: SessionGenuineSignal[];
  scam_type: ScamType;
  risk: number;
  verdict: ModelVerdict;
  ever_scam: boolean;
  first_scam_at: number | null;
  chunks: ChunkRecord[];
}

/** One entry in calls/manifest.json. */
export interface ManifestEntry {
  file: string;
  title: string;
  expected: ExpectedOutcome;
  first_demand_at?: number | null;
  uploaded?: boolean;
}

export interface CallChunk {
  index: number;
  start_s: number;
  end_s: number;
}

/** Public metadata for a playable call, as returned by GET /api/calls. */
export interface CallMeta {
  id: string;
  file: string;
  title: string;
  expected: ExpectedOutcome;
  first_demand_at: number | null;
  duration: number;
  chunks: CallChunk[];
  has_cache: boolean;
}
