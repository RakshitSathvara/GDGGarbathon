/**
 * Pure session rules, silence-aware chunking math, and context block formatting for Saavdhan.
 */

export type Speaker = 'CALLER' | 'RECEIVER' | 'UNKNOWN';

export type RedFlagType =
  | 'AUTHORITY_CLAIM'
  | 'URGENCY'
  | 'THREAT'
  | 'OTP_OR_CREDENTIALS'
  | 'MONEY_REQUEST'
  | 'REMOTE_ACCESS_OR_LINK'
  | 'SECRECY'
  | 'HANDOFF_TO_OFFICIAL';

export type ScamType = 'DIGITAL_ARREST' | 'FAKE_KYC' | 'FAKE_COURIER' | 'OTHER_FRAUD' | 'NONE';
export type Verdict = 'SAFE' | 'SUSPICIOUS' | 'SCAM' | 'unavailable';

export interface TranscriptTurn {
  speaker: Speaker;
  text: string;
  chunk_index?: number;
  start_s?: number;
  end_s?: number;
}

export interface RedFlagItem {
  type: RedFlagType;
  quote: string;
  why: string;
  chunk_index?: number;
  start_s?: number;
  end_s?: number;
  time_mm_ss?: string;
}

export interface GenuineSignalItem {
  quote: string;
  why: string;
  chunk_index?: number;
  start_s?: number;
  end_s?: number;
  time_mm_ss?: string;
}

export interface SessionState {
  session_id: string;
  call_id: string;
  transcript: TranscriptTurn[];
  red_flags: RedFlagItem[];
  genuine_signals: GenuineSignalItem[];
  scam_type: ScamType;
  risk: number;
  verdict: Verdict;
  ever_scam: boolean;
  first_scam_at: number | null;
  warning_gu: string;
  warning_hi: string;
  warning_en: string;
  chunks: any[];
}

export const HARD_RED_FLAGS = new Set<RedFlagType>([
  'OTP_OR_CREDENTIALS',
  'MONEY_REQUEST',
  'REMOTE_ACCESS_OR_LINK',
  'SECRECY',
  'HANDOFF_TO_OFFICIAL',
]);

export const TRIO_RED_FLAGS: RedFlagType[] = ['AUTHORITY_CLAIM', 'THREAT', 'URGENCY'];

export const SCAM_FALLBACK_GU =
  'સાવધાન! આ કોલ ફ્રોડ હોઈ શકે છે. OTP કે પૈસા ન આપો. ફોન કાપી નાખો અને 1930 પર ફોન કરો.';
export const SCAM_FALLBACK_HI =
  'सावधान! यह कॉल फ्रॉड हो सकती है। OTP या पैसे मत दीजिए। फ़ोन काट दीजिए और 1930 पर कॉल कीजिए।';
export const SCAM_FALLBACK_EN =
  'Warning! This call may be a fraud. Do not share OTP or money. Hang up and call 1930.';

export const SUSPICIOUS_FALLBACK_GU =
  'સાવધાન! આ કોલ શંકાસ્પદ લાગે છે. કોઈ પણ માહિતી આપતા પહેલા ચકાસણી કરો.';
export const SUSPICIOUS_FALLBACK_HI =
  'सावधान! यह कॉल संदिग्ध लग रही है। कोई भी जानकारी देने से पहले जाँच करें।';
export const SUSPICIOUS_FALLBACK_EN =
  'Caution! This call sounds suspicious. Verify before sharing any details.';

export const MAX_WAV_UPLOAD_BYTES = 10 * 1024 * 1024; // 10 MB

export interface WavValidationResult {
  valid: boolean;
  error?: string;
  sanitizedStem?: string;
}

export function validateWavUpload(
  fileName: string,
  byteLength: number,
  headerBytes?: Uint8Array
): WavValidationResult {
  const trimmed = String(fileName || '').trim();
  if (!trimmed) {
    return { valid: false, error: 'Please select a .wav audio file.' };
  }
  if (!trimmed.toLowerCase().endsWith('.wav')) {
    return { valid: false, error: 'Only .wav files are allowed.' };
  }
  if (!Number.isFinite(byteLength) || byteLength <= 44) {
    return { valid: false, error: 'The .wav file is empty or corrupted.' };
  }
  if (byteLength > MAX_WAV_UPLOAD_BYTES) {
    const sizeMb = (byteLength / (1024 * 1024)).toFixed(2);
    return {
      valid: false,
      error: `File size (${sizeMb} MB) exceeds the 10 MB maximum limit.`,
    };
  }
  if (headerBytes && headerBytes.length >= 12) {
    const riff = String.fromCharCode(headerBytes[0], headerBytes[1], headerBytes[2], headerBytes[3]);
    const wave = String.fromCharCode(headerBytes[8], headerBytes[9], headerBytes[10], headerBytes[11]);
    if (riff !== 'RIFF' || wave !== 'WAVE') {
      return { valid: false, error: 'Invalid WAV file header (expected RIFF/WAVE).' };
    }
  }

  const baseNoExt = trimmed.replace(/\.wav$/i, '');
  const sanitizedStem =
    baseNoExt
      .toLowerCase()
      .replace(/[^a-z0-9_-]+/g, '_')
      .replace(/^_+|_+$/g, '')
      .slice(0, 48) || 'uploaded_call';

  return { valid: true, sanitizedStem };
}

export function verdictFromRisk(risk: number): 'SAFE' | 'SUSPICIOUS' | 'SCAM' {
  if (risk < 30) return 'SAFE';
  if (risk < 70) return 'SUSPICIOUS';
  return 'SCAM';
}

export function formatMmSsTenths(sec: number): string {
  const m = Math.floor(sec / 60);
  const s = sec - m * 60;
  return `${String(m).padStart(2, '0')}:${s.toFixed(1).padStart(4, '0')}`;
}

export function formatMmSs(sec: number): string {
  const total = Math.round(sec);
  const m = Math.floor(total / 60);
  const s = total % 60;
  return `${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
}

export function buildContextBlock(
  chunkNum: number,
  totalChunks: number,
  startS: number,
  endS: number,
  session: SessionState
): string {
  const header = `CHUNK ${chunkNum}/${totalChunks} | ${formatMmSsTenths(startS)}–${formatMmSsTenths(endS)}`;
  const callSoFar =
    session.transcript.length > 0
      ? session.transcript.map((t) => `${t.speaker}: ${t.text}`).join('\n')
      : '(call just started)';
  const flagsStr =
    session.red_flags.length > 0
      ? session.red_flags.map((f) => `${f.type} "${f.quote}"`).join('; ')
      : 'none';
  const signalsStr =
    session.genuine_signals.length > 0
      ? session.genuine_signals.map((s) => `"${s.quote}"`).join('; ')
      : 'none';

  return [
    header,
    'CALL SO FAR:',
    callSoFar,
    `RED FLAGS SO FAR: ${flagsStr}`,
    `GENUINE SIGNALS SO FAR: ${signalsStr}`,
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

export function applySessionRules(
  session: SessionState,
  chunkIndex: number,
  startS: number,
  endS: number,
  chunkResult: any
): any {
  if (chunkResult.status !== 'ok') {
    const unavailableRecord = {
      chunk_index: chunkIndex,
      start_s: startS,
      end_s: endS,
      status: 'unavailable',
      error: chunkResult.error || 'Analysis unavailable',
      latency_ms: chunkResult.latency_ms || 0,
      verdict: 'unavailable',
      risk_score: session.risk,
      transcript: [],
      new_red_flags: [],
      new_genuine_signals: [],
      warning_gu: session.warning_gu,
      warning_hi: session.warning_hi,
      warning_en: session.warning_en,
    };
    session.chunks.push(unavailableRecord);
    return unavailableRecord;
  }

  const chunkTurns: TranscriptTurn[] = [];
  for (const turn of chunkResult.transcript || []) {
    const entry: TranscriptTurn = {
      speaker: turn.speaker,
      text: turn.text,
      chunk_index: chunkIndex,
      start_s: startS,
      end_s: endS,
    };
    session.transcript.push(entry);
    chunkTurns.push(entry);
  }

  const existingKeys = new Set(session.red_flags.map((f) => `${f.type}::${f.quote}`));
  const newFlags: RedFlagItem[] = chunkResult.new_red_flags || [];
  const addedFlags: RedFlagItem[] = [];

  for (const flag of newFlags) {
    const key = `${flag.type}::${flag.quote}`;
    const enriched: RedFlagItem = {
      type: flag.type,
      quote: flag.quote,
      why: flag.why,
      chunk_index: chunkIndex,
      start_s: startS,
      end_s: endS,
      time_mm_ss: formatMmSs(endS),
    };
    addedFlags.push(enriched);
    if (!existingKeys.has(key)) {
      session.red_flags.push(enriched);
      existingKeys.add(key);
    }
  }

  const addedSignals: GenuineSignalItem[] = [];
  for (const sig of chunkResult.new_genuine_signals || []) {
    const enrichedSig: GenuineSignalItem = {
      quote: sig.quote,
      why: sig.why,
      chunk_index: chunkIndex,
      start_s: startS,
      end_s: endS,
      time_mm_ss: formatMmSs(endS),
    };
    session.genuine_signals.push(enrichedSig);
    addedSignals.push(enrichedSig);
  }

  const modelRisk = Number(chunkResult.risk_score ?? 0);
  const modelVerdict = verdictFromRisk(modelRisk);
  let finalRisk = modelRisk;

  // Rule 1: new OTP_OR_CREDENTIALS, MONEY_REQUEST, REMOTE_ACCESS_OR_LINK, SECRECY or HANDOFF_TO_OFFICIAL -> risk >= 75
  if (newFlags.some((f) => HARD_RED_FLAGS.has(f.type))) {
    finalRisk = Math.max(finalRisk, 75);
  }

  // Rule 2: accumulated AUTHORITY_CLAIM + THREAT + URGENCY -> risk >= 70
  const accTypes = new Set(session.red_flags.map((f) => f.type));
  if (TRIO_RED_FLAGS.every((t) => accTypes.has(t))) {
    finalRisk = Math.max(finalRisk, 70);
  }

  // Rule 3: once SCAM, risk never drops below 70; SUSPICIOUS may fall back to SAFE
  if (session.ever_scam) {
    finalRisk = Math.max(finalRisk, 70);
  }

  // Rule 4: displayed verdict comes from final risk: <30 SAFE, 30-69 SUSPICIOUS, >=70 SCAM
  const finalVerdict = verdictFromRisk(finalRisk);

  if (finalVerdict === 'SCAM') {
    session.ever_scam = true;
    if (session.first_scam_at === null) {
      session.first_scam_at = Number(endS.toFixed(2));
    }
  }

  if (chunkResult.scam_type && chunkResult.scam_type !== 'NONE') {
    session.scam_type = chunkResult.scam_type;
  }

  let warningGu = String(chunkResult.warning_gu || '')
    .trim()
    .replace(/सावधान!/g, 'સાવધાન!')
    .replace(/સાપવધાન!/g, 'સાવધાન!');
  let warningHi = String(chunkResult.warning_hi || '').trim();
  let warningEn = String(chunkResult.warning_en || '').trim();

  const rank: Record<string, number> = { SAFE: 0, SUSPICIOUS: 1, SCAM: 2 };
  const ruleRaisedVerdict = rank[finalVerdict] > rank[modelVerdict];

  if (finalVerdict === 'SCAM' && (ruleRaisedVerdict || !warningGu || !warningHi)) {
    if (!warningGu) warningGu = SCAM_FALLBACK_GU;
    if (!warningHi) warningHi = SCAM_FALLBACK_HI;
    if (!warningEn) warningEn = SCAM_FALLBACK_EN;
  } else if (finalVerdict === 'SUSPICIOUS' && ruleRaisedVerdict) {
    if (!warningGu) warningGu = SUSPICIOUS_FALLBACK_GU;
    if (!warningHi) warningHi = SUSPICIOUS_FALLBACK_HI;
    if (!warningEn) warningEn = SUSPICIOUS_FALLBACK_EN;
  }

  if (finalVerdict === 'SCAM' && session.red_flags.length > 0) {
    const allQuotes = session.red_flags.map((f) => f.quote).filter(Boolean);
    const latestQuote = (addedFlags[addedFlags.length - 1] || session.red_flags[session.red_flags.length - 1]).quote;
    if (allQuotes.length > 0 && !allQuotes.some((q) => warningGu.includes(q))) {
      warningGu = `${warningGu} ("${latestQuote}")`;
    }
    if (allQuotes.length > 0 && !allQuotes.some((q) => warningHi.includes(q))) {
      warningHi = `${warningHi} ("${latestQuote}")`;
    }
    if (allQuotes.length > 0 && !allQuotes.some((q) => warningEn.includes(q))) {
      warningEn = `${warningEn} ("${latestQuote}")`;
    }
  }

  session.risk = finalRisk;
  session.verdict = finalVerdict;
  if (warningGu) session.warning_gu = warningGu;
  if (warningHi) session.warning_hi = warningHi;
  if (warningEn) session.warning_en = warningEn;

  const processed = {
    chunk_index: chunkIndex,
    start_s: startS,
    end_s: endS,
    status: 'ok',
    latency_ms: chunkResult.latency_ms || 0,
    model: chunkResult.model || '',
    transcript: chunkTurns,
    new_red_flags: addedFlags,
    new_genuine_signals: addedSignals,
    scam_type: session.scam_type,
    model_risk_score: modelRisk,
    risk_score: finalRisk,
    verdict: finalVerdict,
    warning_gu: warningGu || session.warning_gu,
    warning_hi: warningHi || session.warning_hi,
    warning_en: warningEn || session.warning_en,
  };
  session.chunks.push(processed);
  return processed;
}
