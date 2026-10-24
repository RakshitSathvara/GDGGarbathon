/**
 * Pure, DOM-free helpers for the Saavdhan UI. Unit-tested in tests/node/ui-helpers.test.ts.
 */

export const MAX_WAV_BYTES = 10 * 1024 * 1024;
const WAV_HEADER_BYTES = 44;

/** 75.4 -> "1:15" */
export function formatClock(sec) {
  const total = Math.max(0, Math.round(sec || 0));
  return `${Math.floor(total / 60)}:${String(total % 60).padStart(2, '0')}`;
}

/** 75.9 -> "01:15" (floored, for running timers) */
export function formatPaddedClock(sec) {
  const total = Math.max(0, Math.floor(sec || 0));
  const minutes = String(Math.floor(total / 60)).padStart(2, '0');
  return `${minutes}:${String(total % 60).padStart(2, '0')}`;
}

/** (0, 6.18) -> "0.0s–6.2s" */
export function formatSpan(startS, endS) {
  return `${startS.toFixed(1)}s–${endS.toFixed(1)}s`;
}

/**
 * Client-side checks mirroring the server, so mistakes are reported before uploading.
 * @param {{ name: string, size: number } | null | undefined} file
 * @returns {string | null} an error message, or null when the file is acceptable
 */
export function validateWavFile(file) {
  if (!file) return 'Please select a .wav file to upload.';
  if (
    !String(file.name || '')
      .trim()
      .toLowerCase()
      .endsWith('.wav')
  ) {
    return 'Only .wav files are allowed.';
  }
  if (file.size <= WAV_HEADER_BYTES) return 'The selected .wav file is empty or corrupted.';
  if (file.size > MAX_WAV_BYTES) {
    const mb = (file.size / (1024 * 1024)).toFixed(2);
    return `File size (${mb} MB) exceeds the 10 MB maximum limit.`;
  }
  return null;
}

/** @param {Uint8Array} bytes first bytes of the file */
export function hasWavHeader(bytes) {
  const ascii = (start, end) => String.fromCharCode(...bytes.subarray(start, end));
  return bytes.length >= 12 && ascii(0, 4) === 'RIFF' && ascii(8, 12) === 'WAVE';
}

/** Base64-encodes an ArrayBuffer in 32 KB slices to stay within argument limits. */
export function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  const slices = [];
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    slices.push(String.fromCharCode(...bytes.subarray(offset, offset + 0x8000)));
  }
  return btoa(slices.join(''));
}

/**
 * Splits text into plain / flagged / genuine segments for highlighting. Red-flag quotes win over
 * genuine ones, longer quotes win over shorter ones, and highlights never overlap.
 * @param {string} text
 * @param {string[]} flagQuotes
 * @param {string[]} genuineQuotes
 * @returns {{ text: string, kind: 'plain' | 'flag' | 'genuine' }[]}
 */
export function highlightSegments(text, flagQuotes = [], genuineQuotes = []) {
  const source = String(text ?? '');
  /** @type {{ start: number, end: number, kind: 'flag' | 'genuine' }[]} */
  const ranges = [];
  const claim = (quotes, kind) => {
    const unique = [...new Set(quotes.filter(Boolean))].sort((a, b) => b.length - a.length);
    for (const quote of unique) {
      for (let at = source.indexOf(quote); at !== -1; at = source.indexOf(quote, at + 1)) {
        const end = at + quote.length;
        if (!ranges.some((range) => at < range.end && end > range.start)) {
          ranges.push({ start: at, end, kind });
        }
      }
    }
  };
  claim(flagQuotes, 'flag');
  claim(genuineQuotes, 'genuine');
  ranges.sort((a, b) => a.start - b.start);

  /** @type {{ text: string, kind: 'plain' | 'flag' | 'genuine' }[]} */
  const segments = [];
  let cursor = 0;
  for (const range of ranges) {
    if (range.start > cursor)
      segments.push({ text: source.slice(cursor, range.start), kind: 'plain' });
    segments.push({ text: source.slice(range.start, range.end), kind: range.kind });
    cursor = range.end;
  }
  if (cursor < source.length || segments.length === 0) {
    segments.push({ text: source.slice(cursor), kind: 'plain' });
  }
  return segments;
}

/**
 * Language tag for dynamic transcript text, so screen readers switch voice:
 * Gujarati script -> "gu", Devanagari -> "hi", otherwise undefined (inherit).
 */
export function detectScriptLang(text) {
  if (/[઀-૿]/.test(text)) return 'gu';
  if (/[ऀ-ॿ]/.test(text)) return 'hi';
  return undefined;
}

/**
 * Chunks whose audio the playhead has fully passed and that were not sent yet.
 * The final chunk is only released once playback ends.
 * @param {{ index: number, end_s: number }[]} chunks
 * @param {number} currentTime
 * @param {Set<number>} sent
 * @param {boolean} callEnded
 */
export function chunksReadyToSend(chunks, currentTime, sent, callEnded) {
  return chunks
    .filter((chunk, position) => {
      if (sent.has(chunk.index)) return false;
      const isLast = position === chunks.length - 1;
      return currentTime >= chunk.end_s || (isLast && callEnded);
    })
    .map((chunk) => chunk.index);
}

/** Seconds the analysis trails the playhead. @param {Iterable<{ end_s: number }>} results */
export function analysisLag(currentTime, results) {
  let analyzedUntil = 0;
  for (const result of results) analyzedUntil = Math.max(analyzedUntil, result.end_s || 0);
  return Math.max(0, (currentTime || 0) - analyzedUntil);
}

/**
 * How many seconds before the caller's first demand the scam warning fired
 * (negative = after). Null when either time is unknown.
 */
export function warningLead(firstScamAt, firstDemandAt) {
  if (firstScamAt == null || firstDemandAt == null) return null;
  return Math.round((firstDemandAt - firstScamAt) * 10) / 10;
}

/**
 * Visual state of one timeline cell.
 * @param {{ status: string, verdict: string, risk_score: number, latency_ms: number } | undefined} result
 * @param {{ queued: boolean, analyzing: boolean }} queueState
 */
export function describeChunkState(result, { queued, analyzing }) {
  if (result) {
    const verdict = result.status === 'unavailable' ? 'unavailable' : result.verdict;
    return {
      verdict,
      label: verdict === 'unavailable' ? 'UNAVAIL' : `${verdict} (${result.risk_score})`,
      latency: `${result.latency_ms} ms`,
    };
  }
  if (queued)
    return { verdict: 'inflight', label: analyzing ? 'Analyzing…' : 'Queued', latency: '—' };
  return { verdict: 'pending', label: 'Pending', latency: '—' };
}
