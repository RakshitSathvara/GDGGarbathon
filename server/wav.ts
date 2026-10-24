/**
 * WAV parsing, silence-aware chunking and slicing. Pure functions over Buffers.
 * Mirrors app/chunker.py; tests/fixtures/chunk_boundaries.json pins both to identical output.
 */
import { MIN_CHUNK_SEC } from './config.ts';

export const FRAME_MS = 20;
export const SEARCH_WINDOW_SEC = 1;
const WAV_HEADER_BYTES = 44;
const PCM_FORMAT = 1;
const EXTENSIBLE_FORMAT = 0xfffe;

export class InvalidWavError extends Error {
  override name = 'InvalidWavError';
}

export interface WavInfo {
  audioFormat: number;
  numChannels: number;
  sampleRate: number;
  bitsPerSample: number;
  blockAlign: number;
  dataOffset: number;
  dataSize: number;
  totalFrames: number;
  durationSec: number;
}

export type Boundary = [startS: number, endS: number];

const round3 = (value: number) => Number(value.toFixed(3));

/** Walks the RIFF chunks and returns the audio format plus the location of the PCM data. */
export function readWavInfo(buf: Buffer): WavInfo {
  if (
    buf.length < 12 ||
    buf.toString('ascii', 0, 4) !== 'RIFF' ||
    buf.toString('ascii', 8, 12) !== 'WAVE'
  ) {
    throw new InvalidWavError('Invalid WAV file header (expected RIFF/WAVE).');
  }

  let format: Pick<WavInfo, 'audioFormat' | 'numChannels' | 'sampleRate' | 'bitsPerSample'> | null =
    null;
  let offset = 12;
  while (offset + 8 <= buf.length) {
    const chunkId = buf.toString('ascii', offset, offset + 4);
    const chunkSize = buf.readUInt32LE(offset + 4);
    const body = offset + 8;
    if (chunkId === 'fmt ' && chunkSize >= 16 && body + 16 <= buf.length) {
      format = {
        audioFormat: buf.readUInt16LE(body),
        numChannels: buf.readUInt16LE(body + 2),
        sampleRate: buf.readUInt32LE(body + 4),
        bitsPerSample: buf.readUInt16LE(body + 14),
      };
    } else if (chunkId === 'data') {
      if (!format) break;
      const dataSize = Math.min(chunkSize, buf.length - body);
      const blockAlign = format.numChannels * Math.ceil(format.bitsPerSample / 8);
      if (format.numChannels < 1 || format.sampleRate < 1 || blockAlign < 1) break;
      const totalFrames = Math.floor(dataSize / blockAlign);
      return {
        ...format,
        blockAlign,
        dataOffset: body,
        dataSize,
        totalFrames,
        durationSec: round3(totalFrames / format.sampleRate),
      };
    }
    offset = body + chunkSize + (chunkSize % 2);
  }
  throw new InvalidWavError('The .wav file is empty or corrupted.');
}

export function isPcm16(info: WavInfo): boolean {
  return (
    info.bitsPerSample === 16 &&
    (info.audioFormat === PCM_FORMAT || info.audioFormat === EXTENSIBLE_FORMAT)
  );
}

/** RMS energy of each 20 ms frame (channels averaged), used to find natural pauses. */
export function computeFrameRms(buf: Buffer, info: WavInfo, frameMs = FRAME_MS): number[] {
  if (!isPcm16(info)) throw new InvalidWavError('Only 16-bit PCM audio can be chunked.');
  const frameSamples = Math.max(1, Math.floor((info.sampleRate * frameMs) / 1000));
  const frameCount = Math.floor(info.totalFrames / frameSamples);
  if (frameCount === 0) return [0];

  const rms = new Array<number>(frameCount);
  for (let frame = 0; frame < frameCount; frame++) {
    let sumSquares = 0;
    for (let i = 0; i < frameSamples; i++) {
      const base = info.dataOffset + (frame * frameSamples + i) * info.blockAlign;
      let sample = 0;
      for (let channel = 0; channel < info.numChannels; channel++) {
        sample += buf.readInt16LE(base + channel * 2);
      }
      sample /= info.numChannels;
      sumSquares += sample * sample;
    }
    rms[frame] = Math.sqrt(sumSquares / frameSamples);
  }
  return rms;
}

/**
 * Cuts the call into ~targetSec chunks, placing each cut on the quietest 20 ms frame within
 * ±1 s of the target so words are not split. Chunks are at least 3 s; a short tail is merged back.
 */
export function computeChunkBoundaries(
  frameRms: readonly number[],
  durationSec: number,
  targetSec: number,
): Boundary[] {
  const chunkSec = Math.max(MIN_CHUNK_SEC, targetSec);
  if (durationSec <= 0) return [];
  if (durationSec <= chunkSec) return [[0, round3(durationSec)]];

  const frameSec = FRAME_MS / 1000;
  const boundaries: Boundary[] = [];
  let cursor = 0;

  while (cursor < durationSec) {
    if (durationSec - cursor <= chunkSec) {
      boundaries.push([round3(cursor), round3(durationSec)]);
      break;
    }

    const idealCut = cursor + chunkSec;
    const windowStart = Math.max(cursor + MIN_CHUNK_SEC, idealCut - SEARCH_WINDOW_SEC);
    const windowEnd = Math.min(durationSec, idealCut + SEARCH_WINDOW_SEC);
    const startIdx = Math.max(0, Math.round(windowStart / frameSec));
    const endIdx = Math.min(frameRms.length - 1, Math.round(windowEnd / frameSec));

    let cut = round3(idealCut);
    if (startIdx <= endIdx) {
      let quietest = startIdx;
      for (let idx = startIdx + 1; idx <= endIdx; idx++) {
        if ((frameRms[idx] ?? Number.POSITIVE_INFINITY) < (frameRms[quietest] ?? 0)) quietest = idx;
      }
      cut = round3(quietest * frameSec);
    }
    if (cut - cursor < MIN_CHUNK_SEC) cut = round3(Math.min(durationSec, cursor + chunkSec));

    boundaries.push([round3(cursor), cut]);
    cursor = cut;
  }

  const last = boundaries.at(-1);
  const previous = boundaries.at(-2);
  if (last && previous && last[1] - last[0] < MIN_CHUNK_SEC) {
    boundaries.splice(-2, 2, [previous[0], last[1]]);
  }
  return boundaries;
}

export function computeChunks(
  buf: Buffer,
  targetSec: number,
  info: WavInfo = readWavInfo(buf),
): { boundaries: Boundary[]; duration: number } {
  const needsCuts = info.durationSec > Math.max(MIN_CHUNK_SEC, targetSec);
  const frameRms = needsCuts ? computeFrameRms(buf, info) : [];
  return {
    boundaries: computeChunkBoundaries(frameRms, info.durationSec, targetSec),
    duration: info.durationSec,
  };
}

/** Returns a standalone 44-byte-header PCM WAV containing [startS, endS] of the source. */
export function sliceWav(buf: Buffer, info: WavInfo, startS: number, endS: number): Buffer {
  const startFrame = Math.max(0, Math.min(info.totalFrames, Math.round(startS * info.sampleRate)));
  const endFrame = Math.max(
    startFrame,
    Math.min(info.totalFrames, Math.round(endS * info.sampleRate)),
  );
  const pcmStart = info.dataOffset + startFrame * info.blockAlign;
  const pcm = buf.subarray(pcmStart, pcmStart + (endFrame - startFrame) * info.blockAlign);

  const header = Buffer.alloc(WAV_HEADER_BYTES);
  header.write('RIFF', 0, 'ascii');
  header.writeUInt32LE(36 + pcm.length, 4);
  header.write('WAVE', 8, 'ascii');
  header.write('fmt ', 12, 'ascii');
  header.writeUInt32LE(16, 16);
  header.writeUInt16LE(PCM_FORMAT, 20);
  header.writeUInt16LE(info.numChannels, 22);
  header.writeUInt32LE(info.sampleRate, 24);
  header.writeUInt32LE(info.sampleRate * info.blockAlign, 28);
  header.writeUInt16LE(info.blockAlign, 32);
  header.writeUInt16LE(info.bitsPerSample, 34);
  header.write('data', 36, 'ascii');
  header.writeUInt32LE(pcm.length, 40);
  return Buffer.concat([header, pcm]);
}
