/**
 * Stores an uploaded .wav as a new playable call: validates it, converts it to 16 kHz mono PCM
 * (like scripts/prep.sh) and registers it in the manifest. Uploads are namespaced with "upload_"
 * so they can never overwrite the curated demo calls, and their number is capped.
 */
import { execFile } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { mkdirSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { promisify } from 'node:util';
import type { CallCatalog } from './calls.ts';
import { HttpError } from './errors.ts';
import type { ManifestEntry } from './types.ts';
import { decodeBase64Strict, type UploadRequest, validateWavUpload } from './validation.ts';
import { InvalidWavError, isPcm16, readWavInfo, type WavInfo } from './wav.ts';

const execFileAsync = promisify(execFile);
export const UPLOAD_PREFIX = 'upload_';
const MAX_TITLE_LENGTH = 120;

/** Converts inputPath to a 16 kHz mono 16-bit PCM WAV at outputPath. */
export type AudioConverter = (inputPath: string, outputPath: string) => Promise<void>;

export function createFfmpegConverter(timeoutMs: number): AudioConverter {
  return async (inputPath, outputPath) => {
    await execFileAsync(
      'ffmpeg',
      [
        '-y',
        '-hide_banner',
        '-loglevel',
        'error',
        '-i',
        inputPath,
        '-ar',
        '16000',
        '-ac',
        '1',
        '-c:a',
        'pcm_s16le',
        outputPath,
      ],
      { timeout: timeoutMs, maxBuffer: 1024 * 1024 },
    );
  };
}

export interface UploadDependencies {
  catalog: CallCatalog;
  rawCallsDir: string;
  maxUploadedCalls: number;
  convert: AudioConverter;
  logger?: Pick<Console, 'warn'>;
}

function displayName(fileName: string): string {
  const baseName = fileName.split(/[\\/]/).at(-1) ?? fileName;
  return baseName.replace(/\.wav$/i, '').slice(0, 80);
}

function parseWav(audio: Buffer): WavInfo {
  try {
    return readWavInfo(audio);
  } catch (error) {
    if (error instanceof InvalidWavError) throw new HttpError(400, error.message);
    throw error;
  }
}

async function writePlayableAudio(
  audio: Buffer,
  info: WavInfo,
  fileName: string,
  deps: UploadDependencies,
): Promise<void> {
  const { catalog, rawCallsDir, convert, logger = console } = deps;
  mkdirSync(rawCallsDir, { recursive: true });
  mkdirSync(catalog.callsDir, { recursive: true });
  const rawPath = path.join(rawCallsDir, fileName);
  writeFileSync(rawPath, audio);

  // Convert into a temp file and rename, so a half-written WAV is never served.
  const tempPath = path.join(catalog.callsDir, `.${randomUUID()}.converting.wav`);
  try {
    await convert(rawPath, tempPath);
  } catch (error) {
    rmSync(tempPath, { force: true });
    if (!isPcm16(info)) {
      throw new HttpError(
        422,
        'Could not convert this recording. Install ffmpeg or upload a 16-bit PCM .wav file.',
      );
    }
    logger.warn(`[upload] ffmpeg unavailable (${(error as Error).message}); storing PCM as-is.`);
    writeFileSync(tempPath, audio);
  }
  renameSync(tempPath, catalog.wavPath(fileName));
}

export async function storeUpload(
  request: UploadRequest,
  deps: UploadDependencies,
): Promise<ManifestEntry> {
  const audio = decodeBase64Strict(request.data_base64);
  if (!audio) throw new HttpError(400, 'Invalid base64 audio payload.');

  const check = validateWavUpload(request.filename, audio.length, audio.subarray(0, 12));
  if (!check.valid || !check.sanitizedStem) {
    throw new HttpError(400, check.error ?? 'Invalid .wav file.');
  }
  const info = parseWav(audio);

  const fileName = `${UPLOAD_PREFIX}${check.sanitizedStem}.wav`;
  const manifest = deps.catalog.loadManifest();
  const existing = manifest.find((entry) => entry.file === fileName);
  const uploadedCount = manifest.filter((entry) => entry.uploaded).length;
  if (!existing && uploadedCount >= deps.maxUploadedCalls) {
    throw new HttpError(
      409,
      `Upload limit reached (${deps.maxUploadedCalls} recordings). Remove older uploads first.`,
    );
  }

  await writePlayableAudio(audio, info, fileName, deps);
  deps.catalog.forget(fileName);

  const entry: ManifestEntry = {
    file: fileName,
    title: (request.title?.trim() || `Uploaded — ${displayName(request.filename)}`).slice(
      0,
      MAX_TITLE_LENGTH,
    ),
    expected: request.expected === 'SAFE' ? 'SAFE' : 'SCAM',
    uploaded: true,
  };
  const updated = existing
    ? manifest.map((item) => (item.file === fileName ? { ...item, ...entry } : item))
    : [...manifest, entry];
  deps.catalog.saveManifest(updated);
  return existing ? { ...existing, ...entry } : entry;
}
