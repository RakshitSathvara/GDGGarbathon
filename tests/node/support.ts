/**
 * Shared test utilities: synthetic WAV generation, an isolated temp copy of the project,
 * scripted detectors and an ephemeral HTTP server.
 */
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Express } from 'express';
import { type AppConfig, loadConfig } from '../../server/config.ts';
import type { Detector } from '../../server/detector.ts';
import type { ChunkAnalysis, DetectorResult, ManifestEntry } from '../../server/types.ts';

export const REPO_ROOT = fileURLToPath(new URL('../..', import.meta.url));
export const FIXTURES_DIR = path.join(REPO_ROOT, 'tests', 'fixtures');

export function readFixture<T>(name: string): T {
  return JSON.parse(readFileSync(path.join(FIXTURES_DIR, name), 'utf8')) as T;
}

export interface WavSegment {
  seconds: number;
  /** Peak amplitude of a 440 Hz tone; 0 = silence. */
  amplitude: number;
}

export interface WavOptions {
  sampleRate?: number;
  channels?: number;
  bitsPerSample?: number;
  audioFormat?: number;
  /** Extra RIFF chunk (e.g. LIST) inserted between fmt and data. */
  extraChunk?: { id: string; body: Buffer };
}

/** Builds a canonical PCM WAV from tone/silence segments. */
export function makeWav(segments: WavSegment[], options: WavOptions = {}): Buffer {
  const {
    sampleRate = 16_000,
    channels = 1,
    bitsPerSample = 16,
    audioFormat = 1,
    extraChunk,
  } = options;
  const bytesPerSample = bitsPerSample / 8;
  const frames = segments.reduce((sum, s) => sum + Math.round(s.seconds * sampleRate), 0);
  const data = Buffer.alloc(frames * channels * bytesPerSample);
  let frame = 0;
  for (const segment of segments) {
    const count = Math.round(segment.seconds * sampleRate);
    for (let i = 0; i < count; i++, frame++) {
      const value = Math.round(
        segment.amplitude * Math.sin((2 * Math.PI * 440 * frame) / sampleRate),
      );
      for (let c = 0; c < channels; c++) {
        const offset = (frame * channels + c) * bytesPerSample;
        if (bytesPerSample === 2) data.writeInt16LE(value, offset);
        else data.writeUInt8(128 + Math.round(value / 256), offset);
      }
    }
  }

  const fmt = Buffer.alloc(24);
  fmt.write('fmt ', 0, 'ascii');
  fmt.writeUInt32LE(16, 4);
  fmt.writeUInt16LE(audioFormat, 8);
  fmt.writeUInt16LE(channels, 10);
  fmt.writeUInt32LE(sampleRate, 12);
  fmt.writeUInt32LE(sampleRate * channels * bytesPerSample, 16);
  fmt.writeUInt16LE(channels * bytesPerSample, 20);
  fmt.writeUInt16LE(bitsPerSample, 22);

  const extra = extraChunk ? riffChunk(extraChunk.id, extraChunk.body) : Buffer.alloc(0);
  const dataChunk = riffChunk('data', data);
  const header = Buffer.alloc(12);
  header.write('RIFF', 0, 'ascii');
  header.writeUInt32LE(4 + fmt.length + extra.length + dataChunk.length, 4);
  header.write('WAVE', 8, 'ascii');
  return Buffer.concat([header, fmt, extra, dataChunk]);
}

function riffChunk(id: string, body: Buffer): Buffer {
  const head = Buffer.alloc(8);
  head.write(id, 0, 'ascii');
  head.writeUInt32LE(body.length, 4);
  return Buffer.concat([head, body, body.length % 2 ? Buffer.alloc(1) : Buffer.alloc(0)]);
}

export interface TempProject {
  root: string;
  config: AppConfig;
  writeManifest(entries: ManifestEntry[]): void;
  readManifest(): ManifestEntry[];
  cleanup(): void;
}

/** Isolated copy of static/ plus selected demo calls, so tests never touch the real repo. */
export function createTempProject(
  calls: string[] = ['fake_kyc.wav'],
  env: Record<string, string> = {},
): TempProject {
  const root = mkdtempSync(path.join(tmpdir(), 'saavdhan-test-'));
  const callsDir = path.join(root, 'calls');
  mkdirSync(path.join(callsDir, 'raw'), { recursive: true });
  mkdirSync(path.join(root, 'cache'), { recursive: true });
  cpSync(path.join(REPO_ROOT, 'static'), path.join(root, 'static'), { recursive: true });
  cpSync(path.join(REPO_ROOT, 'prompts'), path.join(root, 'prompts'), { recursive: true });

  const demoManifest = JSON.parse(
    readFileSync(path.join(REPO_ROOT, 'calls', 'manifest.json'), 'utf8'),
  ) as ManifestEntry[];
  for (const file of calls) {
    cpSync(path.join(REPO_ROOT, 'calls', file), path.join(callsDir, file));
  }
  const manifestPath = path.join(callsDir, 'manifest.json');
  const project: TempProject = {
    root,
    config: loadConfig(env, root),
    writeManifest(entries) {
      writeFileSync(manifestPath, JSON.stringify(entries, null, 2));
    },
    readManifest() {
      return JSON.parse(readFileSync(manifestPath, 'utf8')) as ManifestEntry[];
    },
    cleanup() {
      rmSync(root, { recursive: true, force: true });
    },
  };
  project.writeManifest(demoManifest.filter((entry) => calls.includes(entry.file)));
  return project;
}

export function analysis(overrides: Partial<ChunkAnalysis> = {}): ChunkAnalysis {
  return {
    transcript: [],
    new_red_flags: [],
    new_genuine_signals: [],
    scam_type: 'NONE',
    risk_score: 0,
    verdict: 'SAFE',
    warning_gu: '',
    warning_hi: '',
    warning_en: '',
    ...overrides,
  };
}

/** Detector that replies from a script keyed by chunk number and records every call. */
export function scriptedDetector(script: (chunkNumber: number) => DetectorResult) {
  const calls: { wav: Buffer; contextBlock: string }[] = [];
  const detector: Detector = {
    async analyze(wav, contextBlock) {
      calls.push({ wav, contextBlock });
      const chunkNumber = Number(/^CHUNK (\d+)\//.exec(contextBlock)?.[1] ?? 0);
      return script(chunkNumber);
    },
  };
  return { detector, calls };
}

export async function startServer(app: Express): Promise<{ url: string; close(): Promise<void> }> {
  const server = app.listen(0, '127.0.0.1');
  await new Promise<void>((resolve) => server.once('listening', resolve));
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}`,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

export const silentLogger = { warn() {}, error() {} };
