/**
 * Call catalog: reads calls/manifest.json, computes chunk boundaries once per audio file version,
 * and keeps a small LRU of decoded audio so live analysis never re-reads a WAV per chunk.
 */
import { randomUUID } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, renameSync, statSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import type { CallChunk, CallMeta, ManifestEntry } from './types.ts';
import { manifestEntrySchema } from './validation.ts';
import { computeChunks, readWavInfo, type WavInfo } from './wav.ts';

export interface CatalogOptions {
  callsDir: string;
  cacheDir: string;
  manifestPath: string;
  chunkSec: number;
  audioCacheEntries: number;
  logger?: Pick<Console, 'warn'>;
}

export interface LoadedAudio {
  buffer: Buffer;
  info: WavInfo;
}

interface ChunkPlan {
  mtimeMs: number;
  duration: number;
  chunks: CallChunk[];
}

function modifiedAt(filePath: string): number | null {
  try {
    return statSync(filePath).mtimeMs;
  } catch {
    return null;
  }
}

export const callIdOf = (file: string): string => path.parse(file).name;

export class CallCatalog {
  readonly #options: Required<CatalogOptions>;
  readonly #plans = new Map<string, ChunkPlan>();
  readonly #audio = new Map<string, { mtimeMs: number; audio: LoadedAudio }>();

  constructor(options: CatalogOptions) {
    this.#options = { logger: console, ...options };
  }

  get callsDir(): string {
    return this.#options.callsDir;
  }

  loadManifest(): ManifestEntry[] {
    const { manifestPath, logger } = this.#options;
    if (!existsSync(manifestPath)) return [];
    let raw: unknown;
    try {
      raw = JSON.parse(readFileSync(manifestPath, 'utf8'));
    } catch (error) {
      logger.warn(`[calls] Ignoring unreadable manifest: ${(error as Error).message}`);
      return [];
    }
    if (!Array.isArray(raw)) return [];

    const entries: ManifestEntry[] = [];
    for (const item of raw) {
      const parsed = manifestEntrySchema.safeParse(item);
      if (parsed.success) entries.push(parsed.data);
      else logger.warn(`[calls] Skipping invalid manifest entry: ${JSON.stringify(item)}`);
    }
    return entries;
  }

  /** Atomic write (temp file + rename) so readers never observe a half-written manifest. */
  saveManifest(entries: readonly ManifestEntry[]): void {
    const { manifestPath } = this.#options;
    mkdirSync(path.dirname(manifestPath), { recursive: true });
    const tempPath = `${manifestPath}.${randomUUID()}.tmp`;
    writeFileSync(tempPath, `${JSON.stringify(entries, null, 2)}\n`, 'utf8');
    renameSync(tempPath, manifestPath);
  }

  findEntry(callId: string): ManifestEntry | undefined {
    return this.loadManifest().find(
      (entry) => callIdOf(entry.file) === callId || entry.file === callId,
    );
  }

  list(): CallMeta[] {
    return this.loadManifest().map((entry) => this.describe(entry));
  }

  describe(entry: ManifestEntry): CallMeta {
    const id = callIdOf(entry.file);
    const plan = this.#planFor(entry.file);
    return {
      id,
      file: entry.file,
      title: entry.title,
      expected: entry.expected,
      first_demand_at: entry.first_demand_at ?? null,
      duration: plan.duration,
      chunks: plan.chunks,
      has_cache: existsSync(this.cachePath(id)),
    };
  }

  wavPath(file: string): string {
    return path.join(this.#options.callsDir, path.basename(file));
  }

  cachePath(callId: string): string {
    return path.join(this.#options.cacheDir, `${path.basename(callId)}.json`);
  }

  /** Decoded audio for a call, or null when the file does not exist. Throws InvalidWavError. */
  readAudio(file: string): LoadedAudio | null {
    const filePath = this.wavPath(file);
    const mtimeMs = modifiedAt(filePath);
    if (mtimeMs === null) return null;

    const cached = this.#audio.get(file);
    if (cached && cached.mtimeMs === mtimeMs) {
      this.#audio.delete(file);
      this.#audio.set(file, cached);
      return cached.audio;
    }

    const buffer = readFileSync(filePath);
    const audio = { buffer, info: readWavInfo(buffer) };
    this.#audio.delete(file);
    this.#audio.set(file, { mtimeMs, audio });
    while (this.#audio.size > this.#options.audioCacheEntries) {
      const oldest = this.#audio.keys().next().value;
      if (oldest === undefined) break;
      this.#audio.delete(oldest);
    }
    return audio;
  }

  readReplayCache(callId: string): unknown {
    const cachePath = this.cachePath(callId);
    if (!existsSync(cachePath)) return null;
    return JSON.parse(readFileSync(cachePath, 'utf8'));
  }

  forget(file: string): void {
    this.#plans.delete(file);
    this.#audio.delete(file);
  }

  #planFor(file: string): ChunkPlan {
    const mtimeMs = modifiedAt(this.wavPath(file)) ?? 0;
    const cached = this.#plans.get(file);
    if (cached && cached.mtimeMs === mtimeMs) return cached;

    let plan: ChunkPlan = { mtimeMs, duration: 0, chunks: [] };
    try {
      const audio = this.readAudio(file);
      if (audio) {
        const { boundaries, duration } = computeChunks(
          audio.buffer,
          this.#options.chunkSec,
          audio.info,
        );
        const chunks = boundaries.map(([start_s, end_s], index) => ({ index, start_s, end_s }));
        plan = { mtimeMs, duration, chunks };
      }
    } catch (error) {
      this.#options.logger.warn(`[calls] Cannot chunk ${file}: ${(error as Error).message}`);
    }
    this.#plans.set(file, plan);
    return plan;
  }
}
