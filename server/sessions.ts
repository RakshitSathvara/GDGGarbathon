/**
 * In-memory session store with sliding expiry, a hard size cap (LRU eviction) and
 * per-session task serialization so concurrent requests cannot interleave session updates.
 */

export interface SessionStoreOptions {
  ttlMs: number;
  maxSessions: number;
  now?: () => number;
}

interface Entry<T> {
  value: T;
  expiresAt: number;
  queue: Promise<unknown>;
}

export class SessionStore<T> {
  readonly #entries = new Map<string, Entry<T>>();
  readonly #ttlMs: number;
  readonly #maxSessions: number;
  readonly #now: () => number;

  constructor({ ttlMs, maxSessions, now = Date.now }: SessionStoreOptions) {
    this.#ttlMs = ttlMs;
    this.#maxSessions = maxSessions;
    this.#now = now;
  }

  get size(): number {
    return this.#entries.size;
  }

  set(id: string, value: T): void {
    this.#pruneExpired();
    this.#entries.delete(id);
    while (this.#entries.size >= this.#maxSessions) {
      const oldest = this.#entries.keys().next().value;
      if (oldest === undefined) break;
      this.#entries.delete(oldest);
    }
    this.#entries.set(id, {
      value,
      expiresAt: this.#now() + this.#ttlMs,
      queue: Promise.resolve(),
    });
  }

  /** Returns the session and refreshes its expiry; expired sessions are dropped. */
  get(id: string): T | undefined {
    const entry = this.#touch(id);
    return entry?.value;
  }

  /** Runs `task` after every earlier task for the same session has settled. */
  runExclusive<R>(id: string, task: () => Promise<R>): Promise<R> {
    const entry = this.#touch(id);
    if (!entry) return Promise.reject(new Error(`Unknown session ${id}`));
    const run = entry.queue.then(task, task);
    entry.queue = run.catch(() => undefined);
    return run;
  }

  #touch(id: string): Entry<T> | undefined {
    const entry = this.#entries.get(id);
    if (!entry) return undefined;
    if (entry.expiresAt <= this.#now()) {
      this.#entries.delete(id);
      return undefined;
    }
    entry.expiresAt = this.#now() + this.#ttlMs;
    this.#entries.delete(id);
    this.#entries.set(id, entry);
    return entry;
  }

  #pruneExpired(): void {
    const now = this.#now();
    for (const [id, entry] of this.#entries) {
      if (entry.expiresAt <= now) this.#entries.delete(id);
    }
  }
}
