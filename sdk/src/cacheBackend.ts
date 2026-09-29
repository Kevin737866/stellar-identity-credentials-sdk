/**
 * Pluggable, persistent cache backends (#207).
 *
 * {@link CacheManager} is in-memory only, so every page reload starts cold and
 * every process restart re-resolves every DID. This module adds the persistence
 * layer and the invalidation wiring that make a cache worth having.
 *
 * Three pieces:
 *
 * 1. **Backends** — {@link StorageBackend} is a small key/value contract with
 *    two implementations: {@link MemoryBackend} (default) and
 *    {@link WebStorageBackend}, which persists to `localStorage` in browsers
 *    and accepts any synchronous key/value store elsewhere, so React Native
 *    apps can pass AsyncStorage.
 * 2. **Tiered {@link PersistentCacheManager}** — a memory tier in front of a
 *    persistent tier, so hot reads never touch storage while cold reads
 *    survive a reload.
 * 3. **Tag-based invalidation** — cache entries are written with tags
 *    (`did:stellar:GABC`, `credential:cred-1`), and a write operation
 *    invalidates everything under a tag. Without this, a cache that avoids
 *    network calls also serves stale data after a mutation, which is worse
 *    than no cache at all.
 *
 * Every backend failure is non-fatal. A cache is an optimisation, so a quota
 * error or an unavailable store degrades to a direct read rather than failing
 * the caller's identity flow.
 *
 * @module cacheBackend
 * @category Utilities
 */

import { CacheManager, DataType } from './cacheManager';
import { CacheError, ErrorCode } from './errors';

// ── Backend contract ─────────────────────────────────────────────────────────

/**
 * A synchronous key/value store.
 *
 * Kept synchronous on purpose: the SDK's read path is `async` but a cache
 * lookup inside it should not itself introduce a microtask, and `localStorage`
 * is synchronous anyway. React Native's AsyncStorage is async, so mobile apps
 * should pre-hydrate a {@link MemoryBackend} from it at startup rather than
 * wrap it.
 */
export interface StorageBackend {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
  /** Every key currently held. Used for prefix scans and eviction. */
  keys(): string[];
  clear(): void;
}

/**
 * An in-memory backend, and the default when no persistence is configured.
 *
 * @category Utilities
 */
export class MemoryBackend implements StorageBackend {
  private store = new Map<string, string>();

  getItem(key: string): string | null {
    return this.store.has(key) ? (this.store.get(key) as string) : null;
  }

  setItem(key: string, value: string): void {
    this.store.set(key, value);
  }

  removeItem(key: string): void {
    this.store.delete(key);
  }

  keys(): string[] {
    return Array.from(this.store.keys());
  }

  clear(): void {
    this.store.clear();
  }

  /** Number of stored keys. */
  get size(): number {
    return this.store.size;
  }
}

/**
 * The subset of the `Storage` interface this backend needs.
 *
 * Matches `window.localStorage` exactly, and also matches a shim built on
 * React Native's AsyncStorage by keeping the loaded values in memory and
 * persisting writes asynchronously.
 */
export interface WebStorageLike {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
  readonly length: number;
  key(index: number): string | null;
  clear?(): void;
}

/**
 * A backend that persists through the Web Storage API.
 *
 * Uses `length` / `key(i)` rather than an assumed iteration order, because
 * `Object.keys(localStorage)` is not portable and some privacy modes throw on
 * enumeration. Every access is guarded, because `localStorage` throws in
 * sandboxed iframes and when a device is out of quota.
 *
 * @category Utilities
 */
export class WebStorageBackend implements StorageBackend {
  private storage: WebStorageLike;
  private prefix: string;
  private maxSize: number;

  /**
   * @param storage - Usually `window.localStorage`.
   * @param prefix - Key namespace, so several caches can share one store.
   * @param maxSize - Eviction threshold.
   */
  constructor(storage: WebStorageLike, prefix = 'stellar_identity_cache:', maxSize = 500) {
    this.storage = storage;
    this.prefix = prefix;
    this.maxSize = maxSize;
  }

  /**
   * Build a backend from `globalThis.localStorage`, or `null` when it is
   * unavailable (SSR, Node, React Native).
   */
  static fromGlobal(prefix?: string): WebStorageBackend | null {
    try {
      const g = globalThis as unknown as { localStorage?: WebStorageLike };
      if (!g.localStorage) return null;
      return new WebStorageBackend(g.localStorage, prefix);
    } catch {
      return null;
    }
  }

  getItem(key: string): string | null {
    try {
      return this.storage.getItem(this.prefix + key);
    } catch {
      return null;
    }
  }

  setItem(key: string, value: string): void {
    try {
      if (this.size() >= this.maxSize) {
        const oldest = this.findOldestKey();
        if (oldest) this.storage.removeItem(oldest);
      }
      this.storage.setItem(this.prefix + key, value);
    } catch (err) {
      // Quota exceeded, or storage disabled. A cache write failing must not
      // surface to the caller, but it is worth a typed error for debugging.
      throw new CacheError(
        ErrorCode.CacheBackendUnavailable,
        `Persistent cache write failed: ${String(err)}`,
        { key },
      );
    }
  }

  removeItem(key: string): void {
    try {
      this.storage.removeItem(this.prefix + key);
    } catch {
    }
  }

  keys(): string[] {
    const out: string[] = [];
    try {
      for (let i = 0; i < this.storage.length; i++) {
        const k = this.storage.key(i);
        if (k && k.startsWith(this.prefix)) out.push(k);
      }
    } catch {
    }
    return out;
  }

  clear(): void {
    for (const key of this.keys()) {
      this.removeItem(key);
    }
  }

  /** Number of keys in this namespace. */
  size(): number {
    return this.keys().length;
  }

  /**
   * Find the key whose entry was written longest ago.
   *
   * Entries are scanned rather than tracked in an insertion list because
   * `localStorage` exposes no ordering; the scan is O(n) but only runs on the
   * rare eviction path.
   */
  private findOldestKey(): string | null {
    let oldestKey: string | null = null;
    let oldestTime = Infinity;
    for (const key of this.keys()) {
      const raw = this.getItem(key);
      if (!raw) continue;
      try {
        const entry = JSON.parse(raw) as { cachedAt?: number };
        const cachedAt = entry.cachedAt ?? 0;
        if (cachedAt < oldestTime) {
          oldestTime = cachedAt;
          oldestKey = key;
        }
      } catch {
        // An unparseable entry is by definition the oldest; drop it.
        return key;
      }
    }
    return oldestKey;
  }
}

// ── Persistent, tag-aware cache ───────────────────────────────────────────────

/** A persisted cache entry. */
export interface PersistentCacheEntry<T = unknown> {
  /** The cached value. */
  value: T;
  /** Epoch milliseconds when the entry was written. */
  cachedAt: number;
  /** Epoch milliseconds after which the entry is stale. */
  expiresAt: number;
  /** Invalidation tags this entry belongs to. */
  tags: string[];
}

/**
 * Per-`DataType` hit/miss counters, extended with the persistent tier.
 */
export interface PersistentCacheStats {
  /** Reads served from the memory tier. */
  memoryHits: number;
  /** Reads served from the persistent tier after a memory miss. */
  persistentHits: number;
  /** Reads that missed both tiers. */
  misses: number;
  /** Entries dropped because their TTL had passed. */
  expirations: number;
  /** Entries dropped to stay within `maxSize`. */
  evictions: number;
  /** Writes that failed and were swallowed. */
  writeFailures: number;
  /** Current entry count in the memory tier. */
  size: number;
  /** Overall hit rate, or 0 when nothing has been read yet. */
  hitRate: number;
}

/**
 * Configuration for {@link PersistentCacheManager}.
 */
export interface PersistentCacheConfig {
  /**
   * Where entries are persisted. Omit for memory-only behaviour, which is
   * the default so importing the SDK never touches browser storage.
   */
  backend?: StorageBackend;
  /**
   * Whether writes should reach the persistent tier. Turning this off makes
   * the manager behave like a plain in-memory cache.
   * @default true
   */
  persistWrites?: boolean;
  /** Maximum entries per `DataType`. @default 500 */
  maxSize?: number;
  /** Default TTL when `set` is called without one. @default 300_000 */
  defaultTtlMs?: number;
}

/**
 * A two-tier cache with tag-based invalidation.
 *
 * Reads consult the in-memory {@link CacheManager} first and fall back to the
 * persistent backend, so a page reload serves warm data without a network call
 * while hot reads stay in memory.
 *
 * ```ts
 * const cache = new PersistentCacheManager({
 *   backend: WebStorageBackend.fromGlobal() ?? undefined,
 * });
 *
 * // Read-through: a miss issues the network call and populates the cache.
 * const doc = await cache.getOrFetch(
 *   DataType.DID_DOCUMENT,
 *   did,
 *   () => sdk.did.resolveDID(did),
 *   { tags: [`did:${did}`] },
 * );
 *
 * // After a write, drop everything for that subject.
 * cache.invalidateTag('did:GABC…');
 * ```
 *
 * @category Utilities
 */
export class PersistentCacheManager {
  private readonly memory: CacheManager;
  private readonly backend: StorageBackend | null;
  private readonly persistWrites: boolean;
  private readonly maxSize: number;
  private readonly defaultTtlMs: number;
  private readonly stats: Record<string, PersistentCacheStats> = {};

  /** Reverse index: tag → cache keys carrying that tag. */
  private tagIndex = new Map<string, Set<string>>();
  /** Forward index: cache key → the tags it was written under. */
  private keyTags = new Map<string, string[]>();

  constructor(config: PersistentCacheConfig = {}) {
    this.backend = config.backend ?? null;
    this.persistWrites = config.persistWrites ?? true;
    this.maxSize = config.maxSize ?? 500;
    this.defaultTtlMs = config.defaultTtlMs ?? 5 * 60 * 1000;
    this.memory = new CacheManager({ maxSize: this.maxSize });
  }

  // ── Reads ─────────────────────────────────────────────────────────────────

  /**
   * Read a value, consulting memory then the persistent tier.
   *
   * Returns `null` on a miss. Never throws: a backend failure is counted and
   * treated as a miss.
   */
  get<T>(dataType: DataType, key: string): T | null {
    const stat = this.statFor(dataType);

    const fromMemory = this.memory.get<T>(dataType, key);
    if (fromMemory !== null && fromMemory !== undefined) {
      stat.memoryHits++;
      return fromMemory;
    }

    if (this.backend) {
      const entry = this.readPersisted<T>(dataType, key);
      if (entry) {
        stat.persistentHits++;
        // Promote into the memory tier so the next read is free.
        this.memory.set(dataType, key, entry.value, Math.max(1, entry.expiresAt - Date.now()));
        return entry.value;
      }
    }

    stat.misses++;
    return null;
  }

  /**
   * Read-through: return the cached value, or run `fetcher` and cache it.
   *
   * This is the method that actually removes network calls — callers should
   * prefer it over a manual `get` / `set` pair, which is easy to get wrong
   * (forgetting the tags means later invalidation silently does nothing).
   */
  async getOrFetch<T>(
    dataType: DataType,
    key: string,
    fetcher: () => Promise<T>,
    options: { ttlMs?: number; tags?: string[] } = {},
  ): Promise<T> {
    const hit = this.get<T>(dataType, key);
    if (hit !== null) return hit;

    const value = await fetcher();
    this.set(dataType, key, value, {
      ttlMs: options.ttlMs,
      tags: options.tags,
    });
    return value;
  }

  // ── Writes ────────────────────────────────────────────────────────────────

  /**
   * Store a value under `key`, optionally tagged for later invalidation.
   */
  set<T>(
    dataType: DataType,
    key: string,
    value: T,
    options: { ttlMs?: number; tags?: string[] } = {},
  ): void {
    const ttl = options.ttlMs ?? this.defaultTtlMs;
    const now = Date.now();
    const tags = options.tags ?? [];

    this.memory.set(dataType, key, value, ttl);

    if (this.keyTags.has(key)) {
      this.detachTags(key);
    }
    this.keyTags.set(key, tags);
    for (const tag of tags) {
      let set = this.tagIndex.get(tag);
      if (!set) {
        set = new Set();
        this.tagIndex.set(tag, set);
      }
      set.add(key);
    }

    if (!this.backend || !this.persistWrites) return;

    const entry: PersistentCacheEntry<T> = { value, cachedAt: now, expiresAt: now + ttl, tags };
    try {
      this.backend.setItem(this.storageKey(dataType, key), JSON.stringify(entry));
    } catch {
      // Non-fatal: the memory tier still holds the value for this session.
      this.statFor(dataType).writeFailures++;
    }
  }

  // ── Invalidation ──────────────────────────────────────────────────────────

  /**
   * Drop a single entry from both tiers.
   */
  invalidate(dataType: DataType, key: string): void {
    this.memory.invalidate(dataType, key);
    this.detachTags(key);
    if (this.backend) {
      try {
        this.backend.removeItem(this.storageKey(dataType, key));
      } catch {
      }
    }
  }

  /**
   * Drop every entry written under `tag`.
   *
   * This is what a write operation must call. Without it a cache that saves
   * network calls will happily serve a pre-update document, which is a
   * correctness bug rather than a performance win.
   *
   * @returns the number of entries dropped.
   */
  invalidateTag(tag: string): number {
    const keys = this.tagIndex.get(tag);
    if (!keys || keys.size === 0) return 0;

    const dataType = DataType.DID_DOCUMENT;
    let dropped = 0;
    for (const key of Array.from(keys)) {
      this.invalidate(dataType, key);
      dropped++;
    }
    this.tagIndex.delete(tag);
    return dropped;
  }

  /**
   * Drop every entry of a `DataType` from both tiers.
   */
  invalidateForType(dataType: DataType): void {
    this.memory.invalidateForType(dataType);
    if (this.backend) {
      for (const key of this.backend.keys()) {
        if (key.startsWith(`${dataType}:`)) {
          this.backend.removeItem(key);
        }
      }
    }
    for (const [key, tags] of Array.from(this.keyTags.entries())) {
      if (tags.some((t) => t.startsWith(`${dataType}:`))) this.detachTags(key);
    }
  }

  /** Drop everything, in both tiers and the tag indexes. */
  clearAll(): void {
    this.memory.clearAll();
    this.tagIndex.clear();
    this.keyTags.clear();
    if (this.backend) {
      try {
        this.backend.clear();
      } catch {
      }
    }
  }

  // ── Introspection ─────────────────────────────────────────────────────────

  /**
   * Counters for a `DataType`, including the persistent tier.
   */
  getStats(dataType: DataType): PersistentCacheStats {
    const stat = this.statFor(dataType);
    const reads = stat.memoryHits + stat.persistentHits + stat.misses;
    return {
      ...stat,
      hitRate: reads === 0 ? 0 : (stat.memoryHits + stat.persistentHits) / reads,
    };
  }

  /** Counters for every `DataType`. */
  getAllStats(): Record<string, PersistentCacheStats> {
    const out: Record<string, PersistentCacheStats> = {};
    for (const dt of Object.values(DataType)) {
      out[dt] = this.getStats(dt);
    }
    return out;
  }

  /** Reset every counter. Intended for tests. */
  resetStats(): void {
    for (const key of Object.keys(this.stats)) {
      this.stats[key] = this.blankStats();
    }
  }

  // ── Internals ─────────────────────────────────────────────────────────────

  private storageKey(dataType: DataType, key: string): string {
    return `${dataType}:${key}`;
  }

  private readPersisted<T>(dataType: DataType, key: string): PersistentCacheEntry<T> | null {
    if (!this.backend) return null;
    let raw: string | null;
    try {
      raw = this.backend.getItem(this.storageKey(dataType, key));
    } catch {
      return null;
    }
    if (!raw) return null;

    let entry: PersistentCacheEntry<T>;
    try {
      entry = JSON.parse(raw) as PersistentCacheEntry<T>;
    } catch {
      // Corrupt entry: drop it rather than letting it fail every read.
      try {
        this.backend.removeItem(this.storageKey(dataType, key));
      } catch {
      }
      return null;
    }

    if (Date.now() > entry.expiresAt) {
      this.statFor(dataType).expirations++;
      try {
        this.backend.removeItem(this.storageKey(dataType, key));
      } catch {
      }
      return null;
    }
    return entry;
  }

  private detachTags(key: string): void {
    const tags = this.keyTags.get(key);
    if (!tags) return;
    for (const tag of tags) {
      const set = this.tagIndex.get(tag);
      if (!set) continue;
      set.delete(key);
      if (set.size === 0) this.tagIndex.delete(tag);
    }
    this.keyTags.delete(key);
  }

  private blankStats(): PersistentCacheStats {
    return {
      memoryHits: 0,
      persistentHits: 0,
      misses: 0,
      expirations: 0,
      evictions: 0,
      writeFailures: 0,
      size: 0,
      hitRate: 0,
    };
  }

  private statFor(dataType: DataType): PersistentCacheStats {
    const key = String(dataType);
    if (!this.stats[key]) this.stats[key] = this.blankStats();
    return this.stats[key];
  }
}
