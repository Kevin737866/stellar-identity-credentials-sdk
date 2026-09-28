import { DataType } from './cacheManager';

export interface DIDCacheEntry {
  document: unknown;
  cachedAt: number;
  expiresAt: number;
}

export interface StorageBackend {
  get(key: string): DIDCacheEntry | null;
  set(key: string, entry: DIDCacheEntry): void;
  delete(key: string): void;
  clear(): void;
}

export class InMemoryStorageBackend implements StorageBackend {
  private store: Map<string, DIDCacheEntry> = new Map();
  private maxSize: number;
  private accessOrder: string[] = [];

  constructor(maxSize = 500) {
    this.maxSize = maxSize;
  }

  get(key: string): DIDCacheEntry | null {
    const entry = this.store.get(key);
    if (!entry) return null;
    this.touch(key);
    return entry;
  }

  set(key: string, entry: DIDCacheEntry): void {
    if (this.store.has(key)) {
      this.store.set(key, entry);
      this.touch(key);
      return;
    }
    if (this.store.size >= this.maxSize) {
      const lruKey = this.accessOrder.shift();
      if (lruKey) this.store.delete(lruKey);
    }
    this.store.set(key, entry);
    this.accessOrder.push(key);
  }

  delete(key: string): void {
    this.store.delete(key);
    const idx = this.accessOrder.indexOf(key);
    if (idx !== -1) this.accessOrder.splice(idx, 1);
  }

  clear(): void {
    this.store.clear();
    this.accessOrder = [];
  }

  get size(): number {
    return this.store.size;
  }

  private touch(key: string): void {
    const idx = this.accessOrder.indexOf(key);
    if (idx !== -1) {
      this.accessOrder.splice(idx, 1);
      this.accessOrder.push(key);
    }
  }
}

export class LocalStorageBackend implements StorageBackend {
  private prefix: string;
  private maxSize: number;

  constructor(prefix = 'did_cache:', maxSize = 500) {
    this.prefix = prefix;
    this.maxSize = maxSize;
  }

  get(key: string): DIDCacheEntry | null {
    try {
      const raw = localStorage.getItem(this.prefix + key);
      if (!raw) return null;
      return JSON.parse(raw) as DIDCacheEntry;
    } catch {
      return null;
    }
  }

  set(key: string, entry: DIDCacheEntry): void {
    try {
      if (localStorage.length >= this.maxSize) {
        const oldest = this.findOldestKey();
        if (oldest) localStorage.removeItem(oldest);
      }
      localStorage.setItem(this.prefix + key, JSON.stringify(entry));
    } catch {
    }
  }

  delete(key: string): void {
    localStorage.removeItem(this.prefix + key);
  }

  clear(): void {
    const keys: string[] = [];
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i);
      if (k?.startsWith(this.prefix)) keys.push(k);
    }
    keys.forEach(k => localStorage.removeItem(k));
  }

  private findOldestKey(): string | null {
    let oldestKey: string | null = null;
    let oldestTime = Infinity;
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i);
      if (k?.startsWith(this.prefix)) {
        try {
          const entry = JSON.parse(localStorage.getItem(k)!) as DIDCacheEntry;
          if (entry.cachedAt < oldestTime) {
            oldestTime = entry.cachedAt;
            oldestKey = k;
          }
        } catch {
        }
      }
    }
    return oldestKey;
  }
}

export const DEFAULT_DID_CACHE_TTL = 5 * 60 * 1000;

export interface DIDCacheConfig {
  ttl?: number;
  backend?: StorageBackend;
}

export class DIDCache {
  private backend: StorageBackend;
  private ttl: number;

  constructor(config: DIDCacheConfig = {}) {
    this.backend = config.backend ?? new InMemoryStorageBackend();
    this.ttl = config.ttl ?? DEFAULT_DID_CACHE_TTL;
  }

  get<T>(key: string): T | null {
    const entry = this.backend.get(key);
    if (!entry) return null;
    if (Date.now() > entry.expiresAt) {
      this.backend.delete(key);
      return null;
    }
    return entry.document as T;
  }

  set<T>(key: string, document: T, ttlOverride?: number): void {
    const now = Date.now();
    const ttl = ttlOverride ?? this.ttl;
    this.backend.set(key, {
      document,
      cachedAt: now,
      expiresAt: now + ttl,
    });
  }

  invalidate(key: string): void {
    this.backend.delete(key);
  }

  clear(): void {
    this.backend.clear();
  }

  getBackend(): StorageBackend {
    return this.backend;
  }

  updateTTL(newTtl: number): void {
    this.ttl = newTtl;
  }
}
