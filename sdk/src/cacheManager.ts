import { StellarIdentityConfig } from './types';

enum DataType {
  DID_DOCUMENT = 'DID_DOCUMENT',
  REPUTATION_SCORE = 'REPUTATION_SCORE',
  CREDENTIAL_STATUS = 'CREDENTIAL_STATUS',
  CIRCUIT_INFO = 'CIRCUIT_INFO',
}

interface CacheEntry<T> {
  data: T;
  expiresAt: number;
  size: number;
}

interface CacheStats {
  hits: number;
  misses: number;
  evictions: number;
  size: number;
}

const DEFAULT_TTL_MS: Record<DataType, number> = {
  [DataType.DID_DOCUMENT]: 5 * 60 * 1000,
  [DataType.REPUTATION_SCORE]: 60 * 1000,
  [DataType.CREDENTIAL_STATUS]: 30 * 1000,
  [DataType.CIRCUIT_INFO]: 10 * 60 * 1000,
};

const DEFAULT_MAX_SIZE = 1000;

class LRUMap<K, V> extends Map<K, V> {
  private maxSize: number;

  constructor(maxSize: number) {
    super();
    this.maxSize = maxSize;
  }

  get(key: K): V | undefined {
    const value = super.get(key);
    if (value !== undefined) {
      this.delete(key);
      super.set(key, value);
    }
    return value;
  }

  set(key: K, value: V): this {
    if (super.has(key)) {
      this.delete(key);
    } else if (this.size >= this.maxSize) {
      const firstKey = this.keys().next().value;
      if (firstKey !== undefined) {
        this.delete(firstKey);
      }
    }
    super.set(key, value);
    return this;
  }
}

export class CacheManager {
  private stores: Map<DataType, LRUMap<string, CacheEntry<unknown>>> = new Map();
  private ttlConfig: Record<DataType, number>;
  private maxSize: number;
  private stats: Record<DataType, CacheStats>;

  constructor(config?: {
    ttl?: Partial<Record<DataType, number>>;
    maxSize?: number;
  }) {
    this.ttlConfig = { ...DEFAULT_TTL_MS, ...config?.ttl };
    this.maxSize = config?.maxSize ?? DEFAULT_MAX_SIZE;
    this.stats = {} as Record<DataType, CacheStats>;

    for (const dt of Object.values(DataType)) {
      this.stores.set(dt, new LRUMap<string, CacheEntry<unknown>>(this.maxSize));
      this.stats[dt] = { hits: 0, misses: 0, evictions: 0, size: 0 };
    }
  }

  get<T>(dataType: DataType, key: string): T | null {
    const store = this.stores.get(dataType);
    if (!store) return null;

    const entry = store.get(key) as CacheEntry<T> | undefined;
    if (!entry) {
      this.stats[dataType].misses++;
      return null;
    }

    if (Date.now() > entry.expiresAt) {
      store.delete(key);
      this.stats[dataType].misses++;
      this.stats[dataType].evictions++;
      return null;
    }

    this.stats[dataType].hits++;
    return entry.data;
  }

  set<T>(dataType: DataType, key: string, data: T, ttlOverride?: number): void {
    const ttl = ttlOverride ?? this.ttlConfig[dataType] ?? DEFAULT_TTL_MS[DataType.DID_DOCUMENT];
    const store = this.stores.get(dataType);
    if (!store) return;

    const serialized = JSON.stringify(data);
    const size = serialized.length;

    const entry: CacheEntry<T> = {
      data,
      expiresAt: Date.now() + ttl,
      size,
    };

    const prevSize = store.get(key);
    if (prevSize) {
      this.stats[dataType].size -= (prevSize as CacheEntry<T>).size;
    }

    store.set(key, entry);
    this.stats[dataType].size += size;
  }

  invalidate(dataType: DataType, key: string): void {
    const store = this.stores.get(dataType);
    if (!store) return;

    const entry = store.get(key);
    if (entry) {
      this.stats[dataType].size -= entry.size;
      store.delete(key);
    }
  }

  invalidateForType(dataType: DataType): void {
    const store = this.stores.get(dataType);
    if (store) {
      this.stats[dataType].size = 0;
      store.clear();
    }
  }

  clearAll(): void {
    for (const dt of Object.values(DataType)) {
      this.invalidateForType(dt);
    }
  }

  clearCache(): void {
    this.clearAll();
  }

  clearCacheForType(dataType: DataType): void {
    this.invalidateForType(dataType);
  }

  getStats(): Record<DataType, CacheStats> {
    return { ...this.stats };
  }

  getDataType(dataType: string): DataType | undefined {
    return Object.values(DataType).find(dt => dt === dataType);
  }
}

export { DataType, DEFAULT_TTL_MS };
export type { CacheEntry, CacheStats };
