import { DIDCache, InMemoryStorageBackend, LocalStorageBackend, DEFAULT_DID_CACHE_TTL } from '../didCache';

const TEST_KEY = 'did:stellar:GD5DJQDKEJXGYQTELBQJXG2QFQHZXJN5T2YGF4Y4A3K5Z2Q2B4F5';
const TEST_DOCUMENT = {
  id: TEST_KEY,
  controller: 'GD5DJQDKEJXGYQTELBQJXG2QFQHZXJN5T2YGF4Y4A3K5Z2Q2B4F5',
  verificationMethod: [],
  authentication: [],
  service: [],
  created: Date.now(),
  updated: Date.now(),
};

describe('DIDCache', () => {
  let cache: DIDCache;

  beforeEach(() => {
    cache = new DIDCache();
  });

  describe('get', () => {
    it('should return null for cache miss', () => {
      const result = cache.get(TEST_KEY);
      expect(result).toBeNull();
    });

    it('should return cached document on cache hit', () => {
      cache.set(TEST_KEY, TEST_DOCUMENT);
      const result = cache.get(TEST_KEY);
      expect(result).toEqual(TEST_DOCUMENT);
    });

    it('should return null after TTL expiration', async () => {
      cache = new DIDCache({ ttl: 10 });
      cache.set(TEST_KEY, TEST_DOCUMENT);
      await new Promise(resolve => setTimeout(resolve, 20));
      const result = cache.get(TEST_KEY);
      expect(result).toBeNull();
    });
  });

  describe('set', () => {
    it('should store a document in cache', () => {
      cache.set(TEST_KEY, TEST_DOCUMENT);
      const result = cache.get(TEST_KEY);
      expect(result).toBe(TEST_DOCUMENT);
    });

    it('should use custom TTL override', () => {
      cache.set(TEST_KEY, TEST_DOCUMENT, 100);
      const backend = cache.getBackend() as InMemoryStorageBackend;
      const entry = (backend as any).store.get(TEST_KEY);
      expect(entry.expiresAt - entry.cachedAt).toBe(100);
    });

    it('should update existing cache entry', () => {
      cache.set(TEST_KEY, { id: 'old' });
      cache.set(TEST_KEY, TEST_DOCUMENT);
      const result = cache.get(TEST_KEY);
      expect(result).toEqual(TEST_DOCUMENT);
    });
  });

  describe('invalidate', () => {
    it('should remove a specific entry from cache', () => {
      cache.set(TEST_KEY, TEST_DOCUMENT);
      cache.invalidate(TEST_KEY);
      const result = cache.get(TEST_KEY);
      expect(result).toBeNull();
    });

    it('should not throw when invalidating non-existent key', () => {
      expect(() => cache.invalidate('nonexistent')).not.toThrow();
    });
  });

  describe('clear', () => {
    it('should remove all entries from cache', () => {
      cache.set('key1', { id: '1' });
      cache.set('key2', { id: '2' });
      cache.clear();
      expect(cache.get('key1')).toBeNull();
      expect(cache.get('key2')).toBeNull();
    });
  });

  describe('updateTTL', () => {
    it('should update the default TTL', () => {
      cache.updateTTL(60000);
      cache.set(TEST_KEY, TEST_DOCUMENT);
      const backend = cache.getBackend() as InMemoryStorageBackend;
      const entry = (backend as any).store.get(TEST_KEY);
      expect(entry.expiresAt - entry.cachedAt).toBe(60000);
    });
  });

  describe('with InMemoryStorageBackend', () => {
    it('should evict LRU entries when exceeding max size', () => {
      const backend = new InMemoryStorageBackend(3);
      const lruCache = new DIDCache({ backend });
      lruCache.set('key1', { id: '1' });
      lruCache.set('key2', { id: '2' });
      lruCache.set('key3', { id: '3' });
      lruCache.get('key1');
      lruCache.set('key4', { id: '4' });
      expect(lruCache.get('key1')).toEqual({ id: '1' });
      expect(lruCache.get('key2')).toBeNull();
    });
  });
});

describe('InMemoryStorageBackend', () => {
  let backend: InMemoryStorageBackend;

  beforeEach(() => {
    backend = new InMemoryStorageBackend(100);
  });

  it('should store and retrieve entries', () => {
    const entry = { document: { id: 'test' }, cachedAt: Date.now(), expiresAt: Date.now() + 60000 };
    backend.set('key1', entry);
    expect(backend.get('key1')).toEqual(entry);
  });

  it('should return null for missing key', () => {
    expect(backend.get('missing')).toBeNull();
  });

  it('should delete entries', () => {
    const entry = { document: { id: 'test' }, cachedAt: Date.now(), expiresAt: Date.now() + 60000 };
    backend.set('key1', entry);
    backend.delete('key1');
    expect(backend.get('key1')).toBeNull();
  });

  it('should clear all entries', () => {
    backend.set('key1', { document: { id: '1' }, cachedAt: 1, expiresAt: 2 });
    backend.set('key2', { document: { id: '2' }, cachedAt: 1, expiresAt: 2 });
    backend.clear();
    expect(backend.get('key1')).toBeNull();
    expect(backend.get('key2')).toBeNull();
  });

  it('should evict oldest entry when at capacity', () => {
    const small = new InMemoryStorageBackend(2);
    small.set('a', { document: {}, cachedAt: 1, expiresAt: 999 });
    small.set('b', { document: {}, cachedAt: 2, expiresAt: 999 });
    small.set('c', { document: {}, cachedAt: 3, expiresAt: 999 });
    expect(small.get('a')).toBeNull();
    expect(small.get('b')).toBeDefined();
    expect(small.get('c')).toBeDefined();
  });

  it('should track size correctly', () => {
    expect(backend.size).toBe(0);
    backend.set('a', { document: {}, cachedAt: 1, expiresAt: 2 });
    expect(backend.size).toBe(1);
    backend.delete('a');
    expect(backend.size).toBe(0);
  });
});
