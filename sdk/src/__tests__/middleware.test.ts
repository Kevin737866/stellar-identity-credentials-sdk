import {
  MiddlewareChain,
  createMiddlewareChain,
  createLoggingMiddleware,
  createMetricsMiddleware,
  createRateLimitMiddleware,
  createCacheMiddleware,
  Middleware,
  MiddlewareContext,
  SDKOperation,
} from '../middleware';
import { RateLimitError } from '../errors';

jest.mock('../logger', () => ({
  Logger: jest.fn().mockImplementation(() => ({
    trace: jest.fn(),
    debug: jest.fn(),
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
  })),
}));

const ok = <T>(value: T) => jest.fn().mockResolvedValue(value);

describe('MiddlewareChain', () => {
  describe('registration', () => {
    it('registers middleware in order', async () => {
      const chain = new MiddlewareChain();
      await chain.use({ name: 'a' });
      await chain.use({ name: 'b' });

      expect(chain.names()).toEqual(['a', 'b']);
    });

    it('runs setup on registration', async () => {
      const setup = jest.fn();
      await new MiddlewareChain().use({ name: 'x', setup });

      expect(setup).toHaveBeenCalledTimes(1);
    });

    it('rejects unnamed middleware', async () => {
      await expect(new MiddlewareChain().use({} as Middleware)).rejects.toThrow(/must have a name/);
    });

    it('inserts at a position and clamps out-of-range indexes', async () => {
      const chain = new MiddlewareChain([{ name: 'a' }, { name: 'c' }]);
      await chain.useAt({ name: 'b' }, 1);
      expect(chain.names()).toEqual(['a', 'b', 'c']);

      await chain.useAt({ name: 'first' }, -5);
      expect(chain.names()[0]).toBe('first');

      await chain.useAt({ name: 'last' }, 99);
      expect(chain.names()[chain.names().length - 1]).toBe('last');
    });

    it('removes middleware and runs teardown', async () => {
      const teardown = jest.fn();
      const chain = new MiddlewareChain([{ name: 'a', teardown }]);

      await expect(chain.remove('a')).resolves.toBe(true);
      expect(teardown).toHaveBeenCalledTimes(1);
      expect(chain.names()).toEqual([]);
    });

    it('returns false when removing an unknown middleware', async () => {
      await expect(new MiddlewareChain().remove('nope')).resolves.toBe(false);
    });

    it('looks up middleware by name', async () => {
      const mw: Middleware = { name: 'a' };
      const chain = new MiddlewareChain([mw]);

      expect(chain.get('a')).toBe(mw);
      expect(chain.get('missing')).toBeUndefined();
    });

    it('filters by operation', () => {
      const chain = new MiddlewareChain([
        { name: 'all' },
        { name: 'only-did', operations: ['createDID'] },
      ]);

      expect(chain.resolve('createDID').map(m => m.name)).toEqual(['all', 'only-did']);
      expect(chain.resolve('issueCredential').map(m => m.name)).toEqual(['all']);
    });
  });

  describe('hook ordering', () => {
    it('runs before hooks in order and after hooks in reverse', async () => {
      const calls: string[] = [];
      const track = (name: string): Middleware => ({
        name,
        before: () => {
          calls.push(`${name}:before`);
        },
        after: () => {
          calls.push(`${name}:after`);
        },
      });

      const chain = new MiddlewareChain([track('a'), track('b'), track('c')]);
      await chain.run('resolveDID', ['did:stellar:G1'], async () => 'ok');

      expect(calls).toEqual([
        'a:before', 'b:before', 'c:before',
        'c:after', 'b:after', 'a:after',
      ]);
    });

    it('runs onError hooks in reverse order', async () => {
      const calls: string[] = [];
      const track = (name: string): Middleware => ({
        name,
        onError: () => {
          calls.push(`${name}:error`);
        },
      });

      const chain = new MiddlewareChain([track('a'), track('b')]);
      await expect(
        chain.run('resolveDID', [], async () => {
          throw new Error('boom');
        }),
      ).rejects.toThrow('boom');

      expect(calls).toEqual(['b:error', 'a:error']);
    });

    it('propagates the error even when no onError hook exists', async () => {
      const chain = new MiddlewareChain();
      await expect(
        chain.run('verifyCredential', [], async () => {
          throw new Error('failed');
        }),
      ).rejects.toThrow('failed');
    });

    it('survives an onError hook that throws', async () => {
      const chain = new MiddlewareChain([
        {
          name: 'bad',
          onError: () => {
            throw new Error('hook exploded');
          },
        },
      ]);

      await expect(
        chain.run('resolveDID', [], async () => {
          throw new Error('original');
        }),
      ).rejects.toThrow('original');
    });
  });

  describe('argument and result transformation', () => {
    it('passes rewritten arguments to the operation', async () => {
      const operation = jest.fn().mockResolvedValue('done');
      const chain = new MiddlewareChain([
        {
          name: 'rewrite',
          before: (context: MiddlewareContext<[string]>) => ['rewritten'] as [string],
        },
      ]);

      const { result } = await chain.run('resolveDID', ['original'], operation);

      expect(operation).toHaveBeenCalledWith('rewritten');
      expect(result).toBe('done');
    });

    it('chains argument rewrites through several hooks', async () => {
      const operation = jest.fn().mockResolvedValue(undefined);
      const chain = new MiddlewareChain([
        { name: 'one', before: (c: MiddlewareContext<[string]>) => [`${c.args[0]}-a`] },
        { name: 'two', before: (c: MiddlewareContext<[string]>) => [`${c.args[0]}-b`] },
      ]);

      await chain.run('resolveDID', ['x'], operation);

      expect(operation).toHaveBeenCalledWith('x-a-b');
    });

    it('lets after hooks rewrite the result', async () => {
      const chain = new MiddlewareChain([
        { name: 'double', after: (c: MiddlewareContext<[], number>) => c.result! * 2 },
      ]);

      const { result } = await chain.run('getReputationScore', [], async () => 21);
      expect(result).toBe(42);
    });

    it('applies after rewrites in reverse order', async () => {
      const chain = new MiddlewareChain([
        { name: 'a', after: (c: MiddlewareContext<[], number>) => c.result! + 1 },
        { name: 'b', after: (c: MiddlewareContext<[], number>) => c.result! * 10 },
      ]);

      // b runs first (10), then a (11).
      const { result } = await chain.run('getReputationScore', [], async () => 1);
      expect(result).toBe(11);
    });

    it('leaves the result untouched when a hook returns undefined', async () => {
      const chain = new MiddlewareChain([{ name: 'noop', after: () => undefined }]);
      const { result } = await chain.run('getReputationScore', [], async () => 7);
      expect(result).toBe(7);
    });
  });

  describe('context', () => {
    it('assigns a unique requestId and exposes shared state', async () => {
      const chain = new MiddlewareChain([
        {
          name: 'a',
          before: c => {
            c.state.shared = 'value';
          },
        },
        {
          name: 'b',
          before: c => {
            expect(c.state.shared).toBe('value');
          },
          after: c => {
            expect(c.requestId).toMatch(/^mw-/);
          },
        },
      ]);

      await chain.run('resolveDID', [], ok(undefined));
    });

    it('gives each run a distinct requestId', async () => {
      const chain = new MiddlewareChain();
      const first = await chain.run('resolveDID', [], ok(undefined));
      const second = await chain.run('resolveDID', [], ok(undefined));

      expect(first.requestId).not.toBe(second.requestId);
    });

    it('measures duration', async () => {
      const chain = new MiddlewareChain();
      const { durationMs } = await chain.run('resolveDID', [], ok(undefined));
      expect(durationMs).toBeGreaterThanOrEqual(0);
    });
  });

  describe('operation filtering', () => {
    it('skips middleware registered for other operations', async () => {
      const before = jest.fn();
      const chain = new MiddlewareChain([
        { name: 'did-only', operations: ['createDID'] as SDKOperation[], before },
      ]);

      await chain.run('issueCredential', [], ok(undefined));
      expect(before).not.toHaveBeenCalled();

      await chain.run('createDID', [], ok(undefined));
      expect(before).toHaveBeenCalledTimes(1);
    });
  });

  describe('wrap', () => {
    it('produces a function that routes through the chain', async () => {
      const before = jest.fn();
      const chain = new MiddlewareChain([{ name: 'a', before }]);
      const original = jest.fn().mockResolvedValue('value');

      const wrapped = chain.wrap('verifyCredential', original);
      const result = await wrapped('cred-1');

      expect(result).toBe('value');
      expect(original).toHaveBeenCalledWith('cred-1');
      expect(before).toHaveBeenCalledTimes(1);
    });
  });

  describe('dispose', () => {
    it('tears down every middleware and empties the chain', async () => {
      const a = jest.fn();
      const b = jest.fn();
      const chain = new MiddlewareChain([
        { name: 'a', teardown: a },
        { name: 'b', teardown: b },
      ]);

      await chain.dispose();

      expect(b).toHaveBeenCalledTimes(1);
      expect(a).toHaveBeenCalledTimes(1);
      expect(chain.names()).toEqual([]);
    });

    it('continues tearing down when one hook throws', async () => {
      const good = jest.fn();
      const chain = new MiddlewareChain([
        {
          name: 'bad',
          teardown: () => {
            throw new Error('nope');
          },
        },
        { name: 'good', teardown: good },
      ]);

      await expect(chain.dispose()).resolves.toBeUndefined();
      expect(good).toHaveBeenCalledTimes(1);
    });
  });

  it('createMiddlewareChain builds a chain from a list', () => {
    expect(createMiddlewareChain([{ name: 'a' }]).names()).toEqual(['a']);
    expect(createMiddlewareChain().names()).toEqual([]);
  });
});

describe('built-in middleware', () => {
  describe('logging', () => {
    it('runs without error on success and failure', async () => {
      const chain = new MiddlewareChain([createLoggingMiddleware()]);

      await expect(chain.run('resolveDID', [], ok('v'))).resolves.toBeTruthy();
      await expect(
        chain.run('resolveDID', [], async () => {
          throw new Error('x');
        }),
      ).rejects.toThrow('x');
    });

    it('accepts a slow threshold', async () => {
      const chain = new MiddlewareChain([
        createLoggingMiddleware({ slowThresholdMs: 0, logArgs: true }),
      ]);

      await expect(chain.run('resolveDID', ['a'], ok(undefined))).resolves.toBeTruthy();
    });
  });

  describe('metrics', () => {
    it('aggregates counts, errors and durations', async () => {
      const metrics = createMetricsMiddleware();
      const chain = new MiddlewareChain([metrics]);

      await chain.run('resolveDID', [], ok('a'));
      await chain.run('resolveDID', [], ok('b'));
      await expect(
        chain.run('resolveDID', [], async () => {
          throw new Error('fail');
        }),
      ).rejects.toThrow('fail');

      const stats = metrics.getStats();
      expect(stats.resolveDID.count).toBe(3);
      expect(stats.resolveDID.errors).toBe(1);
      expect(stats.resolveDID.minDurationMs).toBeGreaterThanOrEqual(0);
      expect(stats.resolveDID.averageDurationMs).toBeGreaterThanOrEqual(0);
    });

    it('forwards each metric to a sink', async () => {
      const sink = jest.fn();
      const chain = new MiddlewareChain([createMetricsMiddleware({ sink })]);

      await chain.run('issueCredential', [], ok('a'));

      expect(sink).toHaveBeenCalledTimes(1);
      expect(sink.mock.calls[0][0]).toMatchObject({ operation: 'issueCredential', success: true });
    });

    it('can disable collection while still using the sink', async () => {
      const sink = jest.fn();
      const metrics = createMetricsMiddleware({ sink, collect: false });
      const chain = new MiddlewareChain([metrics]);

      await chain.run('resolveDID', [], ok('a'));

      expect(sink).toHaveBeenCalledTimes(1);
      expect(metrics.getStats()).toEqual({});
    });

    it('tracks operations separately', async () => {
      const metrics = createMetricsMiddleware();
      const chain = new MiddlewareChain([metrics]);

      await chain.run('resolveDID', [], ok('a'));
      await chain.run('issueCredential', [], ok('b'));

      const stats = metrics.getStats();
      expect(Object.keys(stats).sort()).toEqual(['issueCredential', 'resolveDID']);
      expect(stats.resolveDID.count).toBe(1);
    });
  });

  describe('rate limiting', () => {
    it('rejects a call over the limit in throw mode', async () => {
      const chain = new MiddlewareChain([
        createRateLimitMiddleware({ max: 1, windowMs: 10_000, strategy: 'throw' }),
      ]);

      await chain.run('resolveDID', [], ok('a'));

      await expect(chain.run('resolveDID', [], ok('b'))).rejects.toBeInstanceOf(RateLimitError);
    });

    it('allows calls under the limit', async () => {
      const chain = new MiddlewareChain([
        createRateLimitMiddleware({ max: 3, windowMs: 10_000, strategy: 'throw' }),
      ]);

      for (let i = 0; i < 3; i++) {
        await expect(chain.run('resolveDID', [], ok('a'))).resolves.toBeTruthy();
      }
    });

    it('times out when queueing cannot free a slot in time', async () => {
      const chain = new MiddlewareChain([
        createRateLimitMiddleware({ max: 1, windowMs: 5_000, maxWaitMs: 10 }),
      ]);

      await chain.run('resolveDID', [], ok('a'));
      await expect(chain.run('resolveDID', [], ok('b'))).rejects.toBeInstanceOf(RateLimitError);
    });

    it('validates its options', () => {
      expect(() => createRateLimitMiddleware({ max: 0, windowMs: 1 })).toThrow(/`max`/);
      expect(() => createRateLimitMiddleware({ max: 1, windowMs: 0 })).toThrow(/`windowMs`/);
    });
  });

  describe('caching', () => {
    it('caches results for a TTL and short-circuits the operation', async () => {
      const chain = new MiddlewareChain([
        createCacheMiddleware({ ttl: { resolveDID: 10_000 } }),
      ]);
      const operation = jest.fn().mockResolvedValue('cached-value');

      const first = await chain.run('resolveDID', ['did:stellar:G1'], operation);
      const second = await chain.run('resolveDID', ['did:stellar:G1'], operation);

      expect(operation).toHaveBeenCalledTimes(1);
      expect(first.cacheHit).toBe(false);
      expect(second.cacheHit).toBe(true);
      expect(second.result).toBe('cached-value');
    });

    it('does not cache mutating operations by default', async () => {
      const chain = new MiddlewareChain([createCacheMiddleware()]);
      const operation = jest.fn().mockResolvedValue('v');

      await chain.run('issueCredential', ['a'], operation);
      await chain.run('issueCredential', ['a'], operation);

      expect(operation).toHaveBeenCalledTimes(2);
    });

    it('distinguishes cache keys by argument', async () => {
      const chain = new MiddlewareChain([
        createCacheMiddleware({ ttl: { resolveDID: 10_000 } }),
      ]);
      const operation = jest.fn().mockImplementation(async (did: string) => `doc:${did}`);

      await chain.run('resolveDID', ['did:stellar:G1'], operation);
      await chain.run('resolveDID', ['did:stellar:G2'], operation);

      expect(operation).toHaveBeenCalledTimes(2);
    });

    it('honours a restricted operation list', async () => {
      const chain = new MiddlewareChain([
        createCacheMiddleware({ operations: ['getCredential'], ttl: { getCredential: 10_000 } }),
      ]);
      const resolve = jest.fn().mockResolvedValue('r');
      const get = jest.fn().mockResolvedValue('c');

      await chain.run('resolveDID', ['d'], resolve);
      await chain.run('resolveDID', ['d'], resolve);
      expect(resolve).toHaveBeenCalledTimes(2);

      await chain.run('getCredential', ['cred-1'], get);
      await chain.run('getCredential', ['cred-1'], get);
      expect(get).toHaveBeenCalledTimes(1);
    });

    it('evicts the oldest entry past maxEntries', async () => {
      const chain = new MiddlewareChain([
        createCacheMiddleware({ maxEntries: 1, ttl: { resolveDID: 10_000 } }),
      ]);
      const operation = jest.fn().mockImplementation(async (did: string) => `doc:${did}`);

      await chain.run('resolveDID', ['a'], operation);
      await chain.run('resolveDID', ['b'], operation);
      await chain.run('resolveDID', ['a'], operation);

      // 'a' was evicted when 'b' was inserted, so it is fetched again.
      expect(operation).toHaveBeenCalledTimes(3);
    });

    it('clears the store on teardown', async () => {
      const chain = new MiddlewareChain([
        createCacheMiddleware({ ttl: { resolveDID: 10_000 } }),
      ]);
      const operation = jest.fn().mockResolvedValue('v');

      await chain.run('resolveDID', ['d'], operation);
      await chain.dispose();
      await chain.use(createCacheMiddleware({ ttl: { resolveDID: 10_000 } }));
      await chain.run('resolveDID', ['d'], operation);

      expect(operation).toHaveBeenCalledTimes(2);
    });

    it('handles arguments that cannot be serialized', async () => {
      const chain = new MiddlewareChain([
        createCacheMiddleware({ ttl: { resolveDID: 10_000 } }),
      ]);
      const operation = jest.fn().mockResolvedValue('v');
      const circular: Record<string, unknown> = {};
      circular.self = circular;

      await expect(
        chain.run('resolveDID', [circular] as unknown as [string], operation),
      ).resolves.toBeTruthy();
    });

    it('serializes BigInt and Uint8Array arguments', async () => {
      const chain = new MiddlewareChain([
        createCacheMiddleware({ ttl: { resolveDID: 10_000 } }),
      ]);
      const operation = jest.fn().mockResolvedValue('v');

      await chain.run('resolveDID', [1n] as unknown as [string], operation);
      await chain.run('resolveDID', [1n] as unknown as [string], operation);

      expect(operation).toHaveBeenCalledTimes(1);
    });
  });

  describe('chaining built-ins', () => {
    it('runs logging, metrics, rate limit and cache together', async () => {
      const metrics = createMetricsMiddleware();
      const chain = new MiddlewareChain([
        createLoggingMiddleware(),
        metrics,
        createRateLimitMiddleware({ max: 10, windowMs: 1_000, strategy: 'throw' }),
        createCacheMiddleware({ ttl: { resolveDID: 10_000 } }),
      ]);
      const operation = jest.fn().mockResolvedValue('doc');

      await chain.run('resolveDID', ['d'], operation);
      const second = await chain.run('resolveDID', ['d'], operation);

      expect(operation).toHaveBeenCalledTimes(1);
      expect(second.cacheHit).toBe(true);
      expect(metrics.getStats().resolveDID.count).toBe(2);
    });
  });
});
