import { Logger } from './logger';
import { RateLimitError, ErrorCode } from './errors';

// ── Types ─────────────────────────────────────────────────────────────────────

/**
 * Names of the SDK operations that middleware can intercept.
 * Kept as a string union so custom middleware stays type safe.
 */
export type SDKOperation =
  | 'createDID'
  | 'resolveDID'
  | 'updateDID'
  | 'deactivateDID'
  | 'issueCredential'
  | 'verifyCredential'
  | 'revokeCredential'
  | 'getCredential'
  | 'createPresentation'
  | 'verifyPresentation'
  | 'initializeReputation'
  | 'getReputationScore'
  | 'generateProof'
  | 'verifyProof'
  | 'screenAddress'
  | 'batchCreateDIDs'
  | 'batchIssueCredentials'
  | 'batchVerifyCredentials'
  | 'batchRevokeCredentials';

/** Context passed to every middleware hook. */
export interface MiddlewareContext<TArgs extends unknown[] = unknown[], TResult = unknown> {
  /** The operation being intercepted. */
  operation: SDKOperation;
  /** Arguments the SDK method was called with. */
  args: TArgs;
  /** Arbitrary state shared between `before` and `after` for a single call. */
  state: Record<string, unknown>;
  /** Correlation id assigned by the chain; useful for log tracing. */
  requestId: string;
  /** Epoch ms when `before` ran. */
  startedAt: number;
  /** The operation's result. Only available inside `after`/`onError`. */
  result?: TResult;
  /** The thrown error. Only available inside `onError`. */
  error?: Error;
}

/**
 * A single middleware in the chain.
 *
 * Every hook is optional; implement only what you need. `before` may return a
 * replacement argument tuple to transform the inputs, and `after` may return a
 * replacement result to transform the output.
 */
export interface Middleware<TArgs extends unknown[] = unknown[], TResult = unknown> {
  /** Middleware name, used in logs and error messages. */
  name: string;

  /** Restrict this middleware to specific operations. Omit to run for all. */
  operations?: SDKOperation[];

  /**
   * Runs before the operation. Return a new argument tuple to replace the
   * inputs; return nothing to pass them through unchanged.
   */
  before?(context: MiddlewareContext<TArgs, TResult>): void | TArgs | Promise<void | TArgs>;

  /** Runs after a successful operation. Return a value to replace the result. */
  after?(context: MiddlewareContext<TArgs, TResult>): TResult | void | Promise<TResult | void>;

  /** Runs when the operation throws. Rethrow to alter the error. */
  onError?(context: MiddlewareContext<TArgs, TResult>): void | Promise<void>;

  /** Invoked once when the middleware is added to a chain. */
  setup?(): void | Promise<void>;

  /** Invoked once when the middleware is removed or the chain is disposed. */
  teardown?(): void | Promise<void>;
}

/** Options accepted by the built-in middleware factories. */
export interface LoggerMiddlewareOptions {
  /** Log successful operations at this level. Default 'debug'. */
  level?: 'trace' | 'debug' | 'info';
  /** Log failures at this level. Default 'error'. */
  errorLevel?: 'warn' | 'error';
  /** Log the operation arguments. Default false (arguments may be sensitive). */
  logArgs?: boolean;
  /** Warn when an operation exceeds this many ms. */
  slowThresholdMs?: number;
}

export interface MetricsMiddlewareOptions {
  /** Sink for recorded timings. Default: an in-memory collector. */
  sink?: (metric: OperationMetric) => void;
  /** Keep per-operation aggregates retrievable via `getMetrics()`. Default true. */
  collect?: boolean;
}

export interface RateLimitMiddlewareOptions {
  /** Maximum operations per window. */
  max: number;
  /** Window length in ms. */
  windowMs: number;
  /** When exceeded: wait for the window to reset (default) or throw. */
  strategy?: 'queue' | 'throw';
  /** Maximum time to wait per operation when queueing. */
  maxWaitMs?: number;
}

export interface CacheMiddlewareOptions {
  /** Time-to-live per cached operation result. */
  ttl?: Partial<Record<SDKOperation, number>>;
  /** Max entries retained before the oldest are evicted. Default 500. */
  maxEntries?: number;
  /** Restrict caching to these operations. Default: read-only operations. */
  operations?: SDKOperation[];
}

/** A single recorded operation timing. */
export interface OperationMetric {
  operation: SDKOperation;
  durationMs: number;
  success: boolean;
  requestId: string;
  timestamp: number;
}

/** Aggregate statistics for one operation. */
export interface OperationStats {
  count: number;
  errors: number;
  totalDurationMs: number;
  averageDurationMs: number;
  minDurationMs: number;
  maxDurationMs: number;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/** Operations treated as safe to cache. */
const CACHEABLE_OPERATIONS: SDKOperation[] = [
  'resolveDID',
  'verifyCredential',
  'getCredential',
  'getReputationScore',
  'verifyProof',
  'screenAddress',
];

let requestCounter = 0;

function nextRequestId(): string {
  requestCounter += 1;
  return `mw-${Date.now().toString(36)}-${requestCounter}`;
}

/** Stable JSON key for a set of call arguments. */
function cacheKey(operation: SDKOperation, args: unknown[]): string {
  return `${operation}:${safeStringify(args)}`;
}

function safeStringify(value: unknown): string {
  try {
    return JSON.stringify(value, (_k, v) =>
      typeof v === 'bigint' ? v.toString() : v instanceof Uint8Array ? Array.from(v).join(',') : v,
    ) ?? 'undefined';
  } catch {
    return '[unserializable]';
  }
}

// ── Built-in middleware ───────────────────────────────────────────────────────

/**
 * Logs every intercepted operation, its duration and its outcome.
 */
export function createLoggingMiddleware(options: LoggerMiddlewareOptions = {}): Middleware {
  const {
    level = 'debug',
    errorLevel = 'error',
    logArgs = false,
    slowThresholdMs,
  } = options;
  const logger = new Logger('Middleware:logging');

  return {
    name: 'logging',

    async before(context) {
      logger.trace(`→ ${context.operation}`, {
        requestId: context.requestId,
        ...(logArgs ? { args: context.args } : {}),
      });
    },

    async after(context) {
      const durationMs = Date.now() - context.startedAt;
      const context_ = {
        requestId: context.requestId,
        durationMs,
        ...(logArgs ? { result: context.result } : {}),
      };

      if (slowThresholdMs !== undefined && durationMs > slowThresholdMs) {
        logger.warn(`slow ${context.operation}`, context_);
        return;
      }
      // Resolve the level explicitly: `Logger.warn` has a different signature
      // from trace/debug/info, so indexing by a union would not typecheck.
      if (level === 'trace') logger.trace(`✓ ${context.operation}`, context_);
      else if (level === 'info') logger.info(`✓ ${context.operation}`, context_);
      else logger.debug(`✓ ${context.operation}`, context_);
    },

    async onError(context) {
      if (errorLevel === 'warn') {
        // `Logger.warn` takes only (message, context), so fold the error in.
        logger.warn(`✗ ${context.operation}`, {
          requestId: context.requestId,
          durationMs: Date.now() - context.startedAt,
          error: context.error?.message ?? 'unknown error',
        });
      } else {
        logger.error(`✗ ${context.operation}`, context.error, {
          requestId: context.requestId,
          durationMs: Date.now() - context.startedAt,
        });
      }
    },
  };
}

/**
 * Records per-operation timings, errors and averages.
 *
 * Attach the returned middleware to a chain and keep a reference to it to read
 * {@link OperationStats} via `getStats()`.
 */
export function createMetricsMiddleware(
  options: MetricsMiddlewareOptions = {},
): Middleware & { getStats(): Record<string, OperationStats> } {
  const { sink, collect = true } = options;
  const samples: Record<string, number[]> = {};
  const errorCounts: Record<string, number> = {};

  const record = (metric: OperationMetric) => {
    sink?.(metric);
    if (!collect) return;

    const key = metric.operation;
    (samples[key] ??= []).push(metric.durationMs);
    if (!metric.success) errorCounts[key] = (errorCounts[key] ?? 0) + 1;
  };

  const getStats = (): Record<string, OperationStats> => {
    const stats: Record<string, OperationStats> = {};
    for (const [operation, durations] of Object.entries(samples)) {
      const total = durations.reduce((sum, d) => sum + d, 0);
      stats[operation] = {
        count: durations.length,
        errors: errorCounts[operation] ?? 0,
        totalDurationMs: total,
        averageDurationMs: durations.length === 0 ? 0 : total / durations.length,
        minDurationMs: Math.min(...durations),
        maxDurationMs: Math.max(...durations),
      };
    }
    return stats;
  };

  return {
    name: 'metrics',

    after(context) {
      record({
        operation: context.operation,
        durationMs: Date.now() - context.startedAt,
        success: true,
        requestId: context.requestId,
        timestamp: Date.now(),
      });
    },

    onError(context) {
      record({
        operation: context.operation,
        durationMs: Date.now() - context.startedAt,
        success: false,
        requestId: context.requestId,
        timestamp: Date.now(),
      });
    },

    getStats,
  };
}

/**
 * Throttles operations to a maximum rate within a sliding window.
 *
 * With `strategy: 'queue'` (default) callers wait for a slot; with
 * `'throw'` a {@link RateLimitError} is raised immediately.
 */
export function createRateLimitMiddleware(options: RateLimitMiddlewareOptions): Middleware {
  const { max, windowMs, strategy = 'queue', maxWaitMs = windowMs } = options;
  if (max <= 0) throw new Error('rate limit `max` must be greater than 0');
  if (windowMs <= 0) throw new Error('rate limit `windowMs` must be greater than 0');

  /** Epoch ms of each admitted call, oldest first. */
  let timestamps: number[] = [];

  const prune = (now: number) => {
    timestamps = timestamps.filter(t => now - t < windowMs);
  };

  const acquire = async (): Promise<void> => {
    const deadline = Date.now() + maxWaitMs;

    for (;;) {
      const now = Date.now();
      prune(now);

      if (timestamps.length < max) {
        timestamps.push(now);
        return;
      }

      if (strategy === 'throw') {
        throw new RateLimitError(
          ErrorCode.RateLimitExceeded,
          `Rate limit exceeded: ${max} operations per ${windowMs}ms`,
          { max, windowMs },
        );
      }

      if (now >= deadline) {
        throw new RateLimitError(
          ErrorCode.RateLimitExceeded,
          `Timed out waiting ${maxWaitMs}ms for a rate limit slot`,
          { max, windowMs, maxWaitMs },
        );
      }

      const waitMs = Math.max(1, Math.min(timestamps[0] + windowMs - now, deadline - now));
      await new Promise(resolve => setTimeout(resolve, waitMs));
    }
  };

  return {
    name: 'rateLimit',
    before: acquire,
  };
}

/**
 * Memoises results of read-only operations for a configurable TTL.
 *
 * When a cached value is hit the operation short-circuits and the remaining
 * middleware in the chain is skipped.
 */
export function createCacheMiddleware(options: CacheMiddlewareOptions = {}): Middleware {
  const { ttl = {}, maxEntries = 500, operations = CACHEABLE_OPERATIONS } = options;
  const store = new Map<string, { value: unknown; expiresAt: number }>();

  const read = <T>(key: string): T | undefined => {
    const hit = store.get(key);
    if (!hit) return undefined;
    if (Date.now() > hit.expiresAt) {
      store.delete(key);
      return undefined;
    }
    return hit.value as T;
  };

  const write = (key: string, value: unknown, operation: SDKOperation): void => {
    if (store.size >= maxEntries) {
      const oldest = store.keys().next().value;
      if (oldest !== undefined) store.delete(oldest);
    }
    store.set(key, { value, expiresAt: Date.now() + (ttl[operation] ?? 0) });
  };

  return {
    name: 'cache',
    operations,

    before(context) {
      if (!context.state) context.state = {};
      const cached = read<unknown>(cacheKey(context.operation, context.args));
      if (cached !== undefined) {
        context.state.cacheHit = true;
        context.result = cached;
      }
    },

    after(context) {
      if (context.state?.cacheHit) return;
      write(cacheKey(context.operation, context.args), context.result, context.operation);
    },

    teardown() {
      store.clear();
    },
  };
}

// ── Chain ─────────────────────────────────────────────────────────────────────

/** A function wrapped by {@link MiddlewareChain.use}. */
export type MiddlewareOperation<TArgs extends unknown[], TResult> = (
  ...args: TArgs
) => Promise<TResult>;

/**
 * Result of running a middleware chain around an operation.
 */
export interface ChainRunResult<TResult> {
  result: TResult;
  requestId: string;
  durationMs: number;
  /** True when a cache middleware short-circuited the operation. */
  cacheHit: boolean;
}

/**
 * Composes an ordered list of middleware around SDK operations.
 *
 * @example
 * ```typescript
 * const chain = new MiddlewareChain()
 *   .use(createLoggingMiddleware())
 *   .use(createRateLimitMiddleware({ max: 10, windowMs: 1000 }));
 *
 * const { result } = await chain.run('resolveDID', [did], () => didClient.resolveDID(did));
 * ```
 *
 * @category Client
 */
export class MiddlewareChain {
  private middlewares: Middleware[] = [];
  private logger: Logger;
  /** Registry of middleware instances keyed by name, for introspection. */
  private registry = new Map<string, Middleware>();

  constructor(middlewares: Middleware[] = []) {
    this.logger = new Logger('MiddlewareChain');
    for (const mw of middlewares) this.use(mw);
  }

  /** Append a middleware to the chain and run its `setup` hook. */
  async use(middleware: Middleware): Promise<this> {
    if (!middleware?.name) {
      throw new Error('Middleware must have a name');
    }
    this.middlewares.push(middleware);
    this.registry.set(middleware.name, middleware);
    await middleware.setup?.();
    return this;
  }

  /**
   * Insert a middleware at a specific position.
   *
   * @param index - Position in the chain. Out-of-range values are clamped.
   */
  async useAt(middleware: Middleware, index: number): Promise<this> {
    if (!middleware?.name) {
      throw new Error('Middleware must have a name');
    }
    const clamped = Math.max(0, Math.min(index, this.middlewares.length));
    this.middlewares.splice(clamped, 0, middleware);
    this.registry.set(middleware.name, middleware);
    await middleware.setup?.();
    return this;
  }

  /** Remove a middleware by name, running its `teardown` hook. */
  async remove(name: string): Promise<boolean> {
    const index = this.middlewares.findIndex(mw => mw.name === name);
    if (index === -1) return false;
    const [removed] = this.middlewares.splice(index, 1);
    this.registry.delete(name);
    await removed.teardown?.();
    return true;
  }

  /** All middlewares that apply to `operation`, in chain order. */
  resolve(operation: SDKOperation): Middleware[] {
    return this.middlewares.filter(
      mw => !mw.operations || mw.operations.includes(operation),
    );
  }

  /** Names of the middlewares currently registered, in chain order. */
  names(): string[] {
    return this.middlewares.map(mw => mw.name);
  }

  /** Look up a registered middleware by name. */
  get<T extends Middleware = Middleware>(name: string): T | undefined {
    return this.registry.get(name) as T | undefined;
  }

  /**
   * Run an operation through the middleware chain.
   *
   * `before` hooks run in registration order and may rewrite the arguments;
   * `after` hooks run in reverse order and may rewrite the result. `onError`
   * runs in reverse order before the error propagates.
   *
   * @param operation - Operation name, used for hook filtering.
   * @param args - Arguments to pass to the operation.
   * @param operation_ - The actual work to perform.
   */
  async run<TArgs extends unknown[], TResult>(
    operation: SDKOperation,
    args: TArgs,
    operation_: (...args: TArgs) => Promise<TResult>,
  ): Promise<ChainRunResult<TResult>> {
    const chain = this.resolve(operation);
    const context: MiddlewareContext<TArgs, TResult> = {
      operation,
      args,
      state: {},
      requestId: nextRequestId(),
      startedAt: Date.now(),
    };

    let currentArgs = args;
    let settled = false;

    // ── before (in order) ──
    for (const mw of chain) {
      if (!mw.before) continue;
      const outcome = await mw.before(context);
      if (Array.isArray(outcome)) {
        currentArgs = outcome as unknown as TArgs;
        context.args = currentArgs;
      }
      // A cache hit short-circuits the remaining chain and the operation.
      if (context.state.cacheHit === true) {
        settled = true;
        break;
      }
    }

    let result: TResult;
    if (settled && context.state.cacheHit === true) {
      result = context.result as TResult;
    } else {
      try {
        result = await operation_(...currentArgs);
        context.result = result;
      } catch (err) {
        const error = err instanceof Error ? err : new Error(String(err));
        context.error = error;
        // onError runs in reverse order.
        for (let i = chain.length - 1; i >= 0; i--) {
          const mw = chain[i];
          if (!mw.onError) continue;
          try {
            await mw.onError(context);
          } catch (hookError) {
            this.logger.warn('onError hook threw', {
              middleware: mw.name,
              operation,
              error: hookError instanceof Error ? hookError.message : String(hookError),
            });
          }
        }
        throw error;
      }
    }

    // ── after (reverse order) ──
    let finalResult = result;
    for (let i = chain.length - 1; i >= 0; i--) {
      const mw = chain[i];
      if (!mw.after) continue;
      const outcome = await mw.after(context);
      if (outcome !== undefined) finalResult = outcome as TResult;
      context.result = finalResult;
    }

    return {
      result: finalResult,
      requestId: context.requestId,
      durationMs: Date.now() - context.startedAt,
      cacheHit: context.state.cacheHit === true,
    };
  }

  /**
   * Wrap a client method so every call flows through the chain.
   *
   * Returns a function with the same signature as the original, suitable for
   * direct assignment: `client.createDID = chain.wrap('createDID', client.createDID)`.
   */
  wrap<TArgs extends unknown[], TResult>(
    operation: SDKOperation,
    fn: MiddlewareOperation<TArgs, TResult>,
  ): MiddlewareOperation<TArgs, TResult> {
    return async (...args: TArgs): Promise<TResult> => {
      const { result } = await this.run(operation, args, fn);
      return result;
    };
  }

  /** Tear down every middleware and empty the chain. */
  async dispose(): Promise<void> {
    for (const mw of [...this.middlewares].reverse()) {
      try {
        await mw.teardown?.();
      } catch (err) {
        this.logger.warn('teardown hook threw', {
          middleware: mw.name,
          error: err instanceof Error ? err.message : String(err),
        });
      }
    }
    this.middlewares = [];
    this.registry.clear();
  }
}

/**
 * Convenience factory: build a chain from a list of middleware.
 */
export function createMiddlewareChain(middlewares: Middleware[] = []): MiddlewareChain {
  return new MiddlewareChain(middlewares);
}
