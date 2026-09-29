/**
 * Automatic retry with exponential back-off and jitter.
 *
 * The retry engine is tightly integrated with the error classification system:
 * only errors whose `retryable` flag is `true` trigger a retry. Non-retryable
 * errors (contract rejections, validation failures, auth errors) are re-thrown
 * immediately.
 *
 * Features:
 *  - Exponential back-off with configurable base delay and multiplier
 *  - Full jitter (± 25 % of computed delay) to prevent thundering herds
 *  - Per-error-code minimum delay override from `error.retryDelayMs`
 *  - Configurable maximum attempts and maximum total delay cap
 *  - Optional `onRetry` callback for logging / monitoring hooks
 *  - Circuit-breaker integration via `CircuitBreaker` class
 *
 * @module retry
 * @category Retry
 */

import {
  StellarIdentityError,
  NetworkError,
  RateLimitError,
  ErrorCode,
  isRetryableError,
  mapContractError,
} from './errors';

// ── Types ─────────────────────────────────────────────────────────────────────

/** Callback invoked before each retry attempt. */
export type OnRetryCallback = (context: RetryContext) => void;

export interface RetryContext {
  /** 1-based attempt number that is about to be executed. */
  attempt: number;
  /** Maximum attempts configured. */
  maxAttempts: number;
  /** The error that caused the previous attempt to fail. */
  error: StellarIdentityError;
  /** Computed delay in milliseconds before this attempt. */
  delayMs: number;
  /** Name of the operation being retried. */
  operation: string;
}

export interface RetryOptions {
  /**
   * Maximum number of total attempts (including the first).
   * @default 3
   */
  maxAttempts?: number;
  /**
   * Base delay for the first retry in milliseconds.
   * @default 500
   */
  baseDelayMs?: number;
  /**
   * Multiplier applied to the delay after each failed attempt.
   * @default 2
   */
  backoffMultiplier?: number;
  /**
   * Absolute ceiling on the computed delay.
   * @default 30_000
   */
  maxDelayMs?: number;
  /**
   * Jitter factor in the range [0, 1]. 0.25 means ±25 % randomisation.
   * @default 0.25
   */
  jitterFactor?: number;
  /**
   * Human-readable name for the operation — used in log messages and errors.
   * @default 'operation'
   */
  operationName?: string;
  /**
   * Called before each retry attempt. Use for logging or monitoring hooks.
   */
  onRetry?: OnRetryCallback;
  /**
   * When true, non-retryable errors are still passed to `onRetry` (with
   * attempt = -1) before being re-thrown, so callers can observe all failures.
   * @default false
   */
  notifyOnNonRetryable?: boolean;
}

// ── Defaults ──────────────────────────────────────────────────────────────────

const DEFAULT_MAX_ATTEMPTS    = 3;
const DEFAULT_BASE_DELAY_MS   = 500;
const DEFAULT_BACKOFF_MULT    = 2;
const DEFAULT_MAX_DELAY_MS    = 30_000;
const DEFAULT_JITTER_FACTOR   = 0.25;

// ── Delay calculation ─────────────────────────────────────────────────────────

/**
 * Calculate the delay before attempt number `attempt` (1-based).
 *
 * Formula: `min(maxDelay, base * multiplier^(attempt-1)) ± jitter`
 *
 * If the error itself has a `retryDelayMs` hint that is larger than the
 * computed delay, the error's hint takes precedence.
 */
export function calculateDelay(
  attempt: number,
  error: StellarIdentityError,
  options: Required<Pick<RetryOptions,
    'baseDelayMs' | 'backoffMultiplier' | 'maxDelayMs' | 'jitterFactor'>>,
): number {
  const exponential = options.baseDelayMs * Math.pow(options.backoffMultiplier, attempt - 1);
  const capped      = Math.min(exponential, options.maxDelayMs);
  const errorMin    = error.retryDelayMs ?? 0;
  const base        = Math.max(capped, errorMin);
  const jitter      = base * options.jitterFactor * (Math.random() * 2 - 1); // ±factor
  return Math.max(0, Math.round(base + jitter));
}

// ── Core retry function ───────────────────────────────────────────────────────

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Execute `fn` with automatic retry on transient / retryable errors.
 *
 * ```typescript
 * const result = await withRetry(
 *   () => sdk.did.resolveDID(did),
 *   { maxAttempts: 4, baseDelayMs: 1000, operationName: 'resolveDID' },
 * );
 * ```
 *
 * @category Retry
 */
export async function withRetry<T>(
  fn: () => Promise<T>,
  options: RetryOptions = {},
): Promise<T> {
  const maxAttempts       = options.maxAttempts       ?? DEFAULT_MAX_ATTEMPTS;
  const baseDelayMs       = options.baseDelayMs       ?? DEFAULT_BASE_DELAY_MS;
  const backoffMultiplier = options.backoffMultiplier ?? DEFAULT_BACKOFF_MULT;
  const maxDelayMs        = options.maxDelayMs        ?? DEFAULT_MAX_DELAY_MS;
  const jitterFactor      = options.jitterFactor      ?? DEFAULT_JITTER_FACTOR;
  const operationName     = options.operationName     ?? 'operation';

  const delayOpts = { baseDelayMs, backoffMultiplier, maxDelayMs, jitterFactor };

  let lastError: StellarIdentityError | null = null;

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      const result = await fn();
      // A success on attempt 1 is a clean success; anything later means the
      // endpoint recovered and the caller should know retries are firing.
      if (attempt === 1) globalMetrics.succeeded++;
      else globalMetrics.succeededAfterRetry++;
      recordMetrics(attempt, 0, null);
      return result;
    } catch (raw) {
      const err = raw instanceof StellarIdentityError
        ? raw
        : mapContractError(raw);

      lastError = err;

      // Non-retryable — notify if configured, then re-throw immediately
      if (!isRetryableError(err)) {
        globalMetrics.abortedNonRetryable++;
        recordMetrics(attempt, 0, err);
        if (options.notifyOnNonRetryable && options.onRetry) {
          options.onRetry({ attempt: -1, maxAttempts, error: err, delayMs: 0, operation: operationName });
        }
        throw err;
      }

      // Last attempt — don't sleep, just throw
      if (attempt === maxAttempts) break;

      const delayMs = calculateDelay(attempt, err, delayOpts);
      recordMetrics(attempt, delayMs, err);

      if (options.onRetry) {
        options.onRetry({ attempt: attempt + 1, maxAttempts, error: err, delayMs, operation: operationName });
      }

      await sleep(delayMs);
    }
  }

  // All attempts exhausted
  globalMetrics.failed++;
  throw new NetworkError(
    ErrorCode.NetworkMaxRetriesExceeded,
    `${operationName} failed after ${maxAttempts} attempts. Last error: ${lastError?.message ?? 'unknown'}`,
    { lastError: lastError?.toJSON(), maxAttempts, operationName },
  );
}

// ── Retry metrics ─────────────────────────────────────────────────────────────

/**
 * Aggregate counters describing retry behaviour.
 *
 * @category Retry
 */
export interface RetryMetrics {
  /** Calls that completed on the first attempt. */
  succeeded: number;
  /** Calls that ultimately returned a value, after one or more retries. */
  succeededAfterRetry: number;
  /** Calls that exhausted their attempt budget. */
  failed: number;
  /** Calls abandoned because the error was not retryable. */
  abortedNonRetryable: number;
  /** Total individual attempts made, including successful first attempts. */
  totalAttempts: number;
  /** Total milliseconds spent sleeping between attempts. */
  totalDelayMs: number;
  /** Longest single back-off delay observed. */
  maxDelayMs: number;
  /** Failures bucketed by the error code that caused them. */
  errorsByCode: Record<number, number>;
}

/**
 * Process-wide retry metrics.
 *
 * Instrumenting retries is the only way to answer "is the endpoint degrading?"
 * in production — a rising `succeededAfterRetry` count with a flat `failed`
 * count is a warning that turns into an outage if ignored, and it is invisible
 * in application logs because every call ultimately returned a value.
 *
 * Counters are process-local and never reset automatically, so a scraper can
 * compute a rate over any window it chooses.
 *
 * ```ts
 * const stats = getRetryMetrics();
 * const retryRate = stats.totalAttempts / (stats.succeeded + stats.failed);
 * ```
 *
 * @category Retry
 */
let globalMetrics: RetryMetrics = createRetryMetrics();

/** A fresh, zeroed metrics object. */
export function createRetryMetrics(): RetryMetrics {
  return {
    succeeded: 0,
    succeededAfterRetry: 0,
    failed: 0,
    abortedNonRetryable: 0,
    totalAttempts: 0,
    totalDelayMs: 0,
    maxDelayMs: 0,
    errorsByCode: {},
  };
}

/** Snapshot the current retry metrics. @category Retry */
export function getRetryMetrics(): RetryMetrics {
  return { ...globalMetrics, errorsByCode: { ...globalMetrics.errorsByCode } };
}

/** Reset the retry counters to zero. Intended for tests. @category Retry */
export function resetRetryMetrics(): void {
  globalMetrics = createRetryMetrics();
}

/** Record an attempt against the global counters. */
function recordMetrics(attempt: number, delayMs: number, error: StellarIdentityError | null): void {
  globalMetrics.totalAttempts++;
  if (delayMs > 0) {
    globalMetrics.totalDelayMs += delayMs;
    if (delayMs > globalMetrics.maxDelayMs) globalMetrics.maxDelayMs = delayMs;
  }
  if (error) {
    globalMetrics.errorsByCode[error.code] = (globalMetrics.errorsByCode[error.code] ?? 0) + 1;
  }
}

// ── Circuit Breaker ───────────────────────────────────────────────────────────

export type CircuitState = 'closed' | 'open' | 'half-open';

export interface CircuitBreakerOptions {
  /**
   * Number of consecutive failures before the circuit opens.
   * @default 5
   */
  failureThreshold?: number;
  /**
   * Number of consecutive successes in half-open state before closing.
   * @default 2
   */
  successThreshold?: number;
  /**
   * How long (ms) the circuit stays open before transitioning to half-open.
   * @default 60_000
   */
  resetTimeoutMs?: number;
  /** Called whenever the circuit transitions state. */
  onStateChange?: (from: CircuitState, to: CircuitState, name: string) => void;
}

/**
 * Circuit breaker that wraps async operations and prevents repeated calls
 * to a failing service.
 *
 * States:
 * - **closed** — normal operation; failures are counted
 * - **open**   — calls fail immediately without executing `fn`
 * - **half-open** — trial calls allowed; success closes, failure re-opens
 *
 * ```typescript
 * const breaker = new CircuitBreaker('rpc', { failureThreshold: 3 });
 * const result  = await breaker.execute(() => sdk.did.resolveDID(did));
 * ```
 *
 * @category Retry
 */
export class CircuitBreaker {
  private state: CircuitState = 'closed';
  private failures = 0;
  private successes = 0;
  private openedAt: number | null = null;

  private readonly failureThreshold: number;
  private readonly successThreshold: number;
  private readonly resetTimeoutMs: number;
  private readonly onStateChange?: CircuitBreakerOptions['onStateChange'];

  constructor(
    public readonly name: string,
    options: CircuitBreakerOptions = {},
  ) {
    this.failureThreshold = options.failureThreshold ?? 5;
    this.successThreshold = options.successThreshold ?? 2;
    this.resetTimeoutMs   = options.resetTimeoutMs   ?? 60_000;
    this.onStateChange    = options.onStateChange;
  }

  /** Current circuit state. */
  getState(): CircuitState { return this.state; }

  /** Reset the breaker to closed state (useful in tests). */
  reset(): void {
    this.transition('closed');
    this.failures = 0;
    this.successes = 0;
    this.openedAt = null;
  }

  /** Execute `fn` guarded by the circuit breaker. */
  async execute<T>(fn: () => Promise<T>): Promise<T> {
    if (this.state === 'open') {
      // Check if the reset timeout has elapsed
      if (this.openedAt !== null && Date.now() - this.openedAt >= this.resetTimeoutMs) {
        this.transition('half-open');
      } else {
        globalMetrics.abortedNonRetryable++;
        throw new NetworkError(
          ErrorCode.NetworkConnectionFailed,
          `Circuit breaker "${this.name}" is OPEN. Calls are blocked until ${
            this.openedAt ? new Date(this.openedAt + this.resetTimeoutMs).toISOString() : 'reset'
          }.`,
          { circuitName: this.name, state: this.state },
        );
      }
    }

    try {
      const result = await fn();
      this.onSuccess();
      return result;
    } catch (err) {
      this.onFailure();
      throw err;
    }
  }

  private onSuccess(): void {
    this.failures = 0;
    if (this.state === 'half-open') {
      this.successes++;
      if (this.successes >= this.successThreshold) {
        this.successes = 0;
        this.transition('closed');
      }
    }
  }

  private onFailure(): void {
    this.successes = 0;
    this.failures++;
    if (this.state === 'closed' && this.failures >= this.failureThreshold) {
      this.openedAt = Date.now();
      this.transition('open');
    } else if (this.state === 'half-open') {
      this.openedAt = Date.now();
      this.transition('open');
    }
  }

  private transition(to: CircuitState): void {
    const from = this.state;
    this.state = to;
    this.onStateChange?.(from, to, this.name);
  }
}

// ── Retry + circuit breaker combined ─────────────────────────────────────────

/**
 * Execute `fn` with both retry-on-transient-error and circuit-breaker protection.
 *
 * The circuit breaker wraps the entire retry loop, so a persistently-open
 * circuit prevents retries from firing at all.
 *
 * @category Retry
 */
export async function withRetryAndCircuitBreaker<T>(
  fn: () => Promise<T>,
  breaker: CircuitBreaker,
  retryOptions: RetryOptions = {},
): Promise<T> {
  return breaker.execute(() => withRetry(fn, retryOptions));
}
