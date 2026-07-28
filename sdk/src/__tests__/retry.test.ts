/**
 * Tests for the retry engine and circuit breaker (issue #110).
 */

import {
  withRetry,
  calculateDelay,
  CircuitBreaker,
  withRetryAndCircuitBreaker,
  RetryOptions,
} from '../retry';
import {
  NetworkError,
  DIDError,
  ValidationError,
  RateLimitError,
  StellarIdentityError,
  ErrorCode,
} from '../errors';

// Silence sleep by replacing it inline — inject via jest fake timers
jest.useFakeTimers();

function flushTimers() {
  return jest.runAllTimersAsync();
}

// ─── calculateDelay ───────────────────────────────────────────────────────────

describe('calculateDelay', () => {
  const opts = { baseDelayMs: 500, backoffMultiplier: 2, maxDelayMs: 30_000, jitterFactor: 0 };

  it('attempt 1 → baseDelayMs with zero jitter', () => {
    const err = new NetworkError(ErrorCode.NetworkTimeout);
    expect(calculateDelay(1, err, opts)).toBe(500);
  });

  it('attempt 2 → 2× base', () => {
    const err = new NetworkError(ErrorCode.NetworkTimeout);
    expect(calculateDelay(2, err, opts)).toBe(1_000);
  });

  it('attempt 3 → 4× base', () => {
    const err = new NetworkError(ErrorCode.NetworkTimeout);
    expect(calculateDelay(3, err, opts)).toBe(2_000);
  });

  it('is capped at maxDelayMs', () => {
    const err = new NetworkError(ErrorCode.NetworkTimeout);
    const capped = calculateDelay(20, err, opts);
    expect(capped).toBe(30_000);
  });

  it('uses error retryDelayMs when it is larger', () => {
    const err = new RateLimitError(ErrorCode.RateLimitExceeded); // retryDelayMs=60_000
    const delay = calculateDelay(1, err, opts);
    expect(delay).toBe(60_000);
  });

  it('jitter stays within ±jitterFactor range', () => {
    const jitteredOpts = { ...opts, jitterFactor: 0.25 };
    const err = new NetworkError(ErrorCode.NetworkTimeout);
    for (let i = 0; i < 50; i++) {
      const d = calculateDelay(1, err, jitteredOpts);
      expect(d).toBeGreaterThanOrEqual(375); // 500 * (1 - 0.25)
      expect(d).toBeLessThanOrEqual(625);    // 500 * (1 + 0.25)
    }
  });
});

// ─── withRetry ────────────────────────────────────────────────────────────────

describe('withRetry', () => {
  const retryOpts: RetryOptions = {
    maxAttempts: 3,
    baseDelayMs: 0,
    jitterFactor: 0,
    operationName: 'testOp',
  };

  it('returns result on first success', async () => {
    const fn = jest.fn().mockResolvedValue('ok');
    const result = await withRetry(fn, retryOpts);
    expect(result).toBe('ok');
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it('retries on retryable NetworkError and succeeds', async () => {
    const fn = jest.fn()
      .mockRejectedValueOnce(new NetworkError(ErrorCode.NetworkTimeout))
      .mockResolvedValue('ok');

    const resultP = withRetry(fn, retryOpts);
    await flushTimers();
    const result = await resultP;

    expect(result).toBe('ok');
    expect(fn).toHaveBeenCalledTimes(2);
  });

  it('does NOT retry non-retryable DIDError', async () => {
    const fn = jest.fn().mockRejectedValue(new DIDError(ErrorCode.DIDNotFound));

    await expect(withRetry(fn, retryOpts)).rejects.toBeInstanceOf(DIDError);
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it('does NOT retry ValidationError', async () => {
    const fn = jest.fn().mockRejectedValue(new ValidationError(ErrorCode.ValidationInvalidAddress));
    await expect(withRetry(fn, retryOpts)).rejects.toBeInstanceOf(ValidationError);
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it('throws NetworkMaxRetriesExceeded after exhausting attempts', async () => {
    const fn = jest.fn().mockRejectedValue(new NetworkError(ErrorCode.NetworkTimeout));

    const p = withRetry(fn, retryOpts);
    await flushTimers();
    const err = await p.catch(e => e);

    expect(err).toBeInstanceOf(NetworkError);
    expect(err.code).toBe(ErrorCode.NetworkMaxRetriesExceeded);
    expect(fn).toHaveBeenCalledTimes(3);
  });

  it('invokes onRetry callback with correct context', async () => {
    const onRetry = jest.fn();
    const fn = jest.fn()
      .mockRejectedValueOnce(new NetworkError(ErrorCode.NetworkConnectionFailed))
      .mockResolvedValue('done');

    const p = withRetry(fn, { ...retryOpts, onRetry });
    await flushTimers();
    await p;

    expect(onRetry).toHaveBeenCalledTimes(1);
    const ctx = onRetry.mock.calls[0][0];
    expect(ctx.attempt).toBe(2);
    expect(ctx.error.code).toBe(ErrorCode.NetworkConnectionFailed);
    expect(ctx.operation).toBe('testOp');
  });

  it('notifies onRetry for non-retryable when notifyOnNonRetryable=true', async () => {
    const onRetry = jest.fn();
    const fn = jest.fn().mockRejectedValue(new DIDError(ErrorCode.DIDDeactivated));

    await expect(withRetry(fn, { ...retryOpts, onRetry, notifyOnNonRetryable: true }))
      .rejects.toBeInstanceOf(DIDError);

    expect(onRetry).toHaveBeenCalledWith(expect.objectContaining({ attempt: -1 }));
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it('maps plain Error to StellarIdentityError before retrying', async () => {
    const fn = jest.fn()
      .mockRejectedValueOnce(new Error('fetch failed: ECONNREFUSED'))
      .mockResolvedValue('mapped');

    const p = withRetry(fn, retryOpts);
    await flushTimers();
    const result = await p;
    expect(result).toBe('mapped');
    expect(fn).toHaveBeenCalledTimes(2);
  });

  it('respects maxAttempts=1 — no retries at all', async () => {
    const fn = jest.fn().mockRejectedValue(new NetworkError(ErrorCode.NetworkTimeout));
    const p = withRetry(fn, { ...retryOpts, maxAttempts: 1 });
    await flushTimers();
    const err = await p.catch(e => e);
    expect(err.code).toBe(ErrorCode.NetworkMaxRetriesExceeded);
    expect(fn).toHaveBeenCalledTimes(1);
  });
});

// ─── CircuitBreaker ───────────────────────────────────────────────────────────

describe('CircuitBreaker', () => {
  it('starts in closed state', () => {
    const cb = new CircuitBreaker('test');
    expect(cb.getState()).toBe('closed');
  });

  it('passes calls through when closed', async () => {
    const cb = new CircuitBreaker('test');
    const result = await cb.execute(() => Promise.resolve('ok'));
    expect(result).toBe('ok');
  });

  it('opens after failureThreshold consecutive failures', async () => {
    const cb = new CircuitBreaker('test', { failureThreshold: 3 });
    const fail = () => cb.execute(() => Promise.reject(new NetworkError(ErrorCode.NetworkTimeout)));

    await fail().catch(() => {});
    expect(cb.getState()).toBe('closed');
    await fail().catch(() => {});
    expect(cb.getState()).toBe('closed');
    await fail().catch(() => {});
    expect(cb.getState()).toBe('open');
  });

  it('throws immediately when open', async () => {
    const cb = new CircuitBreaker('test', { failureThreshold: 1 });
    await cb.execute(() => Promise.reject(new Error('fail'))).catch(() => {});

    expect(cb.getState()).toBe('open');
    await expect(cb.execute(() => Promise.resolve('ok')))
      .rejects.toBeInstanceOf(NetworkError);
  });

  it('transitions to half-open after resetTimeout and closes on success', async () => {
    jest.useRealTimers();

    const cb = new CircuitBreaker('test', {
      failureThreshold: 1,
      resetTimeoutMs: 50,
      successThreshold: 1,
    });

    await cb.execute(() => Promise.reject(new Error('fail'))).catch(() => {});
    expect(cb.getState()).toBe('open');

    await new Promise(r => setTimeout(r, 60));

    const result = await cb.execute(() => Promise.resolve('recovered'));
    expect(result).toBe('recovered');
    expect(cb.getState()).toBe('closed');

    jest.useFakeTimers();
  });

  it('reset() restores closed state', async () => {
    const cb = new CircuitBreaker('test', { failureThreshold: 1 });
    await cb.execute(() => Promise.reject(new Error('x'))).catch(() => {});
    expect(cb.getState()).toBe('open');

    cb.reset();
    expect(cb.getState()).toBe('closed');
    const result = await cb.execute(() => Promise.resolve('after reset'));
    expect(result).toBe('after reset');
  });

  it('invokes onStateChange callback', async () => {
    const onChange = jest.fn();
    const cb = new CircuitBreaker('test', { failureThreshold: 2, onStateChange: onChange });

    await cb.execute(() => Promise.reject(new Error('1'))).catch(() => {});
    await cb.execute(() => Promise.reject(new Error('2'))).catch(() => {});

    expect(onChange).toHaveBeenCalledWith('closed', 'open', 'test');
  });
});

// ─── withRetryAndCircuitBreaker ───────────────────────────────────────────────

describe('withRetryAndCircuitBreaker', () => {
  it('combines retry and circuit breaker', async () => {
    const breaker = new CircuitBreaker('combined', { failureThreshold: 10 });
    const fn = jest.fn()
      .mockRejectedValueOnce(new NetworkError(ErrorCode.NetworkTimeout))
      .mockResolvedValue('combined-ok');

    const p = withRetryAndCircuitBreaker(fn, breaker, {
      maxAttempts: 3, baseDelayMs: 0, jitterFactor: 0,
    });
    await flushTimers();
    const result = await p;

    expect(result).toBe('combined-ok');
    expect(fn).toHaveBeenCalledTimes(2);
    expect(breaker.getState()).toBe('closed');
  });
});
