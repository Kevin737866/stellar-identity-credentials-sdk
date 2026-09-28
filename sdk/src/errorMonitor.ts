/**
 * Error monitoring and reporting hooks for the Stellar Identity SDK.
 *
 * Provides:
 *  - Global and per-domain error event hooks
 *  - Aggregated error counters by code, class, and domain
 *  - Recent error history (ring buffer)
 *  - JSON-serialisable snapshots for telemetry export
 *  - Built-in console reporter and a no-op reporter for tests
 *
 * @module errorMonitor
 * @category Errors
 */

import {
  StellarIdentityError,
  ErrorCode,
  ErrorClass,
} from './errors';

// ── Types ─────────────────────────────────────────────────────────────────────

/** A recorded error event. */
export interface ErrorEvent {
  /** Unique monotonically-increasing event ID within this monitor instance. */
  id: number;
  /** Unix timestamp (ms) when the error was captured. */
  timestamp: number;
  /** The error code. */
  code: ErrorCode;
  /** Classification of the error. */
  errorClass: ErrorClass;
  /** Error name (class name). */
  name: string;
  /** Error message. */
  message: string;
  /** Recovery hint. */
  recovery: string;
  /** Whether this error is retryable. */
  retryable: boolean;
  /** Structured details attached to the error. */
  details: Record<string, unknown>;
  /** Logical domain tag supplied by the reporter (e.g. "didClient"). */
  domain?: string;
  /** Optional operation name (e.g. "createDID"). */
  operation?: string;
}

/** Aggregated counter snapshot. */
export interface ErrorStats {
  /** Total errors captured. */
  total: number;
  /** Counts keyed by ErrorCode number. */
  byCode: Record<number, number>;
  /** Counts keyed by ErrorClass string. */
  byClass: Record<string, number>;
  /** Counts keyed by domain tag. */
  byDomain: Record<string, number>;
  /** Counts keyed by error name. */
  byName: Record<string, number>;
}

/** Callback invoked synchronously when an error is captured. */
export type ErrorHook = (event: ErrorEvent) => void;

/** Reporter interface — implement to send errors to external systems. */
export interface ErrorReporter {
  report(event: ErrorEvent): void | Promise<void>;
}

export interface ErrorMonitorOptions {
  /**
   * Maximum number of events kept in the ring buffer.
   * @default 200
   */
  historySize?: number;
  /**
   * Default domain tag applied when none is supplied.
   * @default 'sdk'
   */
  defaultDomain?: string;
  /**
   * External reporters (e.g. Sentry, Datadog, custom webhook).
   */
  reporters?: ErrorReporter[];
}

// ── ErrorMonitor ──────────────────────────────────────────────────────────────

/**
 * Central error monitoring hub.
 *
 * Capture errors from any SDK client and route them to registered hooks and
 * reporters. A single global instance is available via `ErrorMonitor.global()`,
 * but you can also create isolated instances for testing.
 *
 * @example
 * ```typescript
 * import { ErrorMonitor } from '@stellar-identity/sdk';
 *
 * // Subscribe to all errors
 * ErrorMonitor.global().onError(event => {
 *   console.error(`[${event.code}] ${event.message}\nFix: ${event.recovery}`);
 * });
 *
 * // Subscribe to network errors only
 * ErrorMonitor.global().onErrorClass('network', event => {
 *   myMetrics.increment('sdk.network_errors');
 * });
 * ```
 *
 * @category Errors
 */
export class ErrorMonitor {
  private static _global: ErrorMonitor | null = null;

  private readonly history: ErrorEvent[] = [];
  private readonly maxHistory: number;
  private readonly defaultDomain: string;
  private readonly reporters: ErrorReporter[];

  private readonly globalHooks: ErrorHook[] = [];
  private readonly classHooks: Map<ErrorClass, ErrorHook[]> = new Map();
  private readonly codeHooks:  Map<ErrorCode, ErrorHook[]>  = new Map();
  private readonly domainHooks: Map<string, ErrorHook[]>    = new Map();

  private readonly stats: ErrorStats = {
    total: 0,
    byCode: {},
    byClass: {},
    byDomain: {},
    byName: {},
  };

  private nextId = 1;

  constructor(options: ErrorMonitorOptions = {}) {
    this.maxHistory    = options.historySize    ?? 200;
    this.defaultDomain = options.defaultDomain  ?? 'sdk';
    this.reporters     = options.reporters      ?? [];
  }

  /** Return (or lazily create) the process-level global monitor. */
  static global(): ErrorMonitor {
    if (!ErrorMonitor._global) {
      ErrorMonitor._global = new ErrorMonitor();
    }
    return ErrorMonitor._global;
  }

  /** Replace the global monitor (useful in tests). */
  static setGlobal(monitor: ErrorMonitor): void {
    ErrorMonitor._global = monitor;
  }

  /** Reset the global monitor to null (force re-creation on next access). */
  static resetGlobal(): void {
    ErrorMonitor._global = null;
  }

  // ── Capture ───────────────────────────────────────────────────────────────

  /**
   * Capture a `StellarIdentityError` and dispatch it to all matching hooks
   * and reporters.
   *
   * @param error     - The error to capture.
   * @param domain    - Logical domain (e.g. "didClient", "credentialClient").
   * @param operation - Optional operation name (e.g. "createDID").
   * @returns The error event that was created.
   */
  capture(
    error: StellarIdentityError,
    domain?: string,
    operation?: string,
  ): ErrorEvent {
    const event: ErrorEvent = {
      id:         this.nextId++,
      timestamp:  error.timestamp,
      code:       error.code,
      errorClass: error.errorClass,
      name:       error.name,
      message:    error.message,
      recovery:   error.recovery,
      retryable:  error.retryable,
      details:    error.details,
      domain:     domain ?? this.defaultDomain,
      operation,
    };

    // Store in ring buffer
    this.history.push(event);
    if (this.history.length > this.maxHistory) this.history.shift();

    // Update stats
    this.stats.total++;
    this.stats.byCode[event.code]   = (this.stats.byCode[event.code]   ?? 0) + 1;
    this.stats.byClass[event.errorClass] = (this.stats.byClass[event.errorClass] ?? 0) + 1;
    this.stats.byDomain[event.domain!]   = (this.stats.byDomain[event.domain!]   ?? 0) + 1;
    this.stats.byName[event.name]   = (this.stats.byName[event.name]   ?? 0) + 1;

    // Dispatch hooks
    this.globalHooks.forEach(h => this.safeCall(h, event));
    this.classHooks.get(event.errorClass)?.forEach(h => this.safeCall(h, event));
    this.codeHooks.get(event.code)?.forEach(h => this.safeCall(h, event));
    if (event.domain) this.domainHooks.get(event.domain)?.forEach(h => this.safeCall(h, event));

    // Dispatch reporters (fire-and-forget for async ones)
    this.reporters.forEach(r => {
      try { r.report(event); } catch { /* reporters must not crash callers */ }
    });

    return event;
  }

  // ── Hook registration ─────────────────────────────────────────────────────

  /** Subscribe to every captured error. Returns an unsubscribe function. */
  onError(hook: ErrorHook): () => void {
    this.globalHooks.push(hook);
    return () => this.removeHook(this.globalHooks, hook);
  }

  /** Subscribe to errors of a specific classification. */
  onErrorClass(errorClass: ErrorClass, hook: ErrorHook): () => void {
    const hooks = this.classHooks.get(errorClass) ?? [];
    hooks.push(hook);
    this.classHooks.set(errorClass, hooks);
    return () => this.removeHook(hooks, hook);
  }

  /** Subscribe to a specific error code. */
  onErrorCode(code: ErrorCode, hook: ErrorHook): () => void {
    const hooks = this.codeHooks.get(code) ?? [];
    hooks.push(hook);
    this.codeHooks.set(code, hooks);
    return () => this.removeHook(hooks, hook);
  }

  /** Subscribe to errors from a specific domain. */
  onDomain(domain: string, hook: ErrorHook): () => void {
    const hooks = this.domainHooks.get(domain) ?? [];
    hooks.push(hook);
    this.domainHooks.set(domain, hooks);
    return () => this.removeHook(hooks, hook);
  }

  // ── Reporter management ───────────────────────────────────────────────────

  /** Add an external reporter at runtime. */
  addReporter(reporter: ErrorReporter): void {
    this.reporters.push(reporter);
  }

  /** Remove an external reporter by reference. */
  removeReporter(reporter: ErrorReporter): void {
    const idx = this.reporters.indexOf(reporter);
    if (idx !== -1) this.reporters.splice(idx, 1);
  }

  // ── Queries ───────────────────────────────────────────────────────────────

  /** Return a shallow copy of all captured events. */
  getHistory(): ErrorEvent[] { return [...this.history]; }

  /** Return the most recent `n` events (default 10). */
  getRecentErrors(n = 10): ErrorEvent[] {
    return this.history.slice(-Math.max(1, n));
  }

  /** Return all events matching the given error class. */
  getByClass(errorClass: ErrorClass): ErrorEvent[] {
    return this.history.filter(e => e.errorClass === errorClass);
  }

  /** Return all events matching the given error code. */
  getByCode(code: ErrorCode): ErrorEvent[] {
    return this.history.filter(e => e.code === code);
  }

  /** Return all events from the given domain. */
  getByDomain(domain: string): ErrorEvent[] {
    return this.history.filter(e => e.domain === domain);
  }

  /** Return a snapshot of aggregated statistics. */
  getStats(): Readonly<ErrorStats> {
    return {
      total:    this.stats.total,
      byCode:   { ...this.stats.byCode },
      byClass:  { ...this.stats.byClass },
      byDomain: { ...this.stats.byDomain },
      byName:   { ...this.stats.byName },
    };
  }

  /** Clear history and reset all counters. */
  reset(): void {
    this.history.length = 0;
    this.stats.total = 0;
    this.stats.byCode   = {};
    this.stats.byClass  = {};
    this.stats.byDomain = {};
    this.stats.byName   = {};
  }

  /** Clear all registered hooks (useful in tests). */
  clearHooks(): void {
    this.globalHooks.length = 0;
    this.classHooks.clear();
    this.codeHooks.clear();
    this.domainHooks.clear();
  }

  // ── Private ───────────────────────────────────────────────────────────────

  private safeCall(hook: ErrorHook, event: ErrorEvent): void {
    try { hook(event); } catch { /* hooks must not crash callers */ }
  }

  private removeHook(list: ErrorHook[], hook: ErrorHook): void {
    const idx = list.indexOf(hook);
    if (idx !== -1) list.splice(idx, 1);
  }
}

// ── Built-in reporters ────────────────────────────────────────────────────────

/**
 * Reporter that writes errors to the console in a structured format.
 * @category Errors
 */
export class ConsoleErrorReporter implements ErrorReporter {
  constructor(
    private readonly minClass: ErrorClass = 'network',
    private readonly pretty = false,
  ) {}

  report(event: ErrorEvent): void {
    const priority: Record<ErrorClass, number> = {
      validation: 0, auth: 1, contract: 2, network: 3, ratelimit: 3, unknown: 4,
    };
    if (priority[event.errorClass] < priority[this.minClass]) return;

    const output = this.pretty
      ? JSON.stringify(event, null, 2)
      : JSON.stringify(event);
    console.error(`[stellar-identity:error] ${output}`);
  }
}

/**
 * No-op reporter — swallows all events. Useful as a placeholder in tests.
 * @category Errors
 */
export class NoOpErrorReporter implements ErrorReporter {
  readonly captured: ErrorEvent[] = [];
  report(event: ErrorEvent): void { this.captured.push(event); }
}
