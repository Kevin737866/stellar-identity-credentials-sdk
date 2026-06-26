// ── Constants ─────────────────────────────────────────────────────────────────

const MAX_CONTEXT_DEPTH = 5;
const MAX_HISTORY_SIZE = 500;
const DEFAULT_SAMPLE_RATE = 1.0;
const REDACTED_PLACEHOLDER = '[REDACTED]';

const SENSITIVE_KEYS = new Set([
  'password', 'secret', 'token', 'apiKey', 'api_key',
  'privateKey', 'private_key', 'authorization', 'auth',
  'credential', 'ssn', 'creditCard', 'credit_card', 'cvv',
  'mnemonic', 'seed', 'keypair',
]);

// ── Log level ─────────────────────────────────────────────────────────────────

export enum LogLevel {
  TRACE = 0,
  DEBUG = 1,
  INFO  = 2,
  WARN  = 3,
  ERROR = 4,
  SILENT = 5,
}

const LEVEL_NAMES: Record<LogLevel, string> = {
  [LogLevel.TRACE]:  'TRACE',
  [LogLevel.DEBUG]:  'DEBUG',
  [LogLevel.INFO]:   'INFO',
  [LogLevel.WARN]:   'WARN',
  [LogLevel.ERROR]:  'ERROR',
  [LogLevel.SILENT]: 'SILENT',
};

// ── Interfaces ────────────────────────────────────────────────────────────────

export interface LogContext {
  [key: string]: unknown;
}

export interface LogEntry {
  timestamp: string;
  level: string;
  levelValue: LogLevel;
  category: string;
  message: string;
  context?: LogContext;
  traceId?: string;
  spanId?: string;
  durationMs?: number;
}

export interface LogTransport {
  name: string;
  minLevel?: LogLevel;
  write(entry: LogEntry): void | Promise<void>;
}

export interface TimerHandle {
  /** Stop the timer and emit an INFO log with the elapsed duration. */
  done(message: string, context?: LogContext): void;
  /** Stop the timer and emit a WARN log (useful for slow-path detection). */
  warn(message: string, thresholdMs: number, context?: LogContext): void;
}

export interface LoggerOptions {
  /** Minimum log level. Overridden by `SDK_LOG_LEVEL` env var. */
  level?: LogLevel;
  /** Fraction of log calls to actually emit, in the range [0, 1]. Default 1.0. */
  sampleRate?: number;
  /** Fields to redact from all context objects. Merged with built-in list. */
  redactedKeys?: string[];
  /** Output pretty-printed JSON (for local development). Default false. */
  pretty?: boolean;
  /** Custom transports. If omitted, a console transport is added automatically. */
  transports?: LogTransport[];
  /** Static context merged into every log entry produced by this logger. */
  baseContext?: LogContext;
  /** Correlation ID for distributed tracing. */
  traceId?: string;
}

// ── Built-in transports ───────────────────────────────────────────────────────

/**
 * Writes to `console.*` using the appropriate method per level.
 */
export class ConsoleTransport implements LogTransport {
  name = 'console';

  constructor(
    private readonly pretty = false,
    readonly minLevel?: LogLevel,
  ) {}

  write(entry: LogEntry): void {
    const output = this.pretty
      ? JSON.stringify(entry, null, 2)
      : JSON.stringify(entry);

    switch (entry.levelValue) {
      case LogLevel.ERROR: console.error(output); break;
      case LogLevel.WARN:  console.warn(output);  break;
      case LogLevel.INFO:  console.info(output);  break;
      default:             console.debug(output); break;
    }
  }
}

/**
 * Accumulates log entries in memory. Useful in tests.
 *
 * @example
 * ```ts
 * const buf = new BufferTransport();
 * const logger = new Logger('test', { transports: [buf] });
 * logger.info('hi');
 * expect(buf.entries[0].message).toBe('hi');
 * ```
 */
export class BufferTransport implements LogTransport {
  name = 'buffer';
  readonly entries: LogEntry[] = [];

  constructor(
    private readonly maxSize = MAX_HISTORY_SIZE,
    readonly minLevel?: LogLevel,
  ) {}

  write(entry: LogEntry): void {
    this.entries.push(entry);
    if (this.entries.length > this.maxSize) this.entries.shift();
  }

  clear(): void {
    this.entries.length = 0;
  }

  filter(level: LogLevel): LogEntry[] {
    return this.entries.filter(e => e.levelValue >= level);
  }
}

/**
 * Wraps another transport and emits only sampled entries.
 */
export class SamplingTransport implements LogTransport {
  name: string;

  constructor(
    private readonly inner: LogTransport,
    private readonly rate: number,
    readonly minLevel?: LogLevel,
  ) {
    this.name = `sampling(${inner.name}, ${rate})`;
  }

  write(entry: LogEntry): void {
    if (Math.random() < this.rate) {
      this.inner.write(entry);
    }
  }
}

// ── Global registry ───────────────────────────────────────────────────────────

const registry = new Map<string, Logger>();

// ── Logger ────────────────────────────────────────────────────────────────────

/**
 * Structured, multi-transport logger with child loggers, distributed tracing
 * support, field redaction, performance timers, sampling, and an in-process
 * log history buffer.
 *
 * @example
 * ```ts
 * const log = Logger.get('auth');
 * log.info('User signed in', { userId: '123' });
 *
 * const child = log.child('oauth', { provider: 'github' });
 * const t = child.startTimer();
 * // ... do work ...
 * t.done('Token exchanged');
 * ```
 */
export class Logger {
  private readonly category: string;
  private level: LogLevel;
  private readonly transports: LogTransport[];
  private readonly baseContext: LogContext;
  private readonly redactedKeys: Set<string>;
  private readonly sampleRate: number;
  private readonly pretty: boolean;
  private traceId?: string;
  private spanId?: string;
  private readonly history: BufferTransport;
  private readonly counters: Record<string, number> = {
    trace: 0, debug: 0, info: 0, warn: 0, error: 0, total: 0,
  };

  // ── Static factory ────────────────────────────────────────────────────────

  /**
   * Return (or create) a logger for `category` from the global registry.
   */
  static get(category: string, options?: LoggerOptions): Logger {
    if (!registry.has(category)) {
      registry.set(category, new Logger(category, options));
    }
    return registry.get(category)!;
  }

  /** Remove all loggers from the global registry. */
  static clearRegistry(): void {
    registry.clear();
  }

  /**
   * Apply a new minimum level to every registered logger at once.
   * Useful in tests or for runtime log-level changes via admin API.
   */
  static setGlobalLevel(level: LogLevel): void {
    for (const logger of registry.values()) {
      logger.setLevel(level);
    }
  }

  // ── Constructor ───────────────────────────────────────────────────────────

  constructor(category: string, options: LoggerOptions = {}) {
    this.category = category;
    this.level =
      parseLogLevel(process.env.SDK_LOG_LEVEL) ??
      options.level ??
      LogLevel.INFO;
    this.sampleRate = options.sampleRate ?? DEFAULT_SAMPLE_RATE;
    this.pretty = options.pretty ?? false;
    this.baseContext = options.baseContext ?? {};
    this.traceId = options.traceId;
    this.redactedKeys = new Set([
      ...SENSITIVE_KEYS,
      ...(options.redactedKeys ?? []).map(k => k.toLowerCase()),
    ]);

    this.history = new BufferTransport(MAX_HISTORY_SIZE, LogLevel.WARN);

    this.transports = options.transports?.length
      ? options.transports
      : [new ConsoleTransport(this.pretty)];

    // Always maintain an internal history buffer for WARN+.
    this.transports.push(this.history);
  }

  // ── Child loggers ─────────────────────────────────────────────────────────

  /**
   * Create a child logger that inherits the current logger's configuration
   * and merges `extraContext` into every entry it produces.
   *
   * @param subcategory - Appended to the parent's category as `parent:child`.
   * @param extraContext - Additional fields merged into every child log entry.
   */
  child(subcategory: string, extraContext: LogContext = {}): Logger {
    return new Logger(`${this.category}:${subcategory}`, {
      level: this.level,
      sampleRate: this.sampleRate,
      pretty: this.pretty,
      transports: this.transports.filter(t => !(t instanceof BufferTransport)),
      baseContext: { ...this.baseContext, ...extraContext },
      traceId: this.traceId,
    });
  }

  // ── Distributed tracing ───────────────────────────────────────────────────

  /** Attach a trace ID to all subsequent log entries from this logger. */
  setTraceId(traceId: string): this {
    this.traceId = traceId;
    return this;
  }

  /** Attach a span ID to all subsequent log entries from this logger. */
  setSpanId(spanId: string): this {
    this.spanId = spanId;
    return this;
  }

  // ── Level control ─────────────────────────────────────────────────────────

  setLevel(level: LogLevel): this {
    this.level = level;
    return this;
  }

  getLevel(): LogLevel {
    return this.level;
  }

  isLevelEnabled(level: LogLevel): boolean {
    return level >= this.level;
  }

  // ── Logging methods ───────────────────────────────────────────────────────

  trace(message: string, context?: LogContext): void {
    this.log(LogLevel.TRACE, message, context);
  }

  debug(message: string, context?: LogContext): void {
    this.log(LogLevel.DEBUG, message, context);
  }

  info(message: string, context?: LogContext): void {
    this.log(LogLevel.INFO, message, context);
  }

  warn(message: string, context?: LogContext): void {
    this.log(LogLevel.WARN, message, context);
  }

  error(message: string, error?: Error | unknown, context?: LogContext): void {
    this.log(LogLevel.ERROR, message, {
      ...context,
      error: serializeError(error),
    });
  }

  /**
   * Log at a level determined at call time — useful when the caller receives
   * a level value from configuration.
   */
  log(level: LogLevel, message: string, context?: LogContext): void {
    if (level >= LogLevel.SILENT || level < this.level) return;
    if (this.sampleRate < 1.0 && Math.random() > this.sampleRate) return;

    const levelName = LEVEL_NAMES[level] ?? 'UNKNOWN';
    this.counters[levelName.toLowerCase() as keyof typeof this.counters]++;
    this.counters.total++;

    const merged: LogContext = this.baseContext
      ? { ...this.baseContext, ...context }
      : (context ?? {});

    const entry: LogEntry = {
      timestamp: new Date().toISOString(),
      level: levelName,
      levelValue: level,
      category: this.category,
      message,
      ...(Object.keys(merged).length > 0 && {
        context: this.redact(merged),
      }),
      ...(this.traceId && { traceId: this.traceId }),
      ...(this.spanId && { spanId: this.spanId }),
    };

    for (const transport of this.transports) {
      if (transport.minLevel !== undefined && level < transport.minLevel) {
        continue;
      }
      try {
        transport.write(entry);
      } catch {
        // A failing transport must never crash the caller.
      }
    }
  }

  // ── Performance timers ────────────────────────────────────────────────────

  /**
   * Start a high-resolution timer.  Call `.done()` or `.warn()` on the
   * returned handle to emit a log entry with the elapsed duration.
   *
   * @example
   * ```ts
   * const t = logger.startTimer();
   * await doWork();
   * t.done('DB query complete', { rows: 42 });
   * t.warn('Slow DB query', 200, { rows: 42 }); // logs WARN if > 200 ms
   * ```
   */
  startTimer(context?: LogContext): TimerHandle {
    const start = performance.now();

    return {
      done: (message: string, extraContext?: LogContext) => {
        const durationMs = parseFloat((performance.now() - start).toFixed(3));
        this.log(LogLevel.INFO, message, {
          ...context,
          ...extraContext,
          durationMs,
        });
      },
      warn: (message: string, thresholdMs: number, extraContext?: LogContext) => {
        const durationMs = parseFloat((performance.now() - start).toFixed(3));
        const level = durationMs > thresholdMs ? LogLevel.WARN : LogLevel.DEBUG;
        this.log(level, message, {
          ...context,
          ...extraContext,
          durationMs,
          thresholdMs,
          slow: durationMs > thresholdMs,
        });
      },
    };
  }

  // ── Conditional logging ───────────────────────────────────────────────────

  /**
   * Execute `fn` and log the result only if `condition` is true.
   * Avoids building the log context object when logging is disabled.
   */
  logIf(
    condition: boolean,
    level: LogLevel,
    message: string,
    contextFn?: () => LogContext,
  ): void {
    if (condition && this.isLevelEnabled(level)) {
      this.log(level, message, contextFn?.());
    }
  }

  /**
   * Log a message only once, identified by a deduplication key.
   * Subsequent calls with the same key are silently dropped.
   */
  private readonly onceSeen = new Set<string>();
  logOnce(
    key: string,
    level: LogLevel,
    message: string,
    context?: LogContext,
  ): void {
    if (this.onceSeen.has(key)) return;
    this.onceSeen.add(key);
    this.log(level, message, context);
  }

  // ── Transport management ──────────────────────────────────────────────────

  /**
   * Add a transport at runtime (e.g. to attach a remote sink after startup).
   */
  addTransport(transport: LogTransport): this {
    if (!this.transports.find(t => t.name === transport.name)) {
      this.transports.push(transport);
    }
    return this;
  }

  /**
   * Remove a transport by name.
   */
  removeTransport(name: string): this {
    const idx = this.transports.findIndex(t => t.name === name);
    if (idx !== -1) this.transports.splice(idx, 1);
    return this;
  }

  // ── History & metrics ─────────────────────────────────────────────────────

  /**
   * Return recent WARN+ entries held in the internal ring buffer.
   */
  getHistory(minLevel: LogLevel = LogLevel.WARN): LogEntry[] {
    return this.history.filter(minLevel);
  }

  /**
   * Return a snapshot of how many entries were emitted per level.
   */
  getMetrics(): Record<string, number> {
    return { ...this.counters };
  }

  /** Reset all counters. */
  resetMetrics(): void {
    for (const key of Object.keys(this.counters)) {
      this.counters[key] = 0;
    }
  }

  // ── Private helpers ───────────────────────────────────────────────────────

  /**
   * Recursively redact sensitive keys from a context object.
   * Handles circular references and respects `MAX_CONTEXT_DEPTH`.
   */
  private redact(context: LogContext, depth = 0): LogContext {
    if (depth > MAX_CONTEXT_DEPTH) return { '[truncated]': true };

    const out: LogContext = {};
    for (const [key, value] of Object.entries(context)) {
      if (this.redactedKeys.has(key.toLowerCase())) {
        out[key] = REDACTED_PLACEHOLDER;
        continue;
      }
      if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
        out[key] = this.redact(value as LogContext, depth + 1);
      } else if (Array.isArray(value)) {
        out[key] = value.map(item =>
          item !== null && typeof item === 'object'
            ? this.redact(item as LogContext, depth + 1)
            : item,
        );
      } else {
        out[key] = value;
      }
    }
    return out;
  }
}

// ── Module-level helpers ──────────────────────────────────────────────────────

function parseLogLevel(levelStr?: string): LogLevel | undefined {
  if (!levelStr) return undefined;
  const upper = levelStr.toUpperCase();
  for (const [name, value] of Object.entries(LogLevel)) {
    if (typeof value === 'number' && name === upper) return value as LogLevel;
  }
  return undefined;
}

function serializeError(error: unknown): Record<string, unknown> {
  if (error instanceof Error) {
    const serialized: Record<string, unknown> = {
      name: error.name,
      message: error.message,
      stack: error.stack,
    };
    // Capture any extra enumerable properties (e.g. `code` on NodeJS errors).
    for (const [key, value] of Object.entries(error)) {
      serialized[key] = value;
    }
    if ((error as { cause?: unknown }).cause !== undefined) {
      serialized.cause = serializeError((error as { cause?: unknown }).cause);
    }
    return serialized;
  }
  return { raw: String(error) };
}