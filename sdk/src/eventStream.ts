/**
 * eventStream.ts
 *
 * Real-time event subscription built on a WebSocket transport to the Stellar
 * network. Complements `EventSubscriber` with:
 *
 *   - a `subscribeToEvents` entry point taking declarative filters
 *   - exponential backoff reconnection with jitter and a reset-on-success policy
 *   - structural filtering by address, credential type, DID and credential id
 *   - an async-iterator interface for `for await` consumption
 *   - connection health metrics
 *
 * The WebSocket factory is injectable so the same code runs in Node (tests,
 * SSR) and the browser without touching global state.
 */

import { Logger } from './logger';
import type { StellarIdentityConfig } from './types';

// ── Types ─────────────────────────────────────────────────────────────────────

/** Event types published by the identity contracts. */
export type IdentityEventType =
  | 'DIDCreated'
  | 'DIDUpdated'
  | 'DIDDeactivated'
  | 'CredentialIssued'
  | 'CredentialRevoked'
  | 'CredentialExpired'
  | 'ReputationScoreUpdated'
  | 'ProofVerified'
  | 'AddressSanctioned'
  | 'AddressDesanctioned';

export const IDENTITY_EVENT_TYPES: readonly IdentityEventType[] = [
  'DIDCreated',
  'DIDUpdated',
  'DIDDeactivated',
  'CredentialIssued',
  'CredentialRevoked',
  'CredentialExpired',
  'ReputationScoreUpdated',
  'ProofVerified',
  'AddressSanctioned',
  'AddressDesanctioned',
] as const;

/** A single on-chain event delivered over the stream. */
export interface IdentityEvent<T = Record<string, unknown>> {
  id: string;
  type: IdentityEventType;
  data: T;
  /** Epoch ms the event was observed. */
  timestamp: number;
  /** Ledger sequence, when the transport reports one. */
  ledger?: number;
  /** Contract that emitted the event. */
  contractAddress?: string;
}

/** Declarative filter applied before delivery to a handler. */
export interface EventFilters {
  /** Only these event types. Omit or leave empty for all types. */
  types?: IdentityEventType[];
  /** Only events referencing this Stellar address. */
  address?: string;
  /** Only events with this credential type. */
  credentialType?: string;
  /** Only events for this credential. */
  credentialId?: string;
  /** Only events for this DID (or its underlying address). */
  did?: string;
  /** Only events from this contract. */
  contractAddress?: string;
  /** Only events with a reputation score at or above this value. */
  minScore?: number;
  /** Only events with a reputation score at or below this value. */
  maxScore?: number;
  /** Escape hatch for anything the declarative fields cannot express. */
  predicate?: (event: IdentityEvent) => boolean;
}

export type EventHandler<T = Record<string, unknown>> = (event: IdentityEvent<T>) => void;

/** Handle returned by `subscribeToEvents`. */
export interface EventSubscription {
  id: string;
  /** Stop receiving events and release resources. Idempotent. */
  unsubscribe(): void;
  /** Temporarily stop delivery without tearing down the subscription. */
  pause(): void;
  /** Resume a paused subscription. */
  resume(): void;
  readonly paused: boolean;
  readonly active: boolean;
}

export interface BackoffOptions {
  /** Delay before the first reconnect attempt. Default 500ms. */
  initialDelayMs?: number;
  /** Upper bound for the delay. Default 30_000ms. */
  maxDelayMs?: number;
  /** Growth factor per attempt. Default 2. */
  factor?: number;
  /** Random fraction of the delay added to avoid thundering herds. Default 0.2. */
  jitterRatio?: number;
  /** Give up after this many consecutive failures. Default 8. 0 = never give up. */
  maxAttempts?: number;
}

export interface EventStreamOptions {
  /** Override the WebSocket URL. Defaults to `wss(s)://<rpcUrl>/events`. */
  url?: string;
  /** Factory for the WebSocket implementation. Defaults to the global. */
  webSocketFactory?: (url: string) => WebSocketLike;
  /** Send periodic pings; the server answers with `{ type: 'pong' }`. */
  heartbeatIntervalMs?: number;
  /** Force a reconnect if no pong arrives within this window. */
  heartbeatTimeoutMs?: number;
  /** Reconnection backoff policy. */
  backoff?: BackoffOptions;
  /** Events retained for replay and dedup. Default 500. */
  historySize?: number;
}

/** Minimal WebSocket surface used by the stream. */
export interface WebSocketLike {
  readyState: number;
  send(data: string): void;
  close(code?: number, reason?: string): void;
  onopen: ((event: unknown) => void) | null;
  onclose: ((event: { code?: number; reason?: string }) => void) | null;
  onerror: ((event: unknown) => void) | null;
  onmessage: ((event: { data: unknown }) => void) | null;
}

export const WS_CONNECTING = 0;
export const WS_OPEN = 1;
export const WS_CLOSING = 2;
export const WS_CLOSED = 3;

export type StreamStatus =
  | 'idle'
  | 'connecting'
  | 'connected'
  | 'reconnecting'
  | 'closed'
  | 'failed';

export interface StreamMetrics {
  status: StreamStatus;
  connectedAt: number | null;
  reconnectAttempts: number;
  eventsReceived: number;
  eventsDelivered: number;
  handlerErrors: number;
  malformedMessages: number;
  duplicatesDropped: number;
  lastEventAt: number | null;
  subscribers: number;
}

type StatusListener = (status: StreamStatus, detail?: { attempt: number; delayMs: number; error?: Error }) => void;

// ── Helpers ───────────────────────────────────────────────────────────────────

const DEFAULT_HISTORY = 500;

/** Convert an RPC URL to its WebSocket equivalent. */
export function toWebSocketUrl(rpcUrl: string): string {
  const base = rpcUrl.replace(/^http/, 'ws').replace(/\/+$/, '');
  return `${base}/events`;
}

/**
 * Compute the delay before reconnect attempt `attempt` (1-based).
 *
 * Uses capped exponential growth plus proportional jitter so that many clients
 * reconnecting after an outage do not all retry at the same instant.
 */
export function computeBackoffDelay(
  attempt: number,
  options: BackoffOptions = {},
  random: () => number = Math.random,
): number {
  const {
    initialDelayMs = 500,
    maxDelayMs = 30_000,
    factor = 2,
    jitterRatio = 0.2,
  } = options;

  const exponential = initialDelayMs * factor ** Math.max(0, attempt - 1);
  const capped = Math.min(exponential, maxDelayMs);
  const jitter = capped * jitterRatio * random();
  return Math.round(capped + jitter);
}

/** Extract the Stellar address encoded in a `did:stellar:…` string. */
export function didToAddress(did: string): string | null {
  const match = /^did:stellar:([^:.]+)/.exec(did);
  return match ? match[1] : null;
}

/**
 * Decide whether `event` passes `filters`.
 *
 * All specified fields must match (AND semantics). A filter with no fields
 * matches everything, so a default subscription behaves as a wildcard.
 */
export function matchesFilters(event: IdentityEvent, filters: EventFilters = {}): boolean {
  if (filters.types && filters.types.length > 0 && !filters.types.includes(event.type)) {
    return false;
  }
  if (filters.address !== undefined && event.data?.address !== filters.address) {
    return false;
  }
  if (
    filters.credentialType !== undefined &&
    event.data?.credentialType !== filters.credentialType
  ) {
    return false;
  }
  if (
    filters.credentialId !== undefined &&
    event.data?.credentialId !== filters.credentialId
  ) {
    return false;
  }
  if (filters.contractAddress !== undefined && event.contractAddress !== filters.contractAddress) {
    return false;
  }
  if (filters.did !== undefined) {
    const eventDID = (event.data?.did ?? event.data?.address) as string | undefined;
    if (eventDID !== filters.did && eventDID !== didToAddress(filters.did)) {
      return false;
    }
  }
  if (filters.minScore !== undefined) {
    const score = event.data?.score as number | undefined;
    if (typeof score !== 'number' || score < filters.minScore) return false;
  }
  if (filters.maxScore !== undefined) {
    const score = event.data?.score as number | undefined;
    if (typeof score !== 'number' || score > filters.maxScore) return false;
  }
  if (filters.predicate && !filters.predicate(event)) {
    return false;
  }
  return true;
}

/** Validate and normalise an inbound frame into an `IdentityEvent`. */
export function parseEvent(raw: unknown): IdentityEvent | null {
  let value: unknown = raw;
  if (typeof raw === 'string') {
    try {
      value = JSON.parse(raw);
    } catch {
      return null;
    }
  }
  if (value === null || typeof value !== 'object') return null;

  const obj = value as Record<string, unknown>;

  // Control frames (pong, subscribe acknowledgements) are not events.
  if (typeof obj.type === 'string' && obj.type === 'pong') return null;

  if (typeof obj.type !== 'string') return null;
  if (!(IDENTITY_EVENT_TYPES as readonly string[]).includes(obj.type)) return null;
  if (typeof obj.timestamp !== 'number') return null;
  if (typeof obj.data !== 'object' || obj.data === null) return null;

  return {
    id: typeof obj.id === 'string' && obj.id.length > 0 ? obj.id : syntheticId(obj),
    type: obj.type as IdentityEventType,
    data: obj.data as Record<string, unknown>,
    timestamp: obj.timestamp,
    ...(typeof obj.ledger === 'number' ? { ledger: obj.ledger } : {}),
    ...(typeof obj.contractAddress === 'string' ? { contractAddress: obj.contractAddress } : {}),
  };
}

function syntheticId(obj: Record<string, unknown>): string {
  const ledger = typeof obj.ledger === 'number' ? obj.ledger : 'x';
  return `${obj.type}:${ledger}:${obj.timestamp}`;
}

// ── Stream ────────────────────────────────────────────────────────────────────

interface Subscriber {
  id: string;
  filters: EventFilters;
  handler: EventHandler;
  paused: boolean;
  active: boolean;
}

/**
 * A reconnecting WebSocket stream of identity events.
 *
 * The connection is shared by every subscription on a given instance, so
 * opening ten filtered subscriptions still costs a single socket.
 *
 * @example
 * ```ts
 * const stream = new EventStream(config);
 * const sub = stream.subscribeToEvents(
 *   { types: ['CredentialIssued'], address },
 *   event => console.log(event.data.credentialId),
 * );
 * stream.connect();
 * // later
 * sub.unsubscribe();
 * ```
 *
 * @category Client
 */
export class EventStream {
  private readonly url: string;
  private readonly logger = new Logger('EventStream');
  private readonly webSocketFactory: (url: string) => WebSocketLike;
  private readonly backoff: BackoffOptions;
  private readonly heartbeatIntervalMs: number;
  private readonly heartbeatTimeoutMs: number;
  private readonly historySize: number;

  private ws: WebSocketLike | null = null;
  private status: StreamStatus = 'idle';
  private reconnectAttempts = 0;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private heartbeatTimer: ReturnType<typeof setInterval> | null = null;
  private heartbeatTimeoutTimer: ReturnType<typeof setTimeout> | null = null;
  private shouldReconnect = false;

  private subscribers = new Map<string, Subscriber>();
  private subscriberCounter = 0;
  private history: IdentityEvent[] = [];
  private seenIds = new Set<string>();
  private statusListeners = new Set<StatusListener>();

  private metrics: Omit<StreamMetrics, 'status' | 'subscribers'> = {
    connectedAt: null,
    reconnectAttempts: 0,
    eventsReceived: 0,
    eventsDelivered: 0,
    handlerErrors: 0,
    malformedMessages: 0,
    duplicatesDropped: 0,
    lastEventAt: null,
  };

  constructor(config: StellarIdentityConfig, options: EventStreamOptions = {}) {
    this.url = options.url ?? toWebSocketUrl(config.rpcUrl ?? defaultRpcUrl(config.network));
    this.webSocketFactory =
      options.webSocketFactory ??
      ((target: string) => {
        const Ctor = (globalThis as { WebSocket?: new (url: string) => WebSocketLike }).WebSocket;
        if (!Ctor) {
          throw new Error('No global WebSocket available; pass options.webSocketFactory');
        }
        return new Ctor(target);
      });
    this.backoff = options.backoff ?? {};
    this.heartbeatIntervalMs = options.heartbeatIntervalMs ?? 20_000;
    this.heartbeatTimeoutMs = options.heartbeatTimeoutMs ?? 10_000;
    this.historySize = options.historySize ?? DEFAULT_HISTORY;
  }

  /**
   * Create a stream from a bare WebSocket URL, without an SDK config.
   *
   * Useful for front-ends that already know their endpoint and do not hold a
   * `StellarIdentityConfig`.
   */
  static fromUrl(url: string, options: EventStreamOptions = {}): EventStream {
    return new EventStream(
      { network: 'testnet', contracts: {} as StellarIdentityConfig['contracts'] },
      { ...options, url },
    );
  }

  // ── Subscription ──────────────────────────────────────────────────────────

  /**
   * Register a filtered event handler.
   *
   * The socket is opened lazily on the first subscription, so callers do not
   * have to sequence `subscribe` and `connect` themselves.
   *
   * @param filters - Declarative filter; omit for all events.
   * @param handler - Invoked for each matching event.
   * @param options - `replayHistory` immediately re-delivers recent events.
   */
  subscribeToEvents<T extends Record<string, unknown> = Record<string, unknown>>(
    filters: EventFilters,
    handler: EventHandler<T>,
    options: { replayHistory?: boolean } = {},
  ): EventSubscription {
    if (typeof handler !== 'function') {
      throw new TypeError('subscribeToEvents requires a handler function');
    }

    const id = `evt_${++this.subscriberCounter}`;
    const subscriber: Subscriber = {
      id,
      filters: filters ?? {},
      handler: handler as EventHandler,
      paused: false,
      active: true,
    };
    this.subscribers.set(id, subscriber);

    if (options.replayHistory) {
      for (const event of this.history) {
        this.deliver(subscriber, event);
      }
    }

    this.ensureConnected();

    const stream = this;
    return {
      id,
      unsubscribe: () => {
        subscriber.active = false;
        stream.subscribers.delete(id);
      },
      pause: () => {
        subscriber.paused = true;
      },
      resume: () => {
        subscriber.paused = false;
      },
      get paused() {
        return subscriber.paused;
      },
      get active() {
        return subscriber.active;
      },
    };
  }

  /**
   * Iterate matching events with `for await (const event of stream)`.
   *
   * The iterator buffers events that arrive between loop turns and completes
   * when the stream is closed with {@link close}.
   */
  async *events(
    filters: EventFilters = {},
  ): AsyncGenerator<IdentityEvent, void, undefined> {
    const buffer: IdentityEvent[] = [];
    let notify: (() => void) | null = null;
    let done = false;

    const subscription = this.subscribeToEvents(
      filters,
      event => {
        buffer.push(event);
        notify?.();
      },
    );

    // Wake the iterator only when the stream can no longer produce events.
    const onStatus: StatusListener = status => {
      if (status === 'closed' || status === 'failed') {
        done = true;
        notify?.();
      }
    };
    this.statusListeners.add(onStatus);

    try {
      for (;;) {
        if (buffer.length > 0) {
          yield buffer.shift()!;
          continue;
        }
        if (done) return;
        await new Promise<void>(resolve => {
          notify = resolve;
        });
        notify = null;
      }
    } finally {
      subscription.unsubscribe();
      this.statusListeners.delete(onStatus);
    }
  }

  // ── Connection lifecycle ──────────────────────────────────────────────────

  /** Open the socket if it is not already open or opening. */
  connect(): void {
    if (this.ws && (this.ws.readyState === WS_OPEN || this.ws.readyState === WS_CONNECTING)) {
      return;
    }
    this.shouldReconnect = true;
    this.openSocket();
  }

  /** Close the socket and stop reconnecting. */
  close(): void {
    this.shouldReconnect = false;
    this.clearTimers();
    this.closeSocket();
    this.setStatus('closed');
  }

  /** Alias for {@link close} that also drops all subscriptions. */
  disconnect(): void {
    this.close();
    this.subscribers.clear();
  }

  /** Current connection state. */
  getStatus(): StreamStatus {
    return this.status;
  }

  /** Whether the socket is currently open. */
  isConnected(): boolean {
    return this.ws?.readyState === WS_OPEN;
  }

  /** Observe status transitions. Returns an unsubscribe function. */
  onStatusChange(listener: StatusListener): () => void {
    this.statusListeners.add(listener);
    return () => this.statusListeners.delete(listener);
  }

  /** Snapshot of counters, safe to poll from a status UI. */
  getMetrics(): StreamMetrics {
    return {
      status: this.status,
      subscribers: this.subscribers.size,
      ...this.metrics,
    };
  }

  /** Events received so far, oldest first. */
  getHistory(limit?: number): IdentityEvent[] {
    return limit ? this.history.slice(-limit) : [...this.history];
  }

  // ── Private — socket ──────────────────────────────────────────────────────

  private ensureConnected(): void {
    if (this.shouldReconnect) return;
    this.connect();
  }

  private openSocket(): void {
    this.setStatus(this.reconnectAttempts > 0 ? 'reconnecting' : 'connecting');

    let socket: WebSocketLike;
    try {
      socket = this.webSocketFactory(this.url);
    } catch (err) {
      this.logger.error('Failed to create WebSocket', toError(err), { url: this.url });
      this.scheduleReconnect(toError(err));
      return;
    }

    this.ws = socket;

    socket.onopen = () => {
      this.reconnectAttempts = 0;
      this.metrics.reconnectAttempts = 0;
      this.metrics.connectedAt = Date.now();
      this.setStatus('connected');
      this.startHeartbeat();
      // Re-announce every active filter so the server can narrow the stream.
      this.sendSubscriptionFrames();
    };

    socket.onmessage = event => {
      this.handleMessage(event?.data);
    };

    socket.onerror = event => {
      this.logger.warn('WebSocket error', { url: this.url, event });
    };

    socket.onclose = event => {
      this.stopHeartbeat();
      this.ws = null;
      this.metrics.connectedAt = null;

      if (!this.shouldReconnect) {
        this.setStatus('closed');
        return;
      }
      this.scheduleReconnect(undefined, event?.reason);
    };
  }

  private scheduleReconnect(cause?: Error, reason?: string): void {
    if (!this.shouldReconnect) return;

    this.reconnectAttempts += 1;
    this.metrics.reconnectAttempts = this.reconnectAttempts;

    const { maxAttempts = 8 } = this.backoff;
    if (maxAttempts > 0 && this.reconnectAttempts > maxAttempts) {
      this.logger.error('Giving up after repeated reconnection failures', cause, {
        attempts: this.reconnectAttempts,
        reason,
      });
      this.shouldReconnect = false;
      this.setStatus('failed');
      return;
    }

    const delayMs = computeBackoffDelay(this.reconnectAttempts, this.backoff);
    this.setStatus('reconnecting', { attempt: this.reconnectAttempts, delayMs, ...(cause ? { error: cause } : {}) });

    this.clearReconnectTimer();
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.openSocket();
    }, delayMs);
  }

  private sendSubscriptionFrames(): void {
    if (!this.isConnected()) return;
    for (const subscriber of this.subscribers.values()) {
      try {
        this.ws!.send(JSON.stringify({ type: 'subscribe', filters: subscriber.filters }));
      } catch (err) {
        this.logger.warn('Failed to send subscribe frame', {
          subscriber: subscriber.id,
          error: toError(err).message,
        });
      }
    }
  }

  private handleMessage(raw: unknown): void {
    const event = parseEvent(raw);
    if (!event) {
      this.metrics.malformedMessages += 1;
      return;
    }

    this.metrics.eventsReceived += 1;
    this.metrics.lastEventAt = Date.now();

    if (this.seenIds.has(event.id)) {
      this.metrics.duplicatesDropped += 1;
      return;
    }
    this.seenIds.add(event.id);
    if (this.seenIds.size > this.historySize * 2) {
      const [oldest] = this.seenIds;
      this.seenIds.delete(oldest);
    }

    this.recordHistory(event);

    for (const subscriber of this.subscribers.values()) {
      this.deliver(subscriber, event);
    }
  }

  private deliver(subscriber: Subscriber, event: IdentityEvent): void {
    if (!subscriber.active || subscriber.paused) return;
    if (!matchesFilters(event, subscriber.filters)) return;

    try {
      subscriber.handler(event);
      this.metrics.eventsDelivered += 1;
    } catch (err) {
      // A throwing handler must not take down the socket or other subscribers.
      this.metrics.handlerErrors += 1;
      this.logger.error('Event handler threw', toError(err), { subscriber: subscriber.id });
    }
  }

  private recordHistory(event: IdentityEvent): void {
    this.history.push(event);
    if (this.history.length > this.historySize) {
      this.history.shift();
    }
  }

  // ── Private — heartbeat ───────────────────────────────────────────────────

  private startHeartbeat(): void {
    this.stopHeartbeat();
    this.heartbeatTimer = setInterval(() => {
      if (!this.isConnected()) return;
      try {
        this.ws!.send(JSON.stringify({ type: 'ping' }));
      } catch {
        /* the onerror/onclose handlers will take it from here */
        return;
      }
      this.heartbeatTimeoutTimer = setTimeout(() => {
        this.logger.warn('Heartbeat timed out; forcing reconnect');
        this.closeSocket();
        if (this.shouldReconnect) this.scheduleReconnect();
      }, this.heartbeatTimeoutMs);
    }, this.heartbeatIntervalMs);
  }

  private stopHeartbeat(): void {
    if (this.heartbeatTimer !== null) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
    if (this.heartbeatTimeoutTimer !== null) {
      clearTimeout(this.heartbeatTimeoutTimer);
      this.heartbeatTimeoutTimer = null;
    }
  }

  private closeSocket(): void {
    if (!this.ws) return;
    try {
      this.ws.onopen = null;
      this.ws.onclose = null;
      this.ws.onerror = null;
      this.ws.onmessage = null;
      this.ws.close();
    } catch {
      /* nothing useful to do */
    }
    this.ws = null;
  }

  private clearReconnectTimer(): void {
    if (this.reconnectTimer !== null) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
  }

  private clearTimers(): void {
    this.clearReconnectTimer();
    this.stopHeartbeat();
  }

  // ── Private — status ──────────────────────────────────────────────────────

  private setStatus(
    status: StreamStatus,
    detail?: { attempt: number; delayMs: number; error?: Error },
  ): void {
    if (this.status === status && !detail) return;
    this.status = status;
    for (const listener of this.statusListeners) {
      try {
        listener(status, detail);
      } catch {
        /* a status listener must not break the stream */
      }
    }
  }
}

function toError(value: unknown): Error {
  return value instanceof Error ? value : new Error(String(value));
}

function defaultRpcUrl(network: string): string {
  switch (network) {
    case 'mainnet':
      return 'https://soroban-rpc.stellar.org';
    case 'futurenet':
      return 'https://rpc-futurenet.stellar.org';
    default:
      return 'https://soroban-testnet.stellar.org';
  }
}
