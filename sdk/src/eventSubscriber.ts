import { StellarIdentityConfig } from './types';

// ── Constants ─────────────────────────────────────────────────────────────────

const DEFAULT_RECONNECT_DELAY_MS = 1_000;
const MAX_RECONNECT_DELAY_MS = 30_000;
const DEFAULT_BATCH_INTERVAL_MS = 1_000;
const DEFAULT_ONCE_TIMEOUT_MS = 30_000;
const MAX_QUEUE_SIZE = 1_000;
const MAX_EVENT_HISTORY = 500;
const HEARTBEAT_INTERVAL_MS = 20_000;
const HEARTBEAT_TIMEOUT_MS = 10_000;
const MAX_SUBSCRIPTIONS = 200;

const RPC_URLS: Record<string, string> = {
  mainnet: 'https://soroban-rpc.stellar.org',
  futurenet: 'https://rpc-futurenet.stellar.org',
  testnet: 'https://soroban-testnet.stellar.org',
};

// ── Event types ───────────────────────────────────────────────────────────────

export type EventType =
  | 'DIDCreated'
  | 'DIDUpdated'
  | 'DIDDeactivated'
  | 'CredentialIssued'
  | 'CredentialRevoked'
  | 'ReputationScoreUpdated'
  | 'ProofVerified'
  | 'AddressSanctioned'
  | 'AddressDesanctioned';

const ALL_EVENT_TYPES = new Set<EventType>([
  'DIDCreated',
  'DIDUpdated',
  'DIDDeactivated',
  'CredentialIssued',
  'CredentialRevoked',
  'ReputationScoreUpdated',
  'ProofVerified',
  'AddressSanctioned',
  'AddressDesanctioned',
]);

// ── Connection state ──────────────────────────────────────────────────────────

export type ConnectionState =
  | 'disconnected'
  | 'connecting'
  | 'connected'
  | 'reconnecting'
  | 'paused';

// ── Interfaces ────────────────────────────────────────────────────────────────

export interface EventFilter {
  /** Match events whose `data.address` equals this value. */
  address?: string;
  /** Match events whose `data.credentialType` equals this value. */
  credentialType?: string;
  /** Match events whose `data.score` is at or above this value. */
  minScore?: number;
  /** Match events whose `data.score` is at or below this value. */
  maxScore?: number;
  /** Custom predicate for advanced filtering. */
  predicate?: (event: SDKEvent) => boolean;
}

export interface SDKEvent {
  type: EventType;
  data: Record<string, unknown>;
  timestamp: number;
  /** Unique event ID assigned by the server (used for deduplication). */
  eventId?: string;
}

export interface SubscribeOptions {
  /** Deliver events in batches of this size. */
  batchSize?: number;
  /** Flush the batch at this interval even if `batchSize` is not reached. */
  batchIntervalMs?: number;
  /** Maximum number of events to hold in the queue before dropping oldest. */
  maxQueueSize?: number;
  /** If true, immediately replay recent historical events on subscribe. */
  replayHistory?: boolean;
}

export interface EventSubscriberMetrics {
  totalReceived: number;
  totalDispatched: number;
  totalDropped: number;
  totalErrors: number;
  reconnectCount: number;
  activeSubscriptions: number;
  connectionState: ConnectionState;
  lastEventAt: number | null;
}

export interface ConnectionEventMap {
  connected: () => void;
  disconnected: (reason: string) => void;
  reconnecting: (attempt: number, delayMs: number) => void;
  error: (error: Error) => void;
  paused: () => void;
  resumed: () => void;
}

type ConnectionEventType = keyof ConnectionEventMap;

// ── Internal types ────────────────────────────────────────────────────────────

export interface Subscription {
  id: string;
  eventType: EventType | '*';
  filter?: EventFilter;
  callback: (event: SDKEvent) => void;
  batchSize?: number;
  batchIntervalMs?: number;
  maxQueueSize?: number;
  createdAt: number;
  /** Number of events successfully delivered to this subscription. */
  deliveredCount: number;
  /** Number of events dropped due to queue overflow for this subscription. */
  droppedCount: number;
  paused: boolean;
}

// ── EventSubscriber ───────────────────────────────────────────────────────────

/**
 * Real-time event subscription client for the Stellar Identity SDK.
 *
 * Maintains a WebSocket connection with automatic reconnection, exponential
 * back-off, heartbeat monitoring, wildcard subscriptions, batched delivery,
 * deduplication, event history replay, and connection lifecycle events.
 *
 * @example
 * ```ts
 * const sub = new EventSubscriber(config);
 * sub.on('connected', () => console.log('live'));
 * sub.connect();
 *
 * const id = sub.subscribe('DIDCreated', undefined, e => console.log(e));
 * sub.unsubscribe(id);
 * sub.disconnect();
 * ```
 */
export class EventSubscriber {
  // ── State ─────────────────────────────────────────────────────────────────

  private readonly rpcUrl: string;
  private subscriptions = new Map<string, Subscription>();
  private subscriptionCounter = 0;
  private connectionState: ConnectionState = 'disconnected';

  // ── WebSocket ─────────────────────────────────────────────────────────────

  private ws: WebSocket | null = null;
  private reconnectAttempts = 0;
  private reconnectDelayMs = DEFAULT_RECONNECT_DELAY_MS;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private shouldReconnect = false;

  // ── Heartbeat ─────────────────────────────────────────────────────────────

  private heartbeatTimer: ReturnType<typeof setInterval> | null = null;
  private heartbeatTimeoutTimer: ReturnType<typeof setTimeout> | null = null;

  // ── Batching ──────────────────────────────────────────────────────────────

  private eventQueue = new Map<string, SDKEvent[]>();
  private batchTimers = new Map<string, ReturnType<typeof setInterval>>();

  // ── History & deduplication ───────────────────────────────────────────────

  private eventHistory: SDKEvent[] = [];
  private seenEventIds = new Set<string>();

  // ── Metrics ───────────────────────────────────────────────────────────────

  private metrics: Omit<EventSubscriberMetrics, 'activeSubscriptions' | 'connectionState'> = {
    totalReceived: 0,
    totalDispatched: 0,
    totalDropped: 0,
    totalErrors: 0,
    reconnectCount: 0,
    lastEventAt: null,
  };

  // ── Connection lifecycle callbacks ────────────────────────────────────────

  private connectionListeners = new Map<
    ConnectionEventType,
    Array<(...args: unknown[]) => void>
  >();

  // ── Constructor ───────────────────────────────────────────────────────────

  constructor(config: StellarIdentityConfig) {
    this.rpcUrl = config.rpcUrl ?? RPC_URLS[config.network] ?? RPC_URLS.testnet;
  }

  // ── Subscription API ──────────────────────────────────────────────────────

  /**
   * Subscribe to a specific event type (or `'*'` for all types).
   *
   * @param eventType - The event type to listen for, or `'*'` for wildcard.
   * @param filter - Optional field-level or predicate filter.
   * @param callback - Called for each matching event.
   * @param options - Batching and queue configuration.
   * @returns A subscription ID that can be passed to `unsubscribe`.
   */
  subscribe(
    eventType: EventType | '*',
    filter: EventFilter | undefined,
    callback: (event: SDKEvent) => void,
    options?: SubscribeOptions,
  ): string {
    if (eventType !== '*' && !ALL_EVENT_TYPES.has(eventType as EventType)) {
      throw new Error(`Unsupported event type: ${eventType}`);
    }
    if (this.subscriptions.size >= MAX_SUBSCRIPTIONS) {
      throw new Error(`Subscription limit reached (max ${MAX_SUBSCRIPTIONS})`);
    }

    const id = `sub_${++this.subscriptionCounter}_${Date.now()}`;
    const subscription: Subscription = {
      id,
      eventType,
      filter,
      callback,
      batchSize: options?.batchSize,
      batchIntervalMs: options?.batchIntervalMs,
      maxQueueSize: options?.maxQueueSize ?? MAX_QUEUE_SIZE,
      createdAt: Date.now(),
      deliveredCount: 0,
      droppedCount: 0,
      paused: false,
    };

    this.subscriptions.set(id, subscription);

    if (options?.batchSize || options?.batchIntervalMs) {
      this.setupBatching(
        id,
        options.batchIntervalMs ?? DEFAULT_BATCH_INTERVAL_MS,
      );
    }

    if (options?.replayHistory) {
      this.replayHistory(subscription);
    }

    return id;
  }

  /**
   * Cancel a subscription and clean up all associated timers and queues.
   */
  unsubscribe(subscriptionId: string): void {
    // Flush any pending batched events before removal.
    this.flushQueue(subscriptionId);
    this.subscriptions.delete(subscriptionId);
    this.eventQueue.delete(subscriptionId);

    const timer = this.batchTimers.get(subscriptionId);
    if (timer !== undefined) {
      clearInterval(timer);
      this.batchTimers.delete(subscriptionId);
    }
  }

  /**
   * Unsubscribe all active subscriptions at once.
   */
  unsubscribeAll(): void {
    for (const id of [...this.subscriptions.keys()]) {
      this.unsubscribe(id);
    }
  }

  /**
   * Wait for the next matching event and resolve with it.
   * Rejects with a timeout error if no event arrives within `timeoutMs`.
   *
   * @param eventType - The event type to wait for.
   * @param filter - Optional filter.
   * @param timeoutMs - Milliseconds before the promise rejects. Default 30 s.
   */
  once(
    eventType: EventType,
    filter?: EventFilter,
    timeoutMs = DEFAULT_ONCE_TIMEOUT_MS,
  ): Promise<SDKEvent> {
    return new Promise<SDKEvent>((resolve, reject) => {
      let timer: ReturnType<typeof setTimeout> | null = null;
      let resolved = false;

      const id = this.subscribe(eventType, filter, event => {
        if (resolved) return;
        resolved = true;
        if (timer !== null) clearTimeout(timer);
        this.unsubscribe(id);
        resolve(event);
      });

      timer = setTimeout(() => {
        if (resolved) return;
        resolved = true;
        this.unsubscribe(id);
        reject(
          new Error(
            `once('${eventType}') timed out after ${timeoutMs} ms`,
          ),
        );
      }, timeoutMs);
    });
  }

  /**
   * Pause event delivery to a subscription without removing it.
   * Events that arrive while paused are silently dropped (not queued).
   */
  pause(subscriptionId: string): void {
    const sub = this.subscriptions.get(subscriptionId);
    if (sub) sub.paused = true;
  }

  /**
   * Resume delivery to a previously paused subscription.
   */
  resume(subscriptionId: string): void {
    const sub = this.subscriptions.get(subscriptionId);
    if (sub) sub.paused = false;
  }

  /**
   * Return the per-subscription delivery statistics.
   */
  subscriptionStats(
    subscriptionId: string,
  ): { delivered: number; dropped: number; queued: number } | null {
    const sub = this.subscriptions.get(subscriptionId);
    if (!sub) return null;
    return {
      delivered: sub.deliveredCount,
      dropped: sub.droppedCount,
      queued: this.eventQueue.get(subscriptionId)?.length ?? 0,
    };
  }

  // ── Connection API ────────────────────────────────────────────────────────

  /**
   * Open the WebSocket connection and enable automatic reconnection.
   */
  connect(): void {
    this.shouldReconnect = true;
    this.reconnectAttempts = 0;
    this.reconnectDelayMs = DEFAULT_RECONNECT_DELAY_MS;
    this.setConnectionState('connecting');
    this.connectInternal();
  }

  /**
   * Close the connection and disable automatic reconnection.
   */
  disconnect(): void {
    this.shouldReconnect = false;
    this.clearReconnectTimer();
    this.stopHeartbeat();
    this.closeSocket();
    this.setConnectionState('disconnected');
    this.stopAllBatchTimers();
    this.emit('disconnected', 'client requested disconnect');
  }

  /**
   * Pause all event delivery without closing the connection.
   * Events received while paused are still tracked in subscription queues
   * if batching is enabled.
   */
  pauseAll(): void {
    for (const sub of this.subscriptions.values()) {
      sub.paused = true;
    }
    this.setConnectionState('paused');
    this.emit('paused');
  }

  /**
   * Resume all previously paused subscriptions.
   */
  resumeAll(): void {
    for (const sub of this.subscriptions.values()) {
      sub.paused = false;
    }
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.setConnectionState('connected');
    }
    this.emit('resumed');
  }

  // ── Connection lifecycle events ───────────────────────────────────────────

  /**
   * Register a listener for connection lifecycle events.
   *
   * @example
   * ```ts
   * sub.on('connected', () => console.log('connected'));
   * sub.on('error', err => console.error(err));
   * ```
   */
  on<K extends ConnectionEventType>(
    event: K,
    listener: ConnectionEventMap[K],
  ): this {
    if (!this.connectionListeners.has(event)) {
      this.connectionListeners.set(event, []);
    }
    this.connectionListeners.get(event)!.push(
      listener as (...args: unknown[]) => void,
    );
    return this;
  }

  /**
   * Remove a previously registered lifecycle listener.
   */
  off<K extends ConnectionEventType>(
    event: K,
    listener: ConnectionEventMap[K],
  ): this {
    const listeners = this.connectionListeners.get(event);
    if (listeners) {
      const idx = listeners.indexOf(listener as (...args: unknown[]) => void);
      if (idx !== -1) listeners.splice(idx, 1);
    }
    return this;
  }

  // ── Query API ─────────────────────────────────────────────────────────────

  /**
   * Return a snapshot of current SDK-level metrics.
   */
  getMetrics(): EventSubscriberMetrics {
    return {
      ...this.metrics,
      activeSubscriptions: this.subscriptions.size,
      connectionState: this.connectionState,
    };
  }

  /**
   * Return a copy of the recent event history buffer.
   * The buffer holds up to `MAX_EVENT_HISTORY` events in order of receipt.
   */
  getEventHistory(
    eventType?: EventType,
    limit = MAX_EVENT_HISTORY,
  ): SDKEvent[] {
    const source = eventType
      ? this.eventHistory.filter(e => e.type === eventType)
      : this.eventHistory;
    return source.slice(-limit);
  }

  /** Whether the WebSocket is currently open and ready. */
  get isConnected(): boolean {
    return this.connectionState === 'connected';
  }

  /** Number of active subscriptions. */
  get subscriptionCount(): number {
    return this.subscriptions.size;
  }

  // ── Private — WebSocket management ───────────────────────────────────────

  private connectInternal(): void {
    this.closeSocket();

    try {
      const url = this.buildWsUrl();
      this.ws = new WebSocket(url);

      this.ws.onopen = () => {
        this.setConnectionState('connected');
        this.reconnectAttempts = 0;
        this.reconnectDelayMs = DEFAULT_RECONNECT_DELAY_MS;
        this.startHeartbeat();
        this.emit('connected');
      };

      this.ws.onmessage = (msg: MessageEvent) => {
        this.handleMessage(msg.data);
      };

      this.ws.onclose = (e: CloseEvent) => {
        this.stopHeartbeat();
        if (this.connectionState !== 'disconnected') {
          this.setConnectionState('reconnecting');
          this.emit('disconnected', e.reason || 'connection closed');
        }
        if (this.shouldReconnect) {
          this.scheduleReconnect();
        }
      };

      this.ws.onerror = () => {
        const err = new Error('WebSocket error');
        this.metrics.totalErrors++;
        this.emit('error', err);
      };
    } catch (error) {
      this.metrics.totalErrors++;
      this.emit('error', error instanceof Error ? error : new Error(String(error)));
      if (this.shouldReconnect) {
        this.scheduleReconnect();
      }
    }
  }

  private scheduleReconnect(): void {
    this.clearReconnectTimer();

    const delay = Math.min(
      DEFAULT_RECONNECT_DELAY_MS * 2 ** this.reconnectAttempts,
      MAX_RECONNECT_DELAY_MS,
    );

    this.reconnectTimer = setTimeout(() => {
      this.reconnectAttempts++;
      this.metrics.reconnectCount++;
      this.emit('reconnecting', this.reconnectAttempts, delay);
      this.connectInternal();
    }, delay);
  }

  private closeSocket(): void {
    if (this.ws) {
      try { this.ws.close(); } catch { /* intentional */ }
      this.ws = null;
    }
  }

  private buildWsUrl(): string {
    return this.rpcUrl.replace(/^https?/, match =>
      match === 'https' ? 'wss' : 'ws',
    ) + '/events';
  }

  // ── Private — heartbeat ───────────────────────────────────────────────────

  private startHeartbeat(): void {
    this.stopHeartbeat();
    this.heartbeatTimer = setInterval(() => {
      if (this.ws?.readyState === WebSocket.OPEN) {
        this.ws.send(JSON.stringify({ type: 'ping' }));
        this.heartbeatTimeoutTimer = setTimeout(() => {
          // No pong received — force reconnect.
          this.closeSocket();
          if (this.shouldReconnect) this.scheduleReconnect();
        }, HEARTBEAT_TIMEOUT_MS);
      }
    }, HEARTBEAT_INTERVAL_MS);
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

  // ── Private — message handling ────────────────────────────────────────────

  private handleMessage(raw: unknown): void {
    let parsed: unknown;
    try {
      parsed = typeof raw === 'string' ? JSON.parse(raw) : raw;
    } catch {
      this.metrics.totalErrors++;
      return;
    }

    // Handle pong heartbeat response.
    if (
      parsed !== null &&
      typeof parsed === 'object' &&
      (parsed as Record<string, unknown>).type === 'pong'
    ) {
      if (this.heartbeatTimeoutTimer !== null) {
        clearTimeout(this.heartbeatTimeoutTimer);
        this.heartbeatTimeoutTimer = null;
      }
      return;
    }

    const event = this.validateEvent(parsed);
    if (!event) {
      this.metrics.totalErrors++;
      return;
    }

    // Deduplication: skip events we've already processed.
    if (event.eventId && this.seenEventIds.has(event.eventId)) {
      return;
    }
    if (event.eventId) {
      this.seenEventIds.add(event.eventId);
      // Prevent unbounded growth of the deduplication set.
      if (this.seenEventIds.size > MAX_EVENT_HISTORY * 2) {
        const [oldest] = this.seenEventIds;
        this.seenEventIds.delete(oldest);
      }
    }

    this.metrics.totalReceived++;
    this.metrics.lastEventAt = Date.now();
    this.recordHistory(event);
    this.dispatchEvent(event);
  }

  private validateEvent(raw: unknown): SDKEvent | null {
    if (raw === null || typeof raw !== 'object') return null;
    const obj = raw as Record<string, unknown>;
    if (!ALL_EVENT_TYPES.has(obj.type as EventType)) return null;
    if (typeof obj.timestamp !== 'number') return null;
    if (typeof obj.data !== 'object' || obj.data === null) return null;
    return obj as unknown as SDKEvent;
  }

  private dispatchEvent(event: SDKEvent): void {
    for (const sub of this.subscriptions.values()) {
      if (sub.paused) continue;
      if (sub.eventType !== '*' && sub.eventType !== event.type) continue;
      if (sub.filter && !this.matchesFilter(event, sub.filter)) continue;

      if (sub.batchSize || sub.batchIntervalMs) {
        this.enqueueEvent(sub, event);
      } else {
        this.deliverSafely(sub, event);
      }
    }
  }

  private deliverSafely(sub: Subscription, event: SDKEvent): void {
    try {
      sub.callback(event);
      sub.deliveredCount++;
      this.metrics.totalDispatched++;
    } catch (err) {
      sub.droppedCount++;
      this.metrics.totalErrors++;
      this.emit(
        'error',
        new Error(
          `Callback error in subscription ${sub.id}: ${
            err instanceof Error ? err.message : String(err)
          }`,
        ),
      );
    }
  }

  // ── Private — filtering ───────────────────────────────────────────────────

  private matchesFilter(event: SDKEvent, filter: EventFilter): boolean {
    if (filter.address !== undefined && event.data.address !== filter.address) {
      return false;
    }
    if (
      filter.credentialType !== undefined &&
      event.data.credentialType !== filter.credentialType
    ) {
      return false;
    }
    if (filter.minScore !== undefined) {
      const score = event.data.score as number | undefined;
      if (score === undefined || score < filter.minScore) return false;
    }
    if (filter.maxScore !== undefined) {
      const score = event.data.score as number | undefined;
      if (score === undefined || score > filter.maxScore) return false;
    }
    if (filter.predicate && !filter.predicate(event)) {
      return false;
    }
    return true;
  }

  // ── Private — batching ────────────────────────────────────────────────────

  private enqueueEvent(sub: Subscription, event: SDKEvent): void {
    if (!this.eventQueue.has(sub.id)) {
      this.eventQueue.set(sub.id, []);
    }
    const queue = this.eventQueue.get(sub.id)!;
    const maxQueue = sub.maxQueueSize ?? MAX_QUEUE_SIZE;

    if (queue.length >= maxQueue) {
      // Drop the oldest event to make room (bounded queue).
      queue.shift();
      sub.droppedCount++;
      this.metrics.totalDropped++;
    }

    queue.push(event);

    // Immediate flush if batch size reached.
    if (sub.batchSize && queue.length >= sub.batchSize) {
      this.flushQueue(sub.id);
    }
  }

  private setupBatching(subscriptionId: string, intervalMs: number): void {
    const timer = setInterval(() => {
      this.flushQueue(subscriptionId);
    }, intervalMs);
    this.batchTimers.set(subscriptionId, timer);
  }

  private flushQueue(subscriptionId: string): void {
    const queue = this.eventQueue.get(subscriptionId);
    if (!queue || queue.length === 0) return;

    const sub = this.subscriptions.get(subscriptionId);
    if (!sub) return;

    const batch = queue.splice(0, sub.batchSize ?? queue.length);
    for (const event of batch) {
      this.deliverSafely(sub, event);
    }
  }

  private stopAllBatchTimers(): void {
    for (const timer of this.batchTimers.values()) {
      clearInterval(timer);
    }
    this.batchTimers.clear();
  }

  // ── Private — history ─────────────────────────────────────────────────────

  private recordHistory(event: SDKEvent): void {
    this.eventHistory.push(event);
    if (this.eventHistory.length > MAX_EVENT_HISTORY) {
      this.eventHistory.shift();
    }
  }

  private replayHistory(sub: Subscription): void {
    const relevant = this.eventHistory.filter(e => {
      if (sub.eventType !== '*' && sub.eventType !== e.type) return false;
      if (sub.filter && !this.matchesFilter(e, sub.filter)) return false;
      return true;
    });
    for (const event of relevant) {
      this.deliverSafely(sub, event);
    }
  }

  // ── Private — connection state ────────────────────────────────────────────

  private setConnectionState(state: ConnectionState): void {
    this.connectionState = state;
  }

  private clearReconnectTimer(): void {
    if (this.reconnectTimer !== null) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
  }

  // ── Private — lifecycle event emitter ─────────────────────────────────────

  private emit<K extends ConnectionEventType>(
    event: K,
    ...args: Parameters<ConnectionEventMap[K]>
  ): void {
    const listeners = this.connectionListeners.get(event);
    if (!listeners) return;
    for (const listener of listeners) {
      try {
        (listener as (...a: unknown[]) => void)(...(args as unknown[]));
      } catch { /* prevent listener errors from crashing the subscriber */ }
    }
  }
}

export type { EventType, Subscription, EventFilter, SDKEvent };
