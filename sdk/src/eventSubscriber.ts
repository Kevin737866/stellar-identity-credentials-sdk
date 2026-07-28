/**
 * eventSubscriber.ts
 *
 * The EventSubscriber lets applications subscribe to and react to on-chain
 * events emitted by the Stellar Identity contracts. Events are delivered to
 * registered handlers from two interchangeable transports:
 *
 *   - WebSocket  primary, automatic reconnect with exponential backoff,
 *                shared with the existing implementation.
 *   - Polling    opt-in fallback that hits SorobanRpc.getEvents on a
 *                configurable interval, sharing the same dispatch path so a
 *                subscription behaves identically regardless of transport.
 *
 * Issue #290 additions (subscribeToDIDEvents, subscribeToCredentialEvents,
 * subscribeToContractEvents, enablePolling, polling fallback) live alongside
 * the existing subscribe/unsubscribe/once surface so existing call sites
 * continue to work unchanged.
 */

import { SorobanRpc } from 'stellar-sdk';
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
const DEFAULT_POLL_INTERVAL_MS = 5_000;

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

/** Event types related to a DID lifecycle (Issue #290). */
const DID_RELATED_EVENTS: EventType[] = [
  'DIDCreated',
  'CredentialIssued',
  'CredentialRevoked',
  'ReputationScoreUpdated',
  'AddressSanctioned',
];

/** Event types related to a credential lifecycle (Issue #290). */
const CREDENTIAL_RELATED_EVENTS: EventType[] = [
  'CredentialIssued',
  'CredentialRevoked',
  'ProofVerified',
];

// ── Connection state ──────────────────────────────────────────────────────────

export type ConnectionState =
  | 'disconnected'
  | 'connecting'
  | 'connected'
  | 'reconnecting'
  | 'paused';

// ── Interfaces ────────────────────────────────────────────────────────────────

/** A single on-chain event delivered to subscribers (Issue #290 extended). */
export interface ContractEvent {
  type: EventType;
  data: Record<string, unknown>;
  timestamp: number;
  /** Originating contract address, when known (polling transport). */
  contractAddress?: string;
  /** Ledger sequence the event was observed on, when known. */
  ledger?: number;
  /** Unique event ID assigned by the server (used for deduplication). */
  eventId?: string;
}

/** Backwards-compatible SDK event interface. */
export interface SDKEvent {
  type: EventType;
  data: Record<string, unknown>;
  timestamp: number;
  /** Unique event ID assigned by the server (used for deduplication). */
  eventId?: string;
}

/** Event handler signature. */
export type ContractEventHandler = (event: ContractEvent) => void;

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
  /** Filter to events emitted by a specific contract (Issue #290). */
  contractAddress?: string;
  /** Filter by credential ID (Issue #290). */
  credentialId?: string;
  /** Filter by DID (Issue #290). */
  did?: string;
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

export interface PollingOptions {
  /** Master switch. When false (default) the transport is WebSocket only. */
  enabled: boolean;
  /** Poll interval in ms. Defaults to 5000 when omitted. */
  intervalMs?: number;
  /** Ledger sequence to start polling from. Defaults to 'now'. */
  startLedger?: number;
  /** Specific contract ids to narrow the getEvents RPC. */
  contractIds?: string[];
  /** Specific event topics to filter on. */
  topics?: string[][];
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
  /** Issue #290: marker for synthetic contract-address subscriptions so
   *  unsubscribe(contract:<addr>) evicts only those this call created. */
  _contractOwner?: string;
}

// ── EventSubscriber ───────────────────────────────────────────────────────────

/**
 * Real-time event subscription client for the Stellar Identity SDK.
 *
 * Maintains a WebSocket connection with automatic reconnection, exponential
 * back-off, heartbeat monitoring, wildcard subscriptions, batched delivery,
 * deduplication, event history replay, and connection lifecycle events.
 *
 * Issue #290 additions provide polling fallback, DID/credential/contract
 * subscription helpers, and an `on()` alias for convenience.
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
  private shouldReconnect = false;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;

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

  // ── Polling state (Issue #290) ────────────────────────────────────────────

  private pollingOptions: PollingOptions | null = null;
  private pollingTimer: ReturnType<typeof setInterval> | null = null;
  private lastPolledLedger: number | null = null;
  /** Lazily constructed so unit tests do not need a real Soroban RPC URL. */
  private _rpc?: SorobanRpc.Server;
  private get rpc(): SorobanRpc.Server {
    if (!this._rpc) this._rpc = new SorobanRpc.Server(this.rpcUrl);
    return this._rpc;
  }

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
   * Alias for {@link subscribe} with no batching.
   * Provided so callers that want EventEmitter-style synchronous delivery
   * (one callback per event) do not have to pass options.
   *
   * Note: this overload is for event subscription. For connection lifecycle
   * events use `on('connected' | 'disconnected' | ...)`.
   */
  on(
    eventType: EventType,
    filter: EventFilter | undefined,
    callback: ContractEventHandler,
  ): string;

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
  ): this;

  // Implementation — supports both event subscription and lifecycle registration
  on(
    eventOrType: EventType | ConnectionEventType,
    filterOrListener: EventFilter | undefined | ((...args: unknown[]) => void),
    callback?: ContractEventHandler,
  ): string | this {
    // Route to lifecycle listener registration when the first argument
    // is a known lifecycle event name.
    const lifecycleEvents: ConnectionEventType[] = [
      'connected',
      'disconnected',
      'reconnecting',
      'error',
      'paused',
      'resumed',
    ];
    if (lifecycleEvents.includes(eventOrType as ConnectionEventType)) {
      const event = eventOrType as ConnectionEventType;
      if (!this.connectionListeners.has(event)) {
        this.connectionListeners.set(event, []);
      }
      this.connectionListeners.get(event)!.push(
        filterOrListener as (...args: unknown[]) => void,
      );
      return this;
    }
    // Otherwise treat it as an event-type subscription.
    return this.subscribe(
      eventOrType as EventType,
      filterOrListener as EventFilter | undefined,
      callback as ContractEventHandler,
    );
  }

  /**
   * Subscribe to every event related to a DID across all DID-related event
   * types. Returns the list of subscription ids so callers can bulk-unsubscribe.
   */
  subscribeToDIDEvents(did: string, callback: ContractEventHandler): string[] {
    if (!did) throw new Error('did must be non-empty');
    return DID_RELATED_EVENTS.map(eventType =>
      this.subscribe(eventType, { did, address: didToAddress(did) }, callback),
    );
  }

  /**
   * Subscribe to all events concerning a specific verifiable credential.
   */
  subscribeToCredentialEvents(
    credentialId: string,
    callback: ContractEventHandler,
  ): string[] {
    if (!credentialId) throw new Error('credentialId must be non-empty');
    return CREDENTIAL_RELATED_EVENTS.map(eventType =>
      this.subscribe(eventType, { credentialId }, callback),
    );
  }

  /**
   * Subscribe to every event emitted by a specific contract address.
   * Returns a `contract:<addr>` handle; pass it to `unsubscribe` to tear
   * down all subscriptions created by this call atomically.
   */
  subscribeToContractEvents(
    contractAddress: string,
    callback: ContractEventHandler,
  ): string {
    if (!contractAddress) throw new Error('contractAddress must be non-empty');
    // Dedupe the union of credential- and DID-related event types so a
    // single event cannot fire the user callback twice.
    const targets = Array.from(
      new Set<EventType>([...CREDENTIAL_RELATED_EVENTS, ...DID_RELATED_EVENTS]),
    );
    for (const eventType of targets) {
      const id = this.subscribe(eventType, { contractAddress }, callback);
      // Tag the subscription so unsubscribe(contract:<addr>) can evict
      // only synthetic subscribers owned by this call.
      const sub = this.subscriptions.get(id);
      if (sub) sub._contractOwner = contractAddress;
    }
    return `contract:${contractAddress}`;
  }

  /**
   * Cancel a subscription and clean up all associated timers and queues.
   *
   * Supports the special `contract:<addr>` handle to bulk-unsubscribe
   * all subscriptions created by `subscribeToContractEvents`.
   */
  unsubscribe(subscriptionId: string): void {
    if (subscriptionId.startsWith('contract:')) {
      // Evict only synthetic subscriptions tagged with the matching
      // _contractOwner, not any subscription with the same contractAddress.
      const target = subscriptionId.slice('contract:'.length);
      for (const [id, sub] of Array.from(this.subscriptions.entries())) {
        if (sub._contractOwner === target) {
          this.flushQueue(id);
          this.subscriptions.delete(id);
          this.eventQueue.delete(id);
          const timer = this.batchTimers.get(id);
          if (timer) {
            clearInterval(timer);
            this.batchTimers.delete(id);
          }
        }
      }
      return;
    }

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
    if (this.pollingOptions?.enabled) this.startPollingInternal();
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
    this.stopPollingInternal();
    this.emit('disconnected', 'client requested disconnect');
  }

  /**
   * Pause all event delivery without closing the connection.
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

  // ── Lifecycle listener removal ────────────────────────────────────────────

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

  // ── Polling transport (Issue #290) ────────────────────────────────────────

  /**
   * Configure polling-based event delivery (Issue #290). When `enabled`
   * is true, a setInterval loop hits `rpc.getEvents` and dispatches any
   * matching events through the same path used by the WebSocket transport.
   */
  enablePolling(options: PollingOptions): void {
    this.pollingOptions = options;
    if (options.enabled) {
      this.startPollingInternal();
    } else {
      this.stopPollingInternal();
    }
  }

  /** Returns true when polling-backed delivery is currently active. */
  isPolling(): boolean {
    return this.pollingTimer !== null;
  }

  /** Single polling tick. Exposed for tests; safe to await. */
  async pollOnce(): Promise<void> {
    if (!this.pollingOptions) return;
    try {
      const startLedger = this.lastPolledLedger ?? undefined;
      const response = await this.rpc.getEvents({
        startLedger,
        filters: this.pollingOptions.contractIds?.map(id => ({
          contractIds: [id],
        })),
        topics: this.pollingOptions.topics,
      } as Parameters<SorobanRpc.Server['getEvents']>[0]);
      const events = response?.events ?? [];
      for (const evt of events) {
        const normalised = this.normalisePolledEvent(evt);
        this.dispatchEvent(normalised);
      }
      if (typeof response?.latestLedger === 'number') {
        this.lastPolledLedger = response.latestLedger;
      }
    } catch {
      // Polling failure is non-fatal — logs could be added here.
    }
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

  // ── Private — WebSocket management ────────────────────────────────────────

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
      this.emit(
        'error',
        error instanceof Error ? error : new Error(String(error)),
      );
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
      try {
        this.ws.close();
      } catch {
        /* intentional */
      }
      this.ws = null;
    }
  }

  private buildWsUrl(): string {
    return (
      this.rpcUrl.replace(/^https?/, match =>
        match === 'https' ? 'wss' : 'ws',
      ) + '/events'
    );
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
    // Issue #290 filter fields
    if (filter.contractAddress !== undefined) {
      const addr = (event as unknown as ContractEvent).contractAddress;
      if (addr !== filter.contractAddress) return false;
    }
    if (filter.credentialId !== undefined) {
      if (event.data.credentialId !== filter.credentialId) return false;
    }
    if (filter.did !== undefined) {
      const eventDID = (event.data.did ?? event.data.address) as
        | string
        | undefined;
      if (
        eventDID !== filter.did &&
        eventDID !== didToAddress(filter.did)
      ) {
        return false;
      }
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

  // ── Private — polling (Issue #290) ────────────────────────────────────────

  private startPollingInternal(): void {
    if (!this.pollingOptions) return;
    this.stopPollingInternal();

    const intervalMs =
      this.pollingOptions.intervalMs ?? DEFAULT_POLL_INTERVAL_MS;
    this.lastPolledLedger = this.pollingOptions.startLedger ?? null;
    this.pollingTimer = setInterval(() => {
      void this.pollOnce();
    }, intervalMs);
  }

  private stopPollingInternal(): void {
    if (this.pollingTimer) {
      clearInterval(this.pollingTimer);
      this.pollingTimer = null;
    }
  }

  private normalisePolledEvent(raw: unknown): SDKEvent & ContractEvent {
    const record = (raw && typeof raw === 'object' ? raw : {}) as Record<
      string,
      unknown
    >;
    const inner = (record.event && typeof record.event === 'object'
      ? record.event
      : record) as Record<string, unknown>;
    const type = String(inner.type ?? 'DIDCreated') as EventType;
    return {
      type,
      data: (inner.data && typeof inner.data === 'object'
        ? inner.data
        : {}) as Record<string, unknown>,
      timestamp: Number(inner.timestamp ?? Date.now()),
      contractAddress: record.contractId
        ? String(record.contractId)
        : inner.contractAddress
          ? String(inner.contractAddress)
          : undefined,
      ledger: typeof record.ledger === 'number' ? record.ledger : undefined,
    };
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
      } catch {
        /* prevent listener errors from crashing the subscriber */
      }
    }
  }
}

/** Extract the Stellar address from a `did:stellar:<address>:...` identifier. */
function didToAddress(did: string): string {
  if (!did.startsWith('did:stellar:')) return did;
  return did.slice('did:stellar:'.length).split(':')[0];
}

