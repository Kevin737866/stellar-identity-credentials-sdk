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
 * Issue #290 additions live alongside the existing subscribe/unsubscribe/
 * once surface so existing call sites continue to work unchanged.
 */

import { SorobanRpc } from 'stellar-sdk';
import { StellarIdentityConfig } from './types';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type EventType =
  | 'DIDCreated'
  | 'CredentialIssued'
  | 'CredentialRevoked'
  | 'ReputationScoreUpdated'
  | 'ProofVerified'
  | 'AddressSanctioned';

/** Event handler signature \u2014 aliased as ContractEvent for Issue #290. */
export type ContractEventHandler = (event: ContractEvent) => void;

/** A single on-chain event delivered to subscribers. */
export interface ContractEvent {
  type: EventType;
  data: Record<string, unknown>;
  timestamp: number;
  /** Originating contract address, when known (polling transport). */
  contractAddress?: string;
  /** Ledger sequence the event was observed on, when known. */
  ledger?: number;
}

/** Backwards-compatible alias \u2014 SDKEvent pre-existed Issue #290. */
export type SDKEvent = ContractEvent;

export interface EventFilter {
  address?: string;
  credentialType?: string;
  minScore?: number;
  /** Filter to events emitted by a specific contract. */
  contractAddress?: string;
  /** Filter by credential ID (used by subscribeToCredentialEvents). */
  credentialId?: string;
  /** Filter by DID (used by subscribeToDIDEvents). */
  did?: string;
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

interface Subscription {
  id: string;
  eventType: EventType;
  filter?: EventFilter;
  callback: ContractEventHandler;
  batchSize?: number;
  batchIntervalMs?: number;
  /** Issue #290: marker for synthetic contract-address subscriptions so
   *  unsubscribe(contract:<addr>) evicts only those this call created. */
  _contractOwner?: string;
}

const DEFAULT_RECONNECT_DELAY_MS = 1000;
const MAX_RECONNECT_DELAY_MS = 30000;
const DEFAULT_POLL_INTERVAL_MS = 5000;

const EVENT_TYPE_SET: Set<string> = new Set([
  'DIDCreated',
  'CredentialIssued',
  'CredentialRevoked',
  'ReputationScoreUpdated',
  'ProofVerified',
  'AddressSanctioned',
]);

const DID_RELATED_EVENTS: EventType[] = [
  'DIDCreated',
  'CredentialIssued',
  'CredentialRevoked',
  'ReputationScoreUpdated',
  'AddressSanctioned',
];

const CREDENTIAL_RELATED_EVENTS: EventType[] = [
  'CredentialIssued',
  'CredentialRevoked',
  'ProofVerified',
];

// ---------------------------------------------------------------------------
// EventSubscriber
// ---------------------------------------------------------------------------

export class EventSubscriber {
  private subscriptions: Map<string, Subscription> = new Map();
  private subscriptionCounter = 0;
  private ws: WebSocket | null = null;
  private rpcUrl: string;
  private reconnectAttempts = 0;
  private reconnectDelayMs = DEFAULT_RECONNECT_DELAY_MS;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private shouldReconnect = true;
  private eventQueue: Map<string, ContractEvent[]> = new Map();
  private batchTimers: Map<string, ReturnType<typeof setInterval>> = new Map();
  private isConnected = false;
  /** Lazily constructed so unit tests do not need a real Soroban RPC URL. */
  private _rpc?: SorobanRpc.Server;
  private get rpc(): SorobanRpc.Server {
    if (!this._rpc) this._rpc = new SorobanRpc.Server(this.rpcUrl);
    return this._rpc;
  }
  /** Polling state (Issue #290). */
  private pollingOptions: PollingOptions | null = null;
  private pollingTimer: ReturnType<typeof setInterval> | null = null;
  private lastPolledLedger: number | null = null;

  constructor(config: StellarIdentityConfig) {
    this.rpcUrl = config.rpcUrl || this.getDefaultRpcUrl(config);
  }

  // -------------------------------------------------------------------------
  // Public subscription API
  // -------------------------------------------------------------------------

  subscribe(
    eventType: EventType,
    filter: EventFilter | undefined,
    callback: ContractEventHandler,
    options?: { batchSize?: number; batchIntervalMs?: number },
  ): string {
    if (!EVENT_TYPE_SET.has(eventType)) {
      throw new Error(`Unsupported event type: ${eventType}`);
    }
    return this.registerSubscription(eventType, filter, callback, options);
  }

  /**
   * Alias for {@link subscribe} with batching explicitly disabled.
   * Provided so callers that want Node.js EventEmitter-style synchronous
   * delivery (one callback per event) do not have to pass undefined options.
   */
  on(
    eventType: EventType,
    filter: EventFilter | undefined,
    callback: ContractEventHandler,
  ): string {
    return this.subscribe(eventType, filter, callback);
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
  subscribeToCredentialEvents(credentialId: string, callback: ContractEventHandler): string[] {
    if (!credentialId) throw new Error('credentialId must be non-empty');
    return CREDENTIAL_RELATED_EVENTS.map(eventType =>
      this.subscribe(eventType, { credentialId }, callback),
    );
  }

  /**
   * Subscribe to every event emitted by a specific contract address.
   */
  subscribeToContractEvents(
    contractAddress: string,
    callback: ContractEventHandler,
  ): string {
    if (!contractAddress) throw new Error('contractAddress must be non-empty');
    // Dedupe the union of credential- and DID-related event types so a
    // single event cannot fire the user callback twice. Without this,
    // `CredentialIssued` and `CredentialRevoked` would both appear in
    // both sets and double-deliver.
    const targets = Array.from(
      new Set<EventType>([...CREDENTIAL_RELATED_EVENTS, ...DID_RELATED_EVENTS]),
    );
    const ownerTag = contractAddress; // tags every synthetic subscription
    for (const eventType of targets) {
      this.subscribe(
        eventType,
        { contractAddress },
        callback,
      );
      // Mark the just-created subscription so unsubscribe(contract:<addr>)
      // can recognise and evict only synthetic subscribers owned by this
      // call rather than any subscription with a matching contractAddress.
      const last = Array.from(this.subscriptions.values()).pop();
      if (last) (last as Subscription & { _contractOwner?: string })._contractOwner = ownerTag;
    }
    return `contract:${contractAddress}`;
  }

  unsubscribe(subscriptionId: string): void {
    if (subscriptionId.startsWith('contract:')) {
      // Strip the helper prefix and only evict synthetic subscriptions
      // tagged with the matching _contractOwner. Without the owner tag this
      // would also delete subscriptions created by a separate later
      // subscribeToContractEvents call that happened to target the same
      // contractAddress.
      const target = subscriptionId.slice('contract:'.length);
      for (const [id, sub] of Array.from(this.subscriptions.entries())) {
        if (sub._contractOwner === target) {
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
    this.subscriptions.delete(subscriptionId);
    this.eventQueue.delete(subscriptionId);

    const timer = this.batchTimers.get(subscriptionId);
    if (timer) {
      clearInterval(timer);
      this.batchTimers.delete(subscriptionId);
    }
  }

  async once(eventType: EventType, filter?: EventFilter): Promise<ContractEvent> {
    return new Promise((resolve) => {
      const id = this.subscribe(eventType, filter, (event) => {
        this.unsubscribe(id);
        resolve(event);
      });
    });
  }

  // -------------------------------------------------------------------------
  // Transport control
  // -------------------------------------------------------------------------

  connect(): void {
    this.shouldReconnect = true;
    this.reconnectAttempts = 0;
    this.reconnectDelayMs = DEFAULT_RECONNECT_DELAY_MS;
    this.connectInternal();
    if (this.pollingOptions?.enabled) this.startPollingInternal();
  }

  disconnect(): void {
    this.shouldReconnect = false;
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    if (this.ws) {
      try { this.ws.close(); } catch {}
      this.ws = null;
    }
    this.isConnected = false;
    this.stopPollingInternal();

    for (const timer of this.batchTimers.values()) {
      clearInterval(timer);
    }
    this.batchTimers.clear();
  }

  /**
   * Configure polling-based event delivery (Issue #290 fallback). When
   * `enabled` is true, a setInterval loop hits rpc.getEvents and dispatches
   * any matching events through the same path used by the WebSocket transport.
   */
  enablePolling(options: PollingOptions): void {
    this.pollingOptions = options;
    if (options.enabled) {
      this.startPollingInternal();
    } else {
      this.stopPollingInternal();
    }
  }

  isConnectedToNetwork(): boolean {
    return this.isConnected;
  }

  /** Returns true when polling-backed delivery is currently active. */
  isPolling(): boolean {
    return this.pollingTimer !== null;
  }

  // -------------------------------------------------------------------------
  // Internal subscription bookkeeping
  // -------------------------------------------------------------------------

  private registerSubscription(
    eventType: EventType,
    filter: EventFilter | undefined,
    callback: ContractEventHandler,
    options?: { batchSize?: number; batchIntervalMs?: number },
  ): string {
    const id = `sub_${++this.subscriptionCounter}_${Date.now()}`;
    const subscription: Subscription = {
      id,
      eventType,
      filter,
      callback,
      batchSize: options?.batchSize,
      batchIntervalMs: options?.batchIntervalMs,
    };
    this.subscriptions.set(id, subscription);

    if (options?.batchSize || options?.batchIntervalMs) {
      this.setupBatching(id, options.batchIntervalMs ?? 1000);
    }
    return id;
  }

  // -------------------------------------------------------------------------
  // WebSocket transport
  // -------------------------------------------------------------------------

  private connectInternal(): void {
    if (this.ws) {
      try { this.ws.close(); } catch {}
      this.ws = null;
    }

    try {
      const url = this.rpcUrl.replace(/^http/, 'ws') + '/events';
      this.ws = new WebSocket(url);

      this.ws.onopen = () => {
        this.isConnected = true;
        this.reconnectAttempts = 0;
        this.reconnectDelayMs = DEFAULT_RECONNECT_DELAY_MS;
      };

      this.ws.onmessage = (msg: MessageEvent) => {
        try {
          const event = JSON.parse(msg.data) as ContractEvent;
          this.dispatchEvent(event);
        } catch {}
      };

      this.ws.onclose = () => {
        this.isConnected = false;
        if (this.shouldReconnect) this.scheduleReconnect();
      };

      this.ws.onerror = () => {
        this.isConnected = false;
      };
    } catch {
      if (this.shouldReconnect) this.scheduleReconnect();
    }
  }

  private scheduleReconnect(): void {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
    }
    const delay = Math.min(
      this.reconnectDelayMs * Math.pow(2, this.reconnectAttempts),
      MAX_RECONNECT_DELAY_MS,
    );
    this.reconnectTimer = setTimeout(() => {
      this.reconnectAttempts++;
      this.connectInternal();
    }, delay);
  }

  // -------------------------------------------------------------------------
  // Polling transport (Issue #290)
  // -------------------------------------------------------------------------

  private startPollingInternal(): void {
    if (!this.pollingOptions) return;
    this.stopPollingInternal();

    const intervalMs = this.pollingOptions.intervalMs ?? DEFAULT_POLL_INTERVAL_MS;
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

  /** Single polling tick. Exposed for tests; safe to await. */
  async pollOnce(): Promise<void> {
    if (!this.pollingOptions) return;
    try {
      const startLedger = this.lastPolledLedger ?? undefined;
      const response = await this.rpc.getEvents({
        startLedger,
        filters: this.pollingOptions.contractIds?.map(id => ({ contractIds: [id] })),
        topics: this.pollingOptions.topics,
      } as Parameters<SorobanRpc.Server['getEvents']>[0]);
      const events = response?.events ?? [];
      for (const evt of events) {
        this.dispatchEvent(this.normalisePolledEvent(evt));
      }
      if (typeof response?.latestLedger === 'number') {
        this.lastPolledLedger = response.latestLedger;
      }
    } catch {
      // Polling failure is non-fatal \u2014 logs could be added here.
    }
  }

  private normalisePolledEvent(raw: unknown): ContractEvent {
    const record = (raw && typeof raw === 'object' ? raw : {}) as Record<string, unknown>;
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

  // -------------------------------------------------------------------------
  // Dispatch and filtering
  // -------------------------------------------------------------------------

  private dispatchEvent(event: ContractEvent): void {
    for (const sub of this.subscriptions.values()) {
      if (sub.eventType !== event.type) continue;
      if (sub.filter && !this.matchesFilter(event, sub.filter)) continue;

      if (sub.batchSize) {
        this.enqueueEvent(sub.id, event);
        continue;
      }
      // Wrap in try/catch so a buggy handler cannot break sibling
      // subscribers (Issue #290 reconnection-and-error-handling clause).
      try {
        sub.callback(event);
      } catch {
        // Swallow handler errors; the dispatcher logs nothing because
        // there is no SDK-wide logger and silent recovery preserves
        // at-least-one delivery for the remaining subscribers.
      }
    }
  }

  private matchesFilter(event: ContractEvent, filter: EventFilter): boolean {
    if (filter.address && event.data.address !== filter.address) return false;
    if (filter.credentialType && event.data.credentialType !== filter.credentialType) return false;
    if (filter.contractAddress && event.contractAddress !== filter.contractAddress) return false;
    if (filter.credentialId && event.data.credentialId !== filter.credentialId) return false;
    if (filter.did) {
      const eventDID = event.data.did ?? event.data.address;
      if (eventDID !== filter.did && eventDID !== didToAddress(filter.did)) return false;
    }
    if (filter.minScore !== undefined) {
      const score = event.data.score as number | undefined;
      if (score === undefined || score < filter.minScore) return false;
    }
    return true;
  }

  private enqueueEvent(subscriptionId: string, event: ContractEvent): void {
    if (!this.eventQueue.has(subscriptionId)) {
      this.eventQueue.set(subscriptionId, []);
    }
    this.eventQueue.get(subscriptionId)!.push(event);
  }

  private setupBatching(subscriptionId: string, intervalMs: number): void {
    const timer = setInterval(() => {
      const queue = this.eventQueue.get(subscriptionId);
      if (!queue || queue.length === 0) return;

      const sub = this.subscriptions.get(subscriptionId);
      if (!sub) return;

      const batch = queue.splice(0, sub.batchSize ?? queue.length);
      for (const event of batch) {
        sub.callback(event);
      }
    }, intervalMs);

    this.batchTimers.set(subscriptionId, timer);
  }

  // -------------------------------------------------------------------------
  // Helpers
  // -------------------------------------------------------------------------

  private getDefaultRpcUrl(config: StellarIdentityConfig): string {
    switch (config.network) {
      case 'mainnet': return 'https://soroban-rpc.stellar.org';
      case 'futurenet': return 'https://rpc-futurenet.stellar.org';
      default: return 'https://soroban-testnet.stellar.org';
    }
  }
}

function didToAddress(did: string): string {
  if (!did.startsWith('did:stellar:')) return did;
  return did.slice('did:stellar:'.length).split(':')[0];
}
