import { StellarIdentityConfig } from './types';

type EventType =
  | 'DIDCreated'
  | 'CredentialIssued'
  | 'CredentialRevoked'
  | 'ReputationScoreUpdated'
  | 'ProofVerified'
  | 'AddressSanctioned';

interface Subscription {
  id: string;
  eventType: EventType;
  filter?: EventFilter;
  callback: (event: SDKEvent) => void;
  batchSize?: number;
  batchIntervalMs?: number;
}

interface EventFilter {
  address?: string;
  credentialType?: string;
  minScore?: number;
}

interface SDKEvent {
  type: EventType;
  data: Record<string, unknown>;
  timestamp: number;
}

interface SubscriptionEvent {
  subscriptionId: string;
  event: SDKEvent;
}

const DEFAULT_RECONNECT_DELAY_MS = 1000;
const MAX_RECONNECT_DELAY_MS = 30000;

const EVENT_TYPE_SET: Set<string> = new Set([
  'DIDCreated',
  'CredentialIssued',
  'CredentialRevoked',
  'ReputationScoreUpdated',
  'ProofVerified',
  'AddressSanctioned',
]);

export class EventSubscriber {
  private subscriptions: Map<string, Subscription> = new Map();
  private subscriptionCounter = 0;
  private ws: WebSocket | null = null;
  private rpcUrl: string;
  private reconnectAttempts = 0;
  private reconnectDelayMs = DEFAULT_RECONNECT_DELAY_MS;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private shouldReconnect = true;
  private eventQueue: Map<string, SDKEvent[]> = new Map();
  private batchTimers: Map<string, ReturnType<typeof setInterval>> = new Map();
  private isConnected = false;

  constructor(config: StellarIdentityConfig) {
    this.rpcUrl = config.rpcUrl || this.getDefaultRpcUrl(config);
  }

  subscribe(
    eventType: EventType,
    filter: EventFilter | undefined,
    callback: (event: SDKEvent) => void,
    options?: { batchSize?: number; batchIntervalMs?: number }
  ): string {
    if (!EVENT_TYPE_SET.has(eventType)) {
      throw new Error(`Unsupported event type: ${eventType}`);
    }

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

  unsubscribe(subscriptionId: string): void {
    this.subscriptions.delete(subscriptionId);
    this.eventQueue.delete(subscriptionId);

    const timer = this.batchTimers.get(subscriptionId);
    if (timer) {
      clearInterval(timer);
      this.batchTimers.delete(subscriptionId);
    }
  }

  async once(eventType: EventType, filter?: EventFilter): Promise<SDKEvent> {
    return new Promise((resolve) => {
      const id = this.subscribe(eventType, filter, (event) => {
        this.unsubscribe(id);
        resolve(event);
      });
    });
  }

  connect(): void {
    this.shouldReconnect = true;
    this.reconnectAttempts = 0;
    this.reconnectDelayMs = DEFAULT_RECONNECT_DELAY_MS;
    this.connectInternal();
  }

  disconnect(): void {
    this.shouldReconnect = false;
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
    this.isConnected = false;

    for (const timer of this.batchTimers.values()) {
      clearInterval(timer);
    }
    this.batchTimers.clear();
  }

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
          const event = JSON.parse(msg.data) as SDKEvent;
          this.dispatchEvent(event);
        } catch {}
      };

      this.ws.onclose = () => {
        this.isConnected = false;
        if (this.shouldReconnect) {
          this.scheduleReconnect();
        }
      };

      this.ws.onerror = () => {
        this.isConnected = false;
      };
    } catch {
      if (this.shouldReconnect) {
        this.scheduleReconnect();
      }
    }
  }

  private scheduleReconnect(): void {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
    }

    const delay = Math.min(
      this.reconnectDelayMs * Math.pow(2, this.reconnectAttempts),
      MAX_RECONNECT_DELAY_MS
    );

    this.reconnectTimer = setTimeout(() => {
      this.reconnectAttempts++;
      this.connectInternal();
    }, delay);
  }

  private dispatchEvent(event: SDKEvent): void {
    for (const sub of this.subscriptions.values()) {
      if (sub.eventType !== event.type) continue;
      if (sub.filter && !this.matchesFilter(event, sub.filter)) continue;

      if (sub.batchSize) {
        this.enqueueEvent(sub.id, event);
      } else {
        sub.callback(event);
      }
    }
  }

  private matchesFilter(event: SDKEvent, filter: EventFilter): boolean {
    if (filter.address && event.data.address !== filter.address) return false;
    if (filter.credentialType && event.data.credentialType !== filter.credentialType) return false;
    if (filter.minScore !== undefined) {
      const score = event.data.score as number | undefined;
      if (score === undefined || score < filter.minScore) return false;
    }
    return true;
  }

  private enqueueEvent(subscriptionId: string, event: SDKEvent): void {
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

  private getDefaultRpcUrl(config: StellarIdentityConfig): string {
    switch (config.network) {
      case 'mainnet': return 'https://soroban-rpc.stellar.org';
      case 'futurenet': return 'https://rpc-futurenet.stellar.org';
      default: return 'https://soroban-testnet.stellar.org';
    }
  }
}

export type { EventType, Subscription, EventFilter, SDKEvent };
