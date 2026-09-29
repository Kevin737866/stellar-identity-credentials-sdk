import {
  EventStream,
  toWebSocketUrl,
  computeBackoffDelay,
  matchesFilters,
  parseEvent,
  didToAddress,
  IdentityEvent,
  WebSocketLike,
  WS_OPEN,
  WS_CLOSED,
} from '../eventStream';

jest.mock('../logger', () => ({
  Logger: jest.fn().mockImplementation(() => ({
    trace: jest.fn(),
    debug: jest.fn(),
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
  })),
}));

const config = { network: 'testnet' as const };

/** Scriptable WebSocket double. */
class MockWebSocket implements WebSocketLike {
  static instances: MockWebSocket[] = [];
  static OPEN = 1;

  readyState = 0;
  sent: string[] = [];
  closed = false;

  onopen: ((event: unknown) => void) | null = null;
  onclose: ((event: { code?: number; reason?: string }) => void) | null = null;
  onerror: ((event: unknown) => void) | null = null;
  onmessage: ((event: { data: unknown }) => void) | null = null;

  constructor(readonly url: string) {
    MockWebSocket.instances.push(this);
  }

  send(data: string): void {
    this.sent.push(data);
  }

  close(): void {
    this.closed = true;
    this.readyState = WS_CLOSED;
  }

  /** Simulate the server accepting the connection. */
  open(): void {
    this.readyState = WS_OPEN;
    this.onopen?.({});
  }

  /** Simulate an inbound frame. */
  emit(payload: unknown): void {
    this.onmessage?.({ data: JSON.stringify(payload) });
  }

  /** Simulate the server closing the connection. */
  serverClose(reason = 'server'): void {
    this.readyState = WS_CLOSED;
    this.onclose?.({ code: 1006, reason });
  }
}

function makeStream(overrides: Record<string, unknown> = {}) {
  const stream = new EventStream(config, {
    webSocketFactory: (url: string) => new MockWebSocket(url),
    ...overrides,
  });
  return stream;
}

function event(overrides: Partial<IdentityEvent> = {}): IdentityEvent {
  return {
    id: 'e1',
    type: 'CredentialIssued',
    data: {},
    timestamp: 1000,
    ...overrides,
  };
}

beforeEach(() => {
  MockWebSocket.instances = [];
  jest.useRealTimers();
});

describe('toWebSocketUrl', () => {
  it('converts https to wss', () => {
    expect(toWebSocketUrl('https://soroban-testnet.stellar.org')).toBe(
      'wss://soroban-testnet.stellar.org/events',
    );
  });

  it('converts http to ws', () => {
    expect(toWebSocketUrl('http://localhost:8000')).toBe('ws://localhost:8000/events');
  });

  it('strips a trailing slash', () => {
    expect(toWebSocketUrl('https://rpc.example/')).toBe('wss://rpc.example/events');
  });
});

describe('computeBackoffDelay', () => {
  it('grows exponentially', () => {
    const noJitter = { jitterRatio: 0 };
    expect(computeBackoffDelay(1, { initialDelayMs: 100 }, () => 0)).toBe(100);
    expect(computeBackoffDelay(2, { initialDelayMs: 100 }, () => 0)).toBe(200);
    expect(computeBackoffDelay(3, { initialDelayMs: 100 }, () => 0)).toBe(400);
    expect(noJitter).toBeDefined();
  });

  it('caps at maxDelayMs', () => {
    expect(computeBackoffDelay(20, { initialDelayMs: 100, maxDelayMs: 1000 }, () => 0)).toBe(1000);
  });

  it('adds jitter within the configured ratio', () => {
    const delay = computeBackoffDelay(1, { initialDelayMs: 1000, jitterRatio: 0.5 }, () => 1);
    expect(delay).toBe(1500);
  });

  it('treats attempt 0 as the first attempt', () => {
    expect(computeBackoffDelay(0, { initialDelayMs: 100 }, () => 0)).toBe(100);
  });
});

describe('didToAddress', () => {
  it('extracts the address from a stellar DID', () => {
    expect(didToAddress('did:stellar:GABC123')).toBe('GABC123');
  });

  it('returns null for a non-stellar DID', () => {
    expect(didToAddress('did:web:example.com')).toBeNull();
  });

  it('returns null for garbage', () => {
    expect(didToAddress('nonsense')).toBeNull();
  });
});

describe('matchesFilters', () => {
  it('matches everything with no filters', () => {
    expect(matchesFilters(event())).toBe(true);
  });

  it('filters by type', () => {
    expect(matchesFilters(event(), { types: ['CredentialIssued'] })).toBe(true);
    expect(matchesFilters(event(), { types: ['CredentialRevoked'] })).toBe(false);
  });

  it('treats an empty type list as no filter', () => {
    expect(matchesFilters(event(), { types: [] })).toBe(true);
  });

  it('filters by address', () => {
    const e = event({ data: { address: 'G1' } });
    expect(matchesFilters(e, { address: 'G1' })).toBe(true);
    expect(matchesFilters(e, { address: 'G2' })).toBe(false);
  });

  it('filters by credentialType', () => {
    const e = event({ data: { credentialType: 'KYC' } });
    expect(matchesFilters(e, { credentialType: 'KYC' })).toBe(true);
    expect(matchesFilters(e, { credentialType: 'Education' })).toBe(false);
  });

  it('filters by credentialId', () => {
    const e = event({ data: { credentialId: 'cred-1' } });
    expect(matchesFilters(e, { credentialId: 'cred-1' })).toBe(true);
    expect(matchesFilters(e, { credentialId: 'cred-2' })).toBe(false);
  });

  it('filters by contractAddress', () => {
    const e = event({ contractAddress: 'C1' });
    expect(matchesFilters(e, { contractAddress: 'C1' })).toBe(true);
    expect(matchesFilters(e, { contractAddress: 'C2' })).toBe(false);
  });

  it('matches a DID against either the DID or its address', () => {
    const e = event({ data: { did: 'did:stellar:GABC' } });
    expect(matchesFilters(e, { did: 'did:stellar:GABC' })).toBe(true);
    expect(matchesFilters(e, { did: 'GABC' })).toBe(true);
    expect(matchesFilters(e, { did: 'GOTHER' })).toBe(false);
  });

  it('falls back to the address when no did is present', () => {
    const e = event({ data: { address: 'GABC' } });
    expect(matchesFilters(e, { did: 'GABC' })).toBe(true);
  });

  it('filters by score range', () => {
    const e = event({ data: { score: 500 } });
    expect(matchesFilters(e, { minScore: 400 })).toBe(true);
    expect(matchesFilters(e, { minScore: 600 })).toBe(false);
    expect(matchesFilters(e, { maxScore: 600 })).toBe(true);
    expect(matchesFilters(e, { maxScore: 400 })).toBe(false);
  });

  it('rejects a score filter when the event has no score', () => {
    expect(matchesFilters(event(), { minScore: 0 })).toBe(false);
  });

  it('applies a custom predicate', () => {
    expect(matchesFilters(event(), { predicate: e => e.type === 'CredentialIssued' })).toBe(true);
    expect(matchesFilters(event(), { predicate: () => false })).toBe(false);
  });

  it('requires every specified field to match', () => {
    const e = event({ data: { address: 'G1', credentialType: 'KYC' } });
    expect(matchesFilters(e, { address: 'G1', credentialType: 'KYC' })).toBe(true);
    expect(matchesFilters(e, { address: 'G1', credentialType: 'Education' })).toBe(false);
  });
});

describe('parseEvent', () => {
  it('parses a valid frame', () => {
    const parsed = parseEvent({
      id: 'e1',
      type: 'CredentialIssued',
      data: { credentialId: 'c1' },
      timestamp: 1,
      ledger: 5,
      contractAddress: 'C1',
    });

    expect(parsed).toEqual({
      id: 'e1',
      type: 'CredentialIssued',
      data: { credentialId: 'c1' },
      timestamp: 1,
      ledger: 5,
      contractAddress: 'C1',
    });
  });

  it('parses a JSON string frame', () => {
    const parsed = parseEvent(
      JSON.stringify({ type: 'DIDCreated', data: {}, timestamp: 1 }),
    );
    expect(parsed?.type).toBe('DIDCreated');
  });

  it('synthesises an id when absent', () => {
    const parsed = parseEvent({ type: 'DIDCreated', data: {}, timestamp: 7, ledger: 3 });
    expect(parsed?.id).toBe('DIDCreated:3:7');
  });

  it('rejects an unknown event type', () => {
    expect(parseEvent({ type: 'NotARealEvent', data: {}, timestamp: 1 })).toBeNull();
  });

  it('rejects a frame without a timestamp', () => {
    expect(parseEvent({ type: 'DIDCreated', data: {} })).toBeNull();
  });

  it('rejects a frame without data', () => {
    expect(parseEvent({ type: 'DIDCreated', timestamp: 1 })).toBeNull();
  });

  it('rejects a pong control frame', () => {
    expect(parseEvent({ type: 'pong' })).toBeNull();
  });

  it('rejects malformed JSON', () => {
    expect(parseEvent('{not json')).toBeNull();
  });

  it('rejects non-objects', () => {
    expect(parseEvent(null)).toBeNull();
    expect(parseEvent(42)).toBeNull();
  });
});

describe('EventStream', () => {
  describe('connection', () => {
    it('connects lazily on the first subscription', () => {
      const stream = makeStream();
      expect(MockWebSocket.instances).toHaveLength(0);

      stream.subscribeToEvents({}, jest.fn());
      expect(MockWebSocket.instances).toHaveLength(1);
    });

    it('uses a wss url derived from the rpc url', () => {
      const stream = new EventStream(config, {
        webSocketFactory: (url: string) => new MockWebSocket(url),
      });
      stream.subscribeToEvents({}, jest.fn());

      expect(MockWebSocket.instances[0].url).toBe('wss://soroban-testnet.stellar.org/events');
    });

    it('honours an explicit url', () => {
      const stream = makeStream({ url: 'wss://custom.example/events' });
      stream.subscribeToEvents({}, jest.fn());

      expect(MockWebSocket.instances[0].url).toBe('wss://custom.example/events');
    });

    it('transitions to connected when the socket opens', () => {
      const stream = makeStream();
      stream.subscribeToEvents({}, jest.fn());

      expect(stream.getStatus()).toBe('connecting');
      MockWebSocket.instances[0].open();
      expect(stream.getStatus()).toBe('connected');
      expect(stream.isConnected()).toBe(true);
    });

    it('reports status transitions to a listener', () => {
      const stream = makeStream();
      const statuses: string[] = [];
      stream.onStatusChange(s => statuses.push(s));

      stream.subscribeToEvents({}, jest.fn());
      MockWebSocket.instances[0].open();

      expect(statuses).toContain('connecting');
      expect(statuses).toContain('connected');
    });

    it('stops reconnecting after close', () => {
      const stream = makeStream();
      stream.subscribeToEvents({}, jest.fn());
      MockWebSocket.instances[0].open();

      stream.close();

      expect(stream.getStatus()).toBe('closed');
      expect(MockWebSocket.instances[0].closed).toBe(true);
    });

    it('is idempotent when connect is called twice', () => {
      const stream = makeStream();
      stream.subscribeToEvents({}, jest.fn());
      stream.connect();
      stream.connect();

      expect(MockWebSocket.instances).toHaveLength(1);
    });
  });

  describe('event delivery', () => {
    it('delivers matching events to the handler', () => {
      const stream = makeStream();
      const handler = jest.fn();
      stream.subscribeToEvents({ types: ['CredentialIssued'] }, handler);

      MockWebSocket.instances[0].open();
      MockWebSocket.instances[0].emit({
        id: 'e1',
        type: 'CredentialIssued',
        data: { credentialId: 'c1' },
        timestamp: 1,
      });

      expect(handler).toHaveBeenCalledTimes(1);
      expect(handler.mock.calls[0][0].data.credentialId).toBe('c1');
    });

    it('filters out non-matching events', () => {
      const stream = makeStream();
      const handler = jest.fn();
      stream.subscribeToEvents({ address: 'G1' }, handler);

      MockWebSocket.instances[0].open();
      MockWebSocket.instances[0].emit({
        id: 'e1',
        type: 'CredentialIssued',
        data: { address: 'G2' },
        timestamp: 1,
      });

      expect(handler).not.toHaveBeenCalled();
    });

    it('fans one event out to every matching subscriber', () => {
      const stream = makeStream();
      const a = jest.fn();
      const b = jest.fn();
      stream.subscribeToEvents({}, a);
      stream.subscribeToEvents({}, b);

      MockWebSocket.instances[0].open();
      MockWebSocket.instances[0].emit({
        id: 'e1',
        type: 'CredentialIssued',
        data: {},
        timestamp: 1,
      });

      expect(a).toHaveBeenCalledTimes(1);
      expect(b).toHaveBeenCalledTimes(1);
    });

    it('drops duplicate event ids', () => {
      const stream = makeStream();
      const handler = jest.fn();
      stream.subscribeToEvents({}, handler);

      MockWebSocket.instances[0].open();
      const frame = { id: 'dup', type: 'CredentialIssued', data: {}, timestamp: 1 };
      MockWebSocket.instances[0].emit(frame);
      MockWebSocket.instances[0].emit(frame);

      expect(handler).toHaveBeenCalledTimes(1);
      expect(stream.getMetrics().duplicatesDropped).toBe(1);
    });

    it('ignores malformed frames without throwing', () => {
      const stream = makeStream();
      const handler = jest.fn();
      stream.subscribeToEvents({}, handler);

      MockWebSocket.instances[0].open();
      MockWebSocket.instances[0].onmessage?.({ data: '{not json' });

      expect(handler).not.toHaveBeenCalled();
      expect(stream.getMetrics().malformedMessages).toBe(1);
    });

    it('isolates a throwing handler from other subscribers', () => {
      const stream = makeStream();
      const good = jest.fn();
      stream.subscribeToEvents({}, () => {
        throw new Error('handler bug');
      });
      stream.subscribeToEvents({}, good);

      MockWebSocket.instances[0].open();
      MockWebSocket.instances[0].emit({
        id: 'e1',
        type: 'CredentialIssued',
        data: {},
        timestamp: 1,
      });

      expect(good).toHaveBeenCalledTimes(1);
      expect(stream.getMetrics().handlerErrors).toBe(1);
    });
  });

  describe('subscriptions', () => {
    it('stops delivering after unsubscribe', () => {
      const stream = makeStream();
      const handler = jest.fn();
      const sub = stream.subscribeToEvents({}, handler);

      MockWebSocket.instances[0].open();
      sub.unsubscribe();
      MockWebSocket.instances[0].emit({
        id: 'e1',
        type: 'CredentialIssued',
        data: {},
        timestamp: 1,
      });

      expect(handler).not.toHaveBeenCalled();
      expect(sub.active).toBe(false);
    });

    it('is idempotent on repeated unsubscribe', () => {
      const stream = makeStream();
      const sub = stream.subscribeToEvents({}, jest.fn());

      expect(() => {
        sub.unsubscribe();
        sub.unsubscribe();
      }).not.toThrow();
    });

    it('pauses and resumes delivery', () => {
      const stream = makeStream();
      const handler = jest.fn();
      const sub = stream.subscribeToEvents({}, handler);

      MockWebSocket.instances[0].open();
      sub.pause();
      expect(sub.paused).toBe(true);
      MockWebSocket.instances[0].emit({
        id: 'e1',
        type: 'CredentialIssued',
        data: {},
        timestamp: 1,
      });
      expect(handler).not.toHaveBeenCalled();

      sub.resume();
      expect(sub.paused).toBe(false);
      MockWebSocket.instances[0].emit({
        id: 'e2',
        type: 'CredentialIssued',
        data: {},
        timestamp: 2,
      });
      expect(handler).toHaveBeenCalledTimes(1);
    });

    it('rejects a non-function handler', () => {
      const stream = makeStream();
      expect(() => stream.subscribeToEvents({}, null as never)).toThrow(TypeError);
    });

    it('replays history when requested', () => {
      const stream = makeStream();
      stream.subscribeToEvents({}, jest.fn());
      MockWebSocket.instances[0].open();
      MockWebSocket.instances[0].emit({
        id: 'e1',
        type: 'CredentialIssued',
        data: {},
        timestamp: 1,
      });

      const replayed = jest.fn();
      stream.subscribeToEvents({}, replayed, { replayHistory: true });

      expect(replayed).toHaveBeenCalledTimes(1);
    });

    it('clears all subscriptions on disconnect', () => {
      const stream = makeStream();
      stream.subscribeToEvents({}, jest.fn());
      stream.disconnect();

      expect(stream.getMetrics().subscribers).toBe(0);
    });
  });

  describe('reconnection', () => {
    it('reconnects after an unexpected close', () => {
      jest.useFakeTimers();
      const stream = makeStream({ backoff: { initialDelayMs: 100, jitterRatio: 0 } });
      stream.subscribeToEvents({}, jest.fn());
      MockWebSocket.instances[0].open();

      MockWebSocket.instances[0].serverClose();
      expect(stream.getStatus()).toBe('reconnecting');

      jest.advanceTimersByTime(100);

      expect(MockWebSocket.instances).toHaveLength(2);
    });

    it('resets the attempt counter after a successful reconnect', () => {
      jest.useFakeTimers();
      const stream = makeStream({ backoff: { initialDelayMs: 100, jitterRatio: 0 } });
      stream.subscribeToEvents({}, jest.fn());
      MockWebSocket.instances[0].open();
      MockWebSocket.instances[0].serverClose();
      jest.advanceTimersByTime(100);
      MockWebSocket.instances[1].open();

      expect(stream.getMetrics().reconnectAttempts).toBe(0);
    });

    it('gives up after maxAttempts', () => {
      jest.useFakeTimers();
      const stream = makeStream({
        backoff: { initialDelayMs: 10, jitterRatio: 0, maxAttempts: 2 },
      });
      stream.subscribeToEvents({}, jest.fn());
      MockWebSocket.instances[0].open();

      MockWebSocket.instances[0].serverClose();
      jest.advanceTimersByTime(10);
      MockWebSocket.instances[1].serverClose();
      jest.advanceTimersByTime(20);
      MockWebSocket.instances[2].serverClose();
      jest.advanceTimersByTime(40);

      expect(stream.getStatus()).toBe('failed');
    });

    it('does not reconnect after an explicit close', () => {
      jest.useFakeTimers();
      const stream = makeStream({ backoff: { initialDelayMs: 10, jitterRatio: 0 } });
      stream.subscribeToEvents({}, jest.fn());
      MockWebSocket.instances[0].open();

      stream.close();
      jest.advanceTimersByTime(1000);

      expect(MockWebSocket.instances).toHaveLength(1);
    });

    it('survives a factory that throws', () => {
      jest.useFakeTimers();
      const stream = new EventStream(config, {
        webSocketFactory: () => {
          throw new Error('no socket for you');
        },
        backoff: { initialDelayMs: 10, jitterRatio: 0 },
      });

      stream.connect();
      expect(stream.getStatus()).toBe('reconnecting');

      jest.advanceTimersByTime(10);
    });
  });

  describe('metrics and history', () => {
    it('tracks received and delivered counts', () => {
      const stream = makeStream();
      stream.subscribeToEvents({}, jest.fn());
      MockWebSocket.instances[0].open();
      MockWebSocket.instances[0].emit({
        id: 'e1',
        type: 'CredentialIssued',
        data: {},
        timestamp: 1,
      });

      const metrics = stream.getMetrics();
      expect(metrics.eventsReceived).toBe(1);
      expect(metrics.eventsDelivered).toBe(1);
      expect(metrics.subscribers).toBe(1);
      expect(metrics.lastEventAt).toBeGreaterThan(0);
    });

    it('retains history up to historySize', () => {
      const stream = makeStream({ historySize: 2 });
      stream.subscribeToEvents({}, jest.fn());
      MockWebSocket.instances[0].open();

      for (let i = 0; i < 5; i++) {
        MockWebSocket.instances[0].emit({
          id: `e${i}`,
          type: 'CredentialIssued',
          data: {},
          timestamp: i,
        });
      }

      const history = stream.getHistory();
      expect(history).toHaveLength(2);
      expect(history.map(e => e.id)).toEqual(['e3', 'e4']);
    });

    it('supports a history limit', () => {
      const stream = makeStream();
      stream.subscribeToEvents({}, jest.fn());
      MockWebSocket.instances[0].open();
      for (let i = 0; i < 3; i++) {
        MockWebSocket.instances[0].emit({
          id: `e${i}`,
          type: 'CredentialIssued',
          data: {},
          timestamp: i,
        });
      }

      expect(stream.getHistory(1)).toHaveLength(1);
    });
  });

  describe('async iteration', () => {
    it('yields events until the stream closes', async () => {
      const stream = makeStream();
      const collected: string[] = [];

      const consume = (async () => {
        for await (const e of stream.events({ types: ['CredentialIssued'] })) {
          collected.push(e.id);
          if (collected.length === 2) stream.close();
        }
      })();

      // Let the generator subscribe before pushing frames.
      await Promise.resolve();
      const socket = MockWebSocket.instances[0];
      socket.open();
      socket.emit({ id: 'e1', type: 'CredentialIssued', data: {}, timestamp: 1 });
      socket.emit({ id: 'e2', type: 'CredentialIssued', data: {}, timestamp: 2 });

      await consume;
      expect(collected).toEqual(['e1', 'e2']);
    });
  });
});
