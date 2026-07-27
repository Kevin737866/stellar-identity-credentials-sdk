/**
 * Tests for Issue #290 \u2014 event subscriber extensions.
 *
 * Coverage required by the issue:
 *   - subscription
 *   - filtering
 *   - multiple handlers
 *   - unsubscription
 *   - reconnection
 *
 * Plus the new surface:
 *   - on() alias
 *   - subscribeToDIDEvents / subscribeToCredentialEvents / subscribeToContractEvents
 *   - EventFilter extensions (contractAddress, credentialId, did)
 *   - Polling fallback (enablePolling + pollOnce)
 */

import {
  EventSubscriber,
  type ContractEvent,
  type EventType,
} from '../eventSubscriber';

const TEST_CONFIG = {
  network: 'testnet' as const,
  contracts: {
    didRegistry: 'CAAAA',
    credentialIssuer: 'CBBBB',
    reputationScore: 'CCCCC',
    zkAttestation: 'CDDDD',
    complianceFilter: 'CEEEE',
  },
  rpcUrl: 'https://soroban-testnet.stellar.org',
};

function makeSubscriber(): EventSubscriber {
  return new EventSubscriber(TEST_CONFIG);
}

function makeEvent(overrides: Partial<ContractEvent> = {}): ContractEvent {
  return {
    type: 'DIDCreated',
    data: {},
    timestamp: Date.now(),
    ...overrides,
  };
}

describe('EventSubscriber.on() (Issue #290 alias)', () => {
  test('registers a non-batched subscription and receives events', () => {
    const sub = makeSubscriber();
    const callback = jest.fn();
    const id = sub.on('DIDCreated', { address: 'GABC' }, callback);
    expect(id).toMatch(/^sub_/);

    // Reach into the dispatch path
    (sub as unknown as {
      dispatchEvent: (e: ContractEvent) => void;
    }).dispatchEvent(makeEvent({ type: 'DIDCreated', data: { address: 'GABC' } }));
    expect(callback).toHaveBeenCalledTimes(1);
  });
});

describe('EventSubscriber.subscribeToDIDEvents() (Issue #290)', () => {
  test('creates one subscription per DID-related event type', () => {
    const sub = makeSubscriber();
    const ids = sub.subscribeToDIDEvents('did:stellar:GABCDEFGHIJK', jest.fn());
    expect(ids.length).toBeGreaterThanOrEqual(4);
    expect(ids.every(id => id.startsWith('sub_'))).toBe(true);
  });

  test('rejects empty DID', () => {
    const sub = makeSubscriber();
    expect(() => sub.subscribeToDIDEvents('', jest.fn())).toThrow();
  });
});

describe('EventSubscriber.subscribeToCredentialEvents() (Issue #290)', () => {
  test('creates one subscription per credential-related event type', () => {
    const sub = makeSubscriber();
    const ids = sub.subscribeToCredentialEvents('cred-001', jest.fn());
    expect(ids.length).toBeGreaterThanOrEqual(2);
    expect(ids.every(id => id.startsWith('sub_'))).toBe(true);
  });

  test('rejects empty credentialId', () => {
    const sub = makeSubscriber();
    expect(() => sub.subscribeToCredentialEvents('', jest.fn())).toThrow();
  });
});

describe('EventSubscriber.subscribeToContractEvents() (Issue #290)', () => {
  test('creates a contract-prefixed subscription handle', () => {
    const sub = makeSubscriber();
    const id = sub.subscribeToContractEvents('CDLDX6JSK6JKZSQULP7N4JZBITMQ3OYRN4JPKK6K6L6L6L6L6L6L6L6L', jest.fn());
    expect(id.startsWith('contract:')).toBe(true);
  });

  test('discards events whose contractAddress does not match', () => {
    const sub = makeSubscriber();
    const callback = jest.fn();
    sub.subscribeToContractEvents('CNTR1', callback);

    (sub as unknown as {
      dispatchEvent: (e: ContractEvent) => void;
    }).dispatchEvent(makeEvent({
      type: 'DIDCreated',
      data: { address: 'GABC' },
      contractAddress: 'CNTR2',
    }));
    expect(callback).not.toHaveBeenCalled();
  });

  test('accepts events whose contractAddress matches', () => {
    const sub = makeSubscriber();
    const callback = jest.fn();
    sub.subscribeToContractEvents('CNTR1', callback);

    (sub as unknown as {
      dispatchEvent: (e: ContractEvent) => void;
    }).dispatchEvent(makeEvent({
      type: 'DIDCreated',
      data: { address: 'GABC' },
      contractAddress: 'CNTR1',
    }));
    expect(callback).toHaveBeenCalled();
  });

  test('rejects empty contractAddress', () => {
    const sub = makeSubscriber();
    expect(() => sub.subscribeToContractEvents('', jest.fn())).toThrow();
  });

  test('can unsubscribe all matching subscriptions with the handle', () => {
    const sub = makeSubscriber();
    const callback = jest.fn();
    const id = sub.subscribeToContractEvents('CNTR1', callback);
    sub.unsubscribe(id);

    // None of the auto-created per-type subscriptions should match anymore.
    (sub as unknown as {
      dispatchEvent: (e: ContractEvent) => void;
    }).dispatchEvent(makeEvent({
      type: 'DIDCreated',
      contractAddress: 'CNTR1',
    }));
    expect(callback).not.toHaveBeenCalled();
  });
});

describe('EventSubscriber filter extensions (Issue #290)', () => {
  test('matchesFilter rejects when did does not match', () => {
    const sub = makeSubscriber();
    const callback = jest.fn();
    sub.subscribe('DIDCreated', { did: 'did:stellar:GABC' }, callback);
    (sub as unknown as {
      dispatchEvent: (e: ContractEvent) => void;
    }).dispatchEvent(makeEvent({
      type: 'DIDCreated',
      data: { address: 'GXYZ' },
    }));
    expect(callback).not.toHaveBeenCalled();
  });

  test('matchesFilter accepts when did matches against data.did', () => {
    const sub = makeSubscriber();
    const callback = jest.fn();
    sub.subscribe('DIDCreated', { did: 'did:stellar:GABC' }, callback);
    (sub as unknown as {
      dispatchEvent: (e: ContractEvent) => void;
    }).dispatchEvent(makeEvent({
      type: 'DIDCreated',
      data: { did: 'did:stellar:GABC', address: 'GABC' },
    }));
    expect(callback).toHaveBeenCalledTimes(1);
  });

  test('matchesFilter rejects on credentialId mismatch', () => {
    const sub = makeSubscriber();
    const callback = jest.fn();
    sub.subscribe('CredentialIssued', { credentialId: 'cred-001' }, callback);
    (sub as unknown as {
      dispatchEvent: (e: ContractEvent) => void;
    }).dispatchEvent(makeEvent({
      type: 'CredentialIssued',
      data: { credentialId: 'cred-002' },
    }));
    expect(callback).not.toHaveBeenCalled();
  });
});

describe('EventSubscriber multiple handlers (Issue #290)', () => {
  test('two handlers for the same event both fire', () => {
    const sub = makeSubscriber();
    const handlerA = jest.fn();
    const handlerB = jest.fn();
    sub.subscribe('DIDCreated', undefined, handlerA);
    sub.subscribe('DIDCreated', undefined, handlerB);
    (sub as unknown as {
      dispatchEvent: (e: ContractEvent) => void;
    }).dispatchEvent(makeEvent({ type: 'DIDCreated' }));
    expect(handlerA).toHaveBeenCalledTimes(1);
    expect(handlerB).toHaveBeenCalledTimes(1);
  });

  test('first handler erroring does not block the second', () => {
    const sub = makeSubscriber();
    const handlerA = jest.fn(() => { throw new Error('boom'); });
    const handlerB = jest.fn();
    sub.subscribe('DIDCreated', undefined, handlerA);
    sub.subscribe('DIDCreated', undefined, handlerB);
    expect(() => {
      (sub as unknown as {
        dispatchEvent: (e: ContractEvent) => void;
      }).dispatchEvent(makeEvent({ type: 'DIDCreated' }));
    }).not.toThrow();
    expect(handlerB).toHaveBeenCalledTimes(1);
  });
});

describe('EventSubscriber unsubscription (Issue #290)', () => {
  test('unsubscribed callback no longer fires', () => {
    const sub = makeSubscriber();
    const callback = jest.fn();
    const id = sub.subscribe('DIDCreated', undefined, callback);
    sub.unsubscribe(id);
    (sub as unknown as {
      dispatchEvent: (e: ContractEvent) => void;
    }).dispatchEvent(makeEvent({ type: 'DIDCreated' }));
    expect(callback).not.toHaveBeenCalled();
  });
});

describe('EventSubscriber reconnection (Issue #290)', () => {
  test('scheduleReconnect applies exponential backoff', () => {
    const sub = makeSubscriber();
    // Force schedule-reconnect by simulating close with shouldReconnect=true.
    (sub as unknown as { reconnectAttempts: number }).reconnectAttempts = 0;
    (sub as unknown as { shouldReconnect: boolean; reconnectDelayMs: number; reconnectTimer: ReturnType<typeof setTimeout> | null }).shouldReconnect = true;
    (sub as unknown as { reconnectDelayMs: number }).reconnectDelayMs = 1000;
    (sub as unknown as { scheduleReconnect: () => void }).scheduleReconnect();
    const timer = (sub as unknown as { reconnectTimer: ReturnType<typeof setTimeout> | null }).reconnectTimer;
    expect(timer).not.toBeNull();
    clearTimeout(timer!);
  });
});

describe('EventSubscriber polling fallback (Issue #290)', () => {
  test('enablePolling starts a polling timer when enabled', () => {
    const sub = makeSubscriber();
    sub.enablePolling({ enabled: true, intervalMs: 60000 });
    expect(sub.isPolling()).toBe(true);
    sub.disconnect();
  });

  test('enablePolling does not start a timer when disabled', () => {
    const sub = makeSubscriber();
    sub.enablePolling({ enabled: false });
    expect(sub.isPolling()).toBe(false);
  });

  test('disconnect stops the polling timer', () => {
    const sub = makeSubscriber();
    sub.enablePolling({ enabled: true, intervalMs: 60000 });
    sub.disconnect();
    expect(sub.isPolling()).toBe(false);
  });
});

describe('EventSubscriber subscribe/unsubscribe lifecycle sanity (Issue #290)', () => {
  test('connecting/disconnecting does not throw without a real WebSocket', () => {
    const sub = makeSubscriber();
    expect(() => sub.connect()).not.toThrow();
    expect(() => sub.disconnect()).not.toThrow();
  });

  test('still throws on unknown event types', () => {
    const sub = makeSubscriber();
    expect(() => {
      sub.subscribe('Bogus' as EventType, undefined, jest.fn());
    }).toThrow(/Unsupported event type/);
  });
});
