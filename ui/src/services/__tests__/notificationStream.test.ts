import {
  NotificationStream,
  NotificationStreamStatus,
  parseNotificationPayload,
} from '../notificationStream';

const baseNotification = {
  id: 'ntf-1',
  type: 'credential-issued',
  title: 'KYC credential issued',
  createdAt: 1_700_000_000_000,
  read: false,
};

describe('parseNotificationPayload', () => {
  it('parses a single notification from a JSON string', () => {
    expect(parseNotificationPayload(JSON.stringify(baseNotification))).toEqual([
      baseNotification,
    ]);
  });

  it('parses an array of notifications', () => {
    const second = { ...baseNotification, id: 'ntf-2' };

    expect(parseNotificationPayload(JSON.stringify([baseNotification, second]))).toHaveLength(2);
  });

  it('parses a { notifications: [] } envelope', () => {
    const second = { ...baseNotification, id: 'ntf-2' };

    expect(
      parseNotificationPayload(JSON.stringify({ notifications: [baseNotification, second] }))
    ).toHaveLength(2);
  });

  it('accepts an already-parsed value', () => {
    expect(parseNotificationPayload(baseNotification)).toEqual([baseNotification]);
  });

  it('defaults read to false when the transport omits it', () => {
    const { read, ...withoutRead } = baseNotification;

    expect(parseNotificationPayload(withoutRead)[0].read).toBe(false);
  });

  it.each([
    ['malformed JSON', '{not json'],
    ['a JSON primitive', '"hello"'],
    ['null', 'null'],
    ['an empty envelope', JSON.stringify({ notifications: 'nope' })],
  ])('returns no notifications for %s', (_label, payload) => {
    expect(parseNotificationPayload(payload)).toEqual([]);
  });

  it('drops invalid entries but keeps valid ones', () => {
    const payload = JSON.stringify([baseNotification, { id: 'broken' }]);

    expect(parseNotificationPayload(payload)).toEqual([baseNotification]);
  });
});

class FakeWebSocket {
  static instances: FakeWebSocket[] = [];

  static reset() {
    FakeWebSocket.instances = [];
  }

  onopen: (() => void) | null = null;
  onmessage: ((event: MessageEvent) => void) | null = null;
  onerror: (() => void) | null = null;
  onclose: (() => void) | null = null;

  closed = false;

  constructor(public readonly url: string) {
    FakeWebSocket.instances.push(this);
  }

  close() {
    this.closed = true;
  }

  emitOpen() {
    this.onopen?.();
  }

  emitMessage(data: string) {
    this.onmessage?.({ data } as MessageEvent);
  }

  emitClose() {
    this.onclose?.();
  }
}

const WebSocketImpl = FakeWebSocket as unknown as typeof WebSocket;

function createStream(overrides: Partial<ConstructorParameters<typeof NotificationStream>[0]> = {}) {
  const onNotification = jest.fn();
  const onStatusChange = jest.fn();

  const stream = new NotificationStream({
    url: 'wss://example.com/notifications',
    onNotification,
    onStatusChange,
    webSocketImpl: WebSocketImpl,
    initialRetryDelayMs: 1000,
    maxRetryDelayMs: 4000,
    ...overrides,
  });

  return { stream, onNotification, onStatusChange };
}

describe('NotificationStream', () => {
  beforeEach(() => {
    FakeWebSocket.reset();
    jest.useFakeTimers();
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  it('connects and reports the open status', () => {
    const { stream, onStatusChange } = createStream();

    stream.connect();
    expect(FakeWebSocket.instances).toHaveLength(1);
    expect(onStatusChange).toHaveBeenLastCalledWith('connecting');

    FakeWebSocket.instances[0].emitOpen();

    expect(onStatusChange).toHaveBeenLastCalledWith('open');
    expect(stream.status).toBe('open');
  });

  it('forwards every notification in a frame', () => {
    const { stream, onNotification } = createStream();
    stream.connect();

    FakeWebSocket.instances[0].emitMessage(JSON.stringify([baseNotification, { ...baseNotification, id: 'ntf-2' }]));

    expect(onNotification).toHaveBeenCalledTimes(2);
    expect(onNotification).toHaveBeenCalledWith(baseNotification);
  });

  it('ignores unparseable frames without throwing', () => {
    const { stream, onNotification } = createStream();
    stream.connect();

    expect(() => FakeWebSocket.instances[0].emitMessage('not-json')).not.toThrow();
    expect(onNotification).not.toHaveBeenCalled();
  });

  it('reconnects with backoff after an unexpected close', () => {
    const { stream, onStatusChange } = createStream();
    stream.connect();
    FakeWebSocket.instances[0].emitOpen();

    FakeWebSocket.instances[0].emitClose();
    expect(onStatusChange).toHaveBeenLastCalledWith('closed');
    expect(FakeWebSocket.instances).toHaveLength(1);

    jest.advanceTimersByTime(1000);
    expect(FakeWebSocket.instances).toHaveLength(2);

    // The next failure waits twice as long.
    FakeWebSocket.instances[1].emitClose();
    jest.advanceTimersByTime(1999);
    expect(FakeWebSocket.instances).toHaveLength(2);
    jest.advanceTimersByTime(1);
    expect(FakeWebSocket.instances).toHaveLength(3);
  });

  it('does not reconnect after an explicit close', () => {
    const { stream, onStatusChange } = createStream();
    stream.connect();
    FakeWebSocket.instances[0].emitOpen();

    stream.close();
    expect(stream.status).toBe('idle');
    expect(onStatusChange).toHaveBeenLastCalledWith('idle');
    expect(FakeWebSocket.instances[0].closed).toBe(true);

    jest.advanceTimersByTime(60_000);
    expect(FakeWebSocket.instances).toHaveLength(1);
  });

  it('reports an error when the runtime has no WebSocket support', () => {
    const original = globalThis.WebSocket;
    // Simulate a runtime (React Native, older embedded webview) without WebSocket.
    // @ts-expect-error deliberately unset the global
    globalThis.WebSocket = undefined;

    try {
      const { stream, onStatusChange } = createStream({
        webSocketImpl: undefined as unknown as typeof WebSocket,
      });
      stream.connect();

      expect(stream.status).toBe('error');
      expect(onStatusChange).toHaveBeenLastCalledWith('error');
      expect(FakeWebSocket.instances).toHaveLength(0);
    } finally {
      globalThis.WebSocket = original;
    }
  });

  it('recovers when the constructor throws', () => {
    const ThrowingWebSocket = function ThrowingWebSocket() {
      throw new Error('blocked');
    } as unknown as typeof WebSocket;

    const { stream } = createStream({ webSocketImpl: ThrowingWebSocket });

    expect(() => stream.connect()).not.toThrow();
    expect(stream.status).toBe('connecting');
  });
});
