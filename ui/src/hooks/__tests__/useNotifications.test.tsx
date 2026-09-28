import { act, renderHook } from '@testing-library/react';
import { CredentialNotification } from '../../types/notifications';
import {
  mergeNotification,
  readStoredNotifications,
  useNotifications,
  writeStoredNotifications,
} from '../useNotifications';

const STORAGE_KEY = 'stellar-identity.test.notifications';

function makeNotification(
  overrides: Partial<CredentialNotification> = {}
): CredentialNotification {
  return {
    id: 'ntf-1',
    type: 'credential-issued',
    title: 'KYC credential issued',
    createdAt: 1_700_000_000_000,
    read: false,
    ...overrides,
  };
}

class FakeWebSocket {
  static instances: FakeWebSocket[] = [];

  onopen: (() => void) | null = null;
  onmessage: ((event: MessageEvent) => void) | null = null;
  onerror: (() => void) | null = null;
  onclose: (() => void) | null = null;

  constructor(public readonly url: string) {
    FakeWebSocket.instances.push(this);
  }

  close() {}

  emitMessage(data: string) {
    this.onmessage?.({ data } as MessageEvent);
  }
}

beforeEach(() => {
  window.localStorage.clear();
  FakeWebSocket.instances = [];
});

describe('mergeNotification', () => {
  it('prepends the new notification', () => {
    const existing = makeNotification({ id: 'ntf-old' });
    const incoming = makeNotification({ id: 'ntf-new' });

    expect(mergeNotification([existing], incoming, 10).map((n) => n.id)).toEqual([
      'ntf-new',
      'ntf-old',
    ]);
  });

  it('replaces an existing notification with the same id', () => {
    const existing = makeNotification({ id: 'ntf-1', title: 'Old title' });
    const incoming = makeNotification({ id: 'ntf-1', title: 'New title' });

    const merged = mergeNotification([existing], incoming, 10);

    expect(merged).toHaveLength(1);
    expect(merged[0].title).toBe('New title');
  });

  it('drops the oldest entry beyond maxItems', () => {
    const existing = [
      makeNotification({ id: 'a' }),
      makeNotification({ id: 'b' }),
    ];

    expect(mergeNotification(existing, makeNotification({ id: 'c' }), 2).map((n) => n.id)).toEqual([
      'c',
      'a',
    ]);
  });
});

describe('storage helpers', () => {
  it('round-trips notifications', () => {
    writeStoredNotifications(STORAGE_KEY, [makeNotification()]);

    expect(readStoredNotifications(STORAGE_KEY)).toEqual([makeNotification()]);
  });

  it('returns nothing when there is no key or no stored value', () => {
    expect(readStoredNotifications(undefined)).toEqual([]);
    expect(readStoredNotifications('missing-key')).toEqual([]);
  });

  it('ignores corrupt stored data', () => {
    window.localStorage.setItem(STORAGE_KEY, 'not-json');
    expect(readStoredNotifications(STORAGE_KEY)).toEqual([]);

    window.localStorage.setItem(STORAGE_KEY, JSON.stringify({ not: 'an array' }));
    expect(readStoredNotifications(STORAGE_KEY)).toEqual([]);
  });

  it('drops entries that no longer validate', () => {
    window.localStorage.setItem(
      STORAGE_KEY,
      JSON.stringify([makeNotification(), { id: 'broken' }])
    );

    expect(readStoredNotifications(STORAGE_KEY)).toEqual([makeNotification()]);
  });
});

describe('useNotifications', () => {
  it('starts empty and reports no unread notifications', () => {
    const { result } = renderHook(() => useNotifications());

    expect(result.current.notifications).toEqual([]);
    expect(result.current.unreadCount).toBe(0);
    expect(result.current.status).toBe('idle');
  });

  it('seeds from initialNotifications when storage is empty', () => {
    const { result } = renderHook(() =>
      useNotifications({ initialNotifications: [makeNotification({ read: true })] })
    );

    expect(result.current.notifications).toHaveLength(1);
    expect(result.current.unreadCount).toBe(0);
  });

  it('tracks the unread count and marks a notification as read', () => {
    const { result } = renderHook(() => useNotifications({ storageKey: STORAGE_KEY }));

    act(() => result.current.addNotification(makeNotification()));
    act(() => result.current.addNotification(makeNotification({ id: 'ntf-2' })));

    expect(result.current.unreadCount).toBe(2);

    act(() => result.current.markAsRead('ntf-1'));

    expect(result.current.unreadCount).toBe(1);
    expect(result.current.notifications[1].read).toBe(true);
  });

  it('marks every notification as read at once', () => {
    const { result } = renderHook(() => useNotifications({ storageKey: STORAGE_KEY }));

    act(() => result.current.addNotification(makeNotification()));
    act(() => result.current.addNotification(makeNotification({ id: 'ntf-2' })));
    act(() => result.current.markAllAsRead());

    expect(result.current.unreadCount).toBe(0);
    expect(result.current.notifications.every((n) => n.read)).toBe(true);
  });

  it('removes a single notification and clears the list', () => {
    const { result } = renderHook(() => useNotifications({ storageKey: STORAGE_KEY }));

    act(() => result.current.addNotification(makeNotification()));
    act(() => result.current.addNotification(makeNotification({ id: 'ntf-2' })));
    act(() => result.current.removeNotification('ntf-1'));

    expect(result.current.notifications.map((n) => n.id)).toEqual(['ntf-2']);

    act(() => result.current.clearAll());
    expect(result.current.notifications).toEqual([]);
  });

  it('keeps at most maxItems notifications, newest first', () => {
    const { result } = renderHook(() =>
      useNotifications({ storageKey: STORAGE_KEY, maxItems: 2 })
    );

    act(() => result.current.addNotification(makeNotification({ id: 'a' })));
    act(() => result.current.addNotification(makeNotification({ id: 'b' })));
    act(() => result.current.addNotification(makeNotification({ id: 'c' })));

    expect(result.current.notifications.map((n) => n.id)).toEqual(['c', 'b']);
  });

  it('persists notifications and restores them on the next mount', () => {
    const first = renderHook(() => useNotifications({ storageKey: STORAGE_KEY }));

    act(() => first.result.current.markAsRead('ntf-1'));
    act(() => first.result.current.addNotification(makeNotification()));
    act(() => first.result.current.markAllAsRead());
    first.unmount();

    const second = renderHook(() => useNotifications({ storageKey: STORAGE_KEY }));

    expect(second.result.current.notifications).toHaveLength(1);
    expect(second.result.current.unreadCount).toBe(0);
  });

  it('does not persist when no storageKey is given', () => {
    const { result } = renderHook(() => useNotifications());

    act(() => result.current.addNotification(makeNotification()));

    expect(window.localStorage.length).toBe(0);
  });

  it('adds notifications pushed over the real-time feed', () => {
    const { result } = renderHook(() =>
      useNotifications({
        storageKey: STORAGE_KEY,
        streamUrl: 'wss://example.com/notifications',
        webSocketImpl: FakeWebSocket as unknown as typeof WebSocket,
      })
    );

    expect(FakeWebSocket.instances).toHaveLength(1);
    expect(FakeWebSocket.instances[0].url).toBe('wss://example.com/notifications');

    act(() => {
      FakeWebSocket.instances[0].emitMessage(JSON.stringify(makeNotification({ id: 'live-1' })));
    });

    expect(result.current.notifications).toHaveLength(1);
    expect(result.current.notifications[0].id).toBe('live-1');
    expect(result.current.unreadCount).toBe(1);
  });

  it('does not open a socket when no streamUrl is configured', () => {
    renderHook(() => useNotifications({ storageKey: STORAGE_KEY }));

    expect(FakeWebSocket.instances).toHaveLength(0);
  });
});
