import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  NotificationStream,
  NotificationStreamStatus,
} from '../services/notificationStream';
import { CredentialNotification, toCredentialNotification } from '../types/notifications';

export interface UseNotificationsOptions {
  /** `localStorage` key used to persist notifications. Omit to disable persistence. */
  storageKey?: string;
  /** Maximum notifications retained; oldest are dropped. Default `50`. */
  maxItems?: number;
  /** Seed notifications used when nothing is stored yet. */
  initialNotifications?: CredentialNotification[];
  /** WebSocket endpoint publishing real-time credential events. */
  streamUrl?: string;
  onStatusChange?: (status: NotificationStreamStatus) => void;
  /** Injectable for tests and non-browser runtimes. */
  webSocketImpl?: typeof WebSocket;
}

export interface UseNotificationsResult {
  notifications: CredentialNotification[];
  unreadCount: number;
  status: NotificationStreamStatus;
  addNotification: (notification: CredentialNotification) => void;
  markAsRead: (id: string) => void;
  markAllAsRead: () => void;
  removeNotification: (id: string) => void;
  clearAll: () => void;
}

/** Read persisted notifications, tolerating corrupt or unavailable storage. */
export function readStoredNotifications(
  storageKey: string | undefined
): CredentialNotification[] {
  if (!storageKey || typeof window === 'undefined' || !window.localStorage) {
    return [];
  }

  try {
    const raw = window.localStorage.getItem(storageKey);
    if (!raw) {
      return [];
    }

    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed)) {
      return [];
    }

    return parsed
      .map((item) => toCredentialNotification(item))
      .filter((item): item is CredentialNotification => item !== null);
  } catch {
    return [];
  }
}

/** Persist notifications, ignoring quota and privacy-mode failures. */
export function writeStoredNotifications(
  storageKey: string | undefined,
  notifications: CredentialNotification[]
): void {
  if (!storageKey || typeof window === 'undefined' || !window.localStorage) {
    return;
  }

  try {
    window.localStorage.setItem(storageKey, JSON.stringify(notifications));
  } catch {
    // Storage can be full or blocked entirely (Safari private mode).
  }
}

/** Prepend `incoming`, dropping any previous entry with the same id. */
export function mergeNotification(
  current: CredentialNotification[],
  incoming: CredentialNotification,
  maxItems: number
): CredentialNotification[] {
  return [incoming, ...current.filter((item) => item.id !== incoming.id)].slice(0, maxItems);
}

/**
 * Owns the notification list: persistence, read/unread state and the real-time
 * credential event feed.
 *
 * Reads from `localStorage` on first render, so a server render will not match
 * the first client render when storage is populated; hydrate around this hook
 * when rendering on the server.
 */
export function useNotifications(
  options: UseNotificationsOptions = {}
): UseNotificationsResult {
  const {
    storageKey,
    maxItems = 50,
    initialNotifications,
    streamUrl,
    webSocketImpl,
  } = options;

  const [notifications, setNotifications] = useState<CredentialNotification[]>(() => {
    const stored = readStoredNotifications(storageKey);
    if (stored.length > 0) {
      return stored;
    }
    return (initialNotifications ?? [])
      .map((item) => toCredentialNotification(item))
      .filter((item): item is CredentialNotification => item !== null);
  });

  const [status, setStatus] = useState<NotificationStreamStatus>('idle');

  // Keep the latest callback without re-subscribing the socket on every render.
  const onStatusChangeRef = useRef(options.onStatusChange);
  useEffect(() => {
    onStatusChangeRef.current = options.onStatusChange;
  }, [options.onStatusChange]);

  useEffect(() => {
    writeStoredNotifications(storageKey, notifications);
  }, [storageKey, notifications]);

  useEffect(() => {
    if (!streamUrl) {
      return undefined;
    }

    const stream = new NotificationStream({
      url: streamUrl,
      webSocketImpl,
      onNotification: (notification) =>
        setNotifications((prev) => mergeNotification(prev, notification, maxItems)),
      onStatusChange: (next) => {
        setStatus(next);
        onStatusChangeRef.current?.(next);
      },
    });

    stream.connect();
    return () => stream.close();
  }, [streamUrl, maxItems, webSocketImpl]);

  const addNotification = useCallback(
    (notification: CredentialNotification) => {
      setNotifications((prev) =>
        mergeNotification(prev, { ...notification, read: notification.read ?? false }, maxItems)
      );
    },
    [maxItems]
  );

  const markAsRead = useCallback((id: string) => {
    setNotifications((prev) =>
      prev.map((item) => (item.id === id ? { ...item, read: true } : item))
    );
  }, []);

  const markAllAsRead = useCallback(() => {
    setNotifications((prev) =>
      prev.every((item) => item.read) ? prev : prev.map((item) => ({ ...item, read: true }))
    );
  }, []);

  const removeNotification = useCallback((id: string) => {
    setNotifications((prev) => prev.filter((item) => item.id !== id));
  }, []);

  const clearAll = useCallback(() => setNotifications([]), []);

  const unreadCount = useMemo(
    () => notifications.reduce((total, item) => (item.read ? total : total + 1), 0),
    [notifications]
  );

  return {
    notifications,
    unreadCount,
    status,
    addNotification,
    markAsRead,
    markAllAsRead,
    removeNotification,
    clearAll,
  };
}
