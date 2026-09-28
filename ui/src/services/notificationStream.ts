import { CredentialNotification, toCredentialNotification } from '../types/notifications';

export type NotificationStreamStatus = 'idle' | 'connecting' | 'open' | 'closed' | 'error';

export interface NotificationStreamOptions {
  /** WebSocket endpoint that publishes credential events. */
  url: string;
  onNotification: (notification: CredentialNotification) => void;
  onStatusChange?: (status: NotificationStreamStatus) => void;
  /** First reconnect delay; doubles up to `maxRetryDelayMs`. */
  initialRetryDelayMs?: number;
  maxRetryDelayMs?: number;
  /** Injectable for tests and non-browser runtimes. */
  webSocketImpl?: typeof WebSocket;
}

/**
 * Interpret a raw WebSocket frame as zero or more notifications.
 *
 * Accepts a single notification, an array of them, or a `{ notifications: [] }`
 * envelope, as either a JSON string or an already-parsed value. Anything that
 * does not validate is dropped rather than thrown, because the transport is
 * untrusted.
 */
export function parseNotificationPayload(
  data: unknown,
  now: number = Date.now()
): CredentialNotification[] {
  let parsed: unknown = data;

  if (typeof data === 'string') {
    try {
      parsed = JSON.parse(data);
    } catch {
      return [];
    }
  }

  if (Array.isArray(parsed)) {
    return parsed
      .map((item) => toCredentialNotification(item, now))
      .filter((item): item is CredentialNotification => item !== null);
  }

  if (parsed && typeof parsed === 'object' && 'notifications' in parsed) {
    const envelope = (parsed as { notifications?: unknown }).notifications;
    return Array.isArray(envelope)
      ? envelope
          .map((item) => toCredentialNotification(item, now))
          .filter((item): item is CredentialNotification => item !== null)
      : [];
  }

  const single = toCredentialNotification(parsed, now);
  return single ? [single] : [];
}

/**
 * Long-lived WebSocket subscription to the credential event feed.
 *
 * Reconnects with exponential backoff so a dropped connection recovers on its
 * own, and degrades to a no-op when the runtime has no WebSocket support.
 */
export class NotificationStream {
  private socket: WebSocket | null = null;
  private retryTimer: ReturnType<typeof setTimeout> | null = null;
  private retryDelayMs: number;
  private closedByUser = false;
  private currentStatus: NotificationStreamStatus = 'idle';

  constructor(private readonly options: NotificationStreamOptions) {
    this.retryDelayMs = options.initialRetryDelayMs ?? 1000;
  }

  get status(): NotificationStreamStatus {
    return this.currentStatus;
  }

  /** Open the connection. Safe to call again after `close()`. */
  connect(): void {
    const WebSocketImpl = this.options.webSocketImpl ?? globalThis.WebSocket;

    if (typeof WebSocketImpl !== 'function') {
      this.setStatus('error');
      return;
    }

    this.closedByUser = false;
    this.setStatus('connecting');

    try {
      this.socket = new WebSocketImpl(this.options.url);
    } catch {
      this.scheduleReconnect();
      return;
    }

    this.socket.onopen = () => {
      this.retryDelayMs = this.options.initialRetryDelayMs ?? 1000;
      this.setStatus('open');
    };

    this.socket.onmessage = (event: MessageEvent) => {
      for (const notification of parseNotificationPayload(event.data)) {
        this.options.onNotification(notification);
      }
    };

    this.socket.onerror = () => this.setStatus('error');

    this.socket.onclose = () => {
      this.setStatus('closed');
      this.scheduleReconnect();
    };
  }

  /** Close the connection and stop reconnecting. */
  close(): void {
    this.closedByUser = true;

    if (this.retryTimer !== null) {
      clearTimeout(this.retryTimer);
      this.retryTimer = null;
    }

    if (this.socket) {
      // Detach handlers first so the teardown does not schedule a reconnect.
      this.socket.onopen = null;
      this.socket.onmessage = null;
      this.socket.onerror = null;
      this.socket.onclose = null;
      this.socket.close();
      this.socket = null;
    }

    this.setStatus('idle');
  }

  private scheduleReconnect(): void {
    if (this.closedByUser || this.retryTimer !== null) {
      return;
    }

    const maxRetryDelayMs = this.options.maxRetryDelayMs ?? 30000;
    const delay = this.retryDelayMs;

    this.retryTimer = setTimeout(() => {
      this.retryTimer = null;
      this.connect();
    }, delay);

    this.retryDelayMs = Math.min(delay * 2, maxRetryDelayMs);
  }

  private setStatus(status: NotificationStreamStatus): void {
    if (this.currentStatus === status) {
      return;
    }
    this.currentStatus = status;
    this.options.onStatusChange?.(status);
  }
}
