/** Credential lifecycle events surfaced in the notification center. */
export type CredentialNotificationType =
  | 'credential-issued'
  | 'credential-verified'
  | 'credential-revoked'
  | 'credential-expiring'
  | 'offer-received';

export interface CredentialNotification {
  id: string;
  type: CredentialNotificationType;
  title: string;
  /** Optional secondary line describing the event. */
  message?: string;
  /** Credential this event refers to, used to navigate on selection. */
  credentialId?: string;
  /** Epoch milliseconds. */
  createdAt: number;
  read: boolean;
}

export type NotificationTone = 'success' | 'danger' | 'warning' | 'info' | 'neutral';

export interface NotificationPresentation {
  /** Human-readable event name. */
  label: string;
  tone: NotificationTone;
}

export const NOTIFICATION_PRESENTATION: Record<
  CredentialNotificationType,
  NotificationPresentation
> = {
  'credential-issued': { label: 'Credential issued', tone: 'success' },
  'credential-verified': { label: 'Credential verified', tone: 'info' },
  'credential-revoked': { label: 'Credential revoked', tone: 'danger' },
  'credential-expiring': { label: 'Credential expiring soon', tone: 'warning' },
  'offer-received': { label: 'Credential offer received', tone: 'info' },
};

export const NOTIFICATION_TONES: Record<NotificationTone, string> = {
  success: 'var(--color-success-600)',
  danger: 'var(--color-danger-600)',
  warning: 'var(--color-warning-600)',
  info: 'var(--color-info-600)',
  neutral: 'var(--color-text-secondary)',
};

const VALID_TYPES = Object.keys(NOTIFICATION_PRESENTATION) as CredentialNotificationType[];

function isNotificationType(value: unknown): value is CredentialNotificationType {
  return typeof value === 'string' && (VALID_TYPES as string[]).includes(value);
}

/**
 * Runtime guard for notifications received from an untrusted transport such as
 * a WebSocket feed or `localStorage`.
 */
export function isCredentialNotification(value: unknown): value is CredentialNotification {
  if (!value || typeof value !== 'object') {
    return false;
  }

  const candidate = value as Partial<CredentialNotification>;

  return (
    typeof candidate.id === 'string' &&
    candidate.id.length > 0 &&
    isNotificationType(candidate.type) &&
    typeof candidate.title === 'string' &&
    typeof candidate.createdAt === 'number' &&
    Number.isFinite(candidate.createdAt) &&
    (candidate.read === undefined || typeof candidate.read === 'boolean') &&
    (candidate.message === undefined || typeof candidate.message === 'string') &&
    (candidate.credentialId === undefined || typeof candidate.credentialId === 'string')
  );
}

/**
 * Coerce an untrusted payload into a notification, defaulting `read` to `false`
 * and `createdAt` to the supplied clock when absent.
 */
export function toCredentialNotification(
  value: unknown,
  now: number = Date.now()
): CredentialNotification | null {
  if (!isCredentialNotification(value)) {
    return null;
  }

  return {
    ...value,
    createdAt: Number.isFinite(value.createdAt) ? value.createdAt : now,
    read: value.read ?? false,
  };
}

/** Format a timestamp as a short relative age, e.g. `4m ago`. */
export function formatRelativeTime(timestamp: number, now: number = Date.now()): string {
  const elapsedSeconds = Math.floor((now - timestamp) / 1000);

  if (!Number.isFinite(elapsedSeconds) || elapsedSeconds < 45) {
    return 'just now';
  }

  const units: Array<{ seconds: number; label: string }> = [
    { seconds: 60 * 60 * 24 * 7, label: 'w' },
    { seconds: 60 * 60 * 24, label: 'd' },
    { seconds: 60 * 60, label: 'h' },
    { seconds: 60, label: 'm' },
  ];

  for (const unit of units) {
    if (elapsedSeconds >= unit.seconds) {
      return `${Math.floor(elapsedSeconds / unit.seconds)}${unit.label} ago`;
    }
  }

  return `${elapsedSeconds}s ago`;
}
