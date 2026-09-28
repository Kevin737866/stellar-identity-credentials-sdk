import React from 'react';
import {
  CredentialNotification,
  NOTIFICATION_PRESENTATION,
  NOTIFICATION_TONES,
  formatRelativeTime,
} from '../types/notifications';

export interface NotificationRowProps {
  notification: CredentialNotification;
  onActivate: (notification: CredentialNotification) => void;
}

/**
 * A single notification entry. Rendered as a button so the whole row is a
 * touch-friendly, keyboard-accessible target that navigates to the credential
 * it refers to.
 */
export const NotificationRow: React.FC<NotificationRowProps> = ({
  notification,
  onActivate,
}) => {
  const presentation = NOTIFICATION_PRESENTATION[notification.type];

  return (
    <li>
      <button
        type="button"
        onClick={() => onActivate(notification)}
        style={{
          display: 'block',
          width: '100%',
          minHeight: 'var(--touch-target-min)',
          padding: 'var(--space-3)',
          border: 'none',
          borderBottom: '1px solid var(--color-border)',
          background: notification.read ? 'transparent' : 'var(--color-primary-50)',
          textAlign: 'left',
          cursor: 'pointer',
          fontFamily: 'var(--font-family)',
          color: 'var(--color-text)',
        }}
      >
        <span
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 'var(--space-2)',
            fontSize: 'var(--font-size-xs)',
            color: NOTIFICATION_TONES[presentation.tone],
            fontWeight: 'var(--font-weight-semibold)' as never,
          }}
        >
          {notification.read ? null : (
            <span
              data-testid="notification-unread-dot"
              aria-hidden="true"
              style={{
                width: '8px',
                height: '8px',
                flexShrink: 0,
                borderRadius: 'var(--radius-full)',
                backgroundColor: 'var(--color-primary-600)',
              }}
            />
          )}
          {presentation.label}
        </span>

        <span
          style={{
            display: 'block',
            marginTop: 'var(--space-1)',
            fontSize: 'var(--font-size-sm)',
            fontWeight: (notification.read
              ? 'var(--font-weight-normal)'
              : 'var(--font-weight-medium)') as never,
          }}
        >
          {notification.title}
        </span>

        {notification.message ? (
          <span
            style={{
              display: 'block',
              fontSize: 'var(--font-size-xs)',
              color: 'var(--color-text-secondary)',
            }}
          >
            {notification.message}
          </span>
        ) : null}

        <span
          style={{
            display: 'block',
            marginTop: 'var(--space-1)',
            fontSize: 'var(--font-size-xs)',
            color: 'var(--color-text-secondary)',
          }}
        >
          {formatRelativeTime(notification.createdAt)}
        </span>
      </button>
    </li>
  );
};
