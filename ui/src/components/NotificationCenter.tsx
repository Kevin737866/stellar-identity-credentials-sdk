import React, { useCallback, useEffect, useId, useRef, useState } from 'react';
import type { NotificationStreamStatus } from '../services/notificationStream';
import { CredentialNotification } from '../types/notifications';
import { BellIcon } from './icons/BellIcon';
import { NotificationRow } from './NotificationRow';

export interface NotificationCenterProps {
  notifications: CredentialNotification[];
  /** Overrides the computed unread count when state is owned elsewhere. */
  unreadCount?: number;
  /** Controlled open state. Omit to let the component manage it. */
  open?: boolean;
  defaultOpen?: boolean;
  onOpenChange?: (open: boolean) => void;
  onMarkAsRead?: (id: string) => void;
  onMarkAllAsRead?: () => void;
  /** Fired when a notification is activated; use it to navigate to the credential. */
  onSelect?: (notification: CredentialNotification) => void;
  onClearAll?: () => void;
  /** Real-time feed status, surfaced as a live indicator. */
  status?: NotificationStreamStatus;
  title?: string;
  emptyMessage?: string;
  /** Maximum notifications rendered in the panel. Default `10`. */
  maxVisible?: number;
}

const STATUS_LABELS: Record<NotificationStreamStatus, string> = {
  idle: 'Inactive',
  connecting: 'Connecting…',
  open: 'Live',
  closed: 'Disconnected',
  error: 'Unavailable',
};

const footerButtonStyle = (enabled: boolean, accent: boolean): React.CSSProperties => ({
  flex: 1,
  minHeight: 'var(--touch-target-min)',
  border: 'none',
  borderRadius: 'var(--radius-md)',
  background: 'transparent',
  color: accent ? 'var(--color-primary-600)' : 'var(--color-text-secondary)',
  cursor: enabled ? 'pointer' : 'not-allowed',
  fontFamily: 'var(--font-family)',
  fontSize: 'var(--font-size-sm)',
});

/**
 * Bell button with an unread badge that opens a panel of credential events.
 *
 * Fully controlled: pass the output of `useNotifications` to wire it up, or
 * drive it from your own store. The component never mutates the list itself —
 * it reports intent through `onMarkAsRead`, `onMarkAllAsRead` and `onSelect`.
 */
export const NotificationCenter: React.FC<NotificationCenterProps> = ({
  notifications,
  unreadCount,
  open,
  defaultOpen = false,
  onOpenChange,
  onMarkAsRead,
  onMarkAllAsRead,
  onSelect,
  onClearAll,
  status,
  title = 'Notifications',
  emptyMessage = 'No notifications yet',
  maxVisible = 10,
}) => {
  const [uncontrolledOpen, setUncontrolledOpen] = useState(defaultOpen);
  const containerRef = useRef<HTMLDivElement>(null);
  const panelId = useId();

  const isControlled = open !== undefined;
  const isOpen = isControlled ? open : uncontrolledOpen;
  const unread = unreadCount ?? notifications.filter((item) => !item.read).length;

  const setOpen = useCallback(
    (next: boolean) => {
      if (!isControlled) {
        setUncontrolledOpen(next);
      }
      onOpenChange?.(next);
    },
    [isControlled, onOpenChange]
  );

  // Dismiss on outside interaction and on Escape, as expected of a popover.
  useEffect(() => {
    if (!isOpen) {
      return undefined;
    }

    const handlePointerDown = (event: MouseEvent | TouchEvent) => {
      if (containerRef.current && !containerRef.current.contains(event.target as Node)) {
        setOpen(false);
      }
    };
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setOpen(false);
      }
    };

    document.addEventListener('mousedown', handlePointerDown);
    document.addEventListener('touchstart', handlePointerDown);
    document.addEventListener('keydown', handleKeyDown);

    return () => {
      document.removeEventListener('mousedown', handlePointerDown);
      document.removeEventListener('touchstart', handlePointerDown);
      document.removeEventListener('keydown', handleKeyDown);
    };
  }, [isOpen, setOpen]);

  const handleActivate = useCallback(
    (notification: CredentialNotification) => {
      onMarkAsRead?.(notification.id);
      onSelect?.(notification);
    },
    [onMarkAsRead, onSelect]
  );

  const visible = notifications.slice(0, maxVisible);
  const unreadIsZero = unread === 0;

  return (
    <div ref={containerRef} style={{ position: 'relative', fontFamily: 'var(--font-family)' }}>
      <button
        type="button"
        onClick={() => setOpen(!isOpen)}
        aria-label={unread > 0 ? `${title}, ${unread} unread` : title}
        aria-haspopup="dialog"
        aria-expanded={isOpen}
        aria-controls={isOpen ? panelId : undefined}
        style={{
          position: 'relative',
          display: 'inline-flex',
          alignItems: 'center',
          justifyContent: 'center',
          minWidth: 'var(--touch-target-min)',
          minHeight: 'var(--touch-target-min)',
          padding: 'var(--space-2)',
          border: 'none',
          borderRadius: 'var(--radius-md)',
          background: 'transparent',
          color: 'var(--color-text)',
          cursor: 'pointer',
        }}
      >
        <BellIcon />
        {unreadIsZero ? null : (
          <span
            data-testid="notification-badge"
            style={{
              position: 'absolute',
              top: '2px',
              right: '2px',
              minWidth: '18px',
              height: '18px',
              padding: '0 4px',
              borderRadius: 'var(--radius-full)',
              backgroundColor: 'var(--color-danger-600)',
              color: '#ffffff',
              fontSize: '10px',
              lineHeight: '18px',
              fontWeight: 'var(--font-weight-semibold)' as never,
            }}
          >
            {unread > 9 ? '9+' : unread}
          </span>
        )}
      </button>

      {isOpen ? (
        <div
          id={panelId}
          role="dialog"
          aria-label={title}
          style={{
            position: 'absolute',
            top: 'calc(100% + var(--space-2))',
            right: 0,
            zIndex: 50,
            width: 'min(360px, calc(100vw - var(--space-8)))',
            maxHeight: '60vh',
            overflowY: 'auto',
            backgroundColor: 'var(--color-bg)',
            border: '1px solid var(--color-border)',
            borderRadius: 'var(--radius-lg)',
            boxShadow: 'var(--shadow-xl)',
          }}
        >
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              gap: 'var(--space-2)',
              padding: 'var(--space-3)',
              borderBottom: '1px solid var(--color-border)',
            }}
          >
            <span style={{ fontWeight: 'var(--font-weight-semibold)' as never }}>{title}</span>
            {status ? (
              <span
                role="status"
                aria-live="polite"
                style={{
                  fontSize: 'var(--font-size-xs)',
                  color:
                    status === 'open'
                      ? 'var(--color-success-600)'
                      : 'var(--color-text-secondary)',
                }}
              >
                {STATUS_LABELS[status]}
              </span>
            ) : null}
          </div>

          {visible.length === 0 ? (
            <p
              role="status"
              style={{
                margin: 0,
                padding: 'var(--space-6) var(--space-3)',
                textAlign: 'center',
                fontSize: 'var(--font-size-sm)',
                color: 'var(--color-text-secondary)',
              }}
            >
              {emptyMessage}
            </p>
          ) : (
            <ul style={{ listStyle: 'none', margin: 0, padding: 0 }}>
              {visible.map((notification) => (
                <NotificationRow
                  key={notification.id}
                  notification={notification}
                  onActivate={handleActivate}
                />
              ))}
            </ul>
          )}

          <div
            style={{
              display: 'flex',
              gap: 'var(--space-2)',
              padding: 'var(--space-2) var(--space-3)',
              borderTop: '1px solid var(--color-border)',
            }}
          >
            <button
              type="button"
              onClick={onMarkAllAsRead}
              disabled={unreadIsZero || !onMarkAllAsRead}
              style={footerButtonStyle(!unreadIsZero && Boolean(onMarkAllAsRead), !unreadIsZero)}
            >
              Mark all as read
            </button>
            {onClearAll ? (
              <button
                type="button"
                onClick={onClearAll}
                style={footerButtonStyle(true, false)}
              >
                Clear all
              </button>
            ) : null}
          </div>
        </div>
      ) : null}
    </div>
  );
};
