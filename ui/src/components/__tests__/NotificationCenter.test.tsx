import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import { CredentialNotification } from '../../types/notifications';
import { NotificationCenter } from '../NotificationCenter';

function makeNotification(
  overrides: Partial<CredentialNotification> = {}
): CredentialNotification {
  return {
    id: 'ntf-1',
    type: 'credential-issued',
    title: 'KYC credential issued',
    message: 'Issued by Verified Identity Inc.',
    credentialId: 'cred-1',
    createdAt: Date.now(),
    read: false,
    ...overrides,
  };
}

const unread = makeNotification({ id: 'ntf-1' });
const secondUnread = makeNotification({ id: 'ntf-2', type: 'offer-received', title: 'New offer' });
const read = makeNotification({ id: 'ntf-3', type: 'credential-verified', read: true });

describe('NotificationCenter', () => {
  it('renders a bell with no badge when everything is read', () => {
    render(<NotificationCenter notifications={[read]} />);

    expect(screen.getByRole('button', { name: 'Notifications' })).toBeInTheDocument();
    expect(screen.queryByTestId('notification-badge')).not.toBeInTheDocument();
  });

  it('shows the unread count in the badge and the accessible name', () => {
    render(<NotificationCenter notifications={[unread, secondUnread, read]} />);

    expect(screen.getByTestId('notification-badge')).toHaveTextContent('2');
    expect(screen.getByRole('button', { name: 'Notifications, 2 unread' })).toBeInTheDocument();
  });

  it('caps the badge at 9+', () => {
    const many = Array.from({ length: 12 }, (_, index) =>
      makeNotification({ id: `ntf-${index}` })
    );

    render(<NotificationCenter notifications={many} />);

    expect(screen.getByTestId('notification-badge')).toHaveTextContent('9+');
  });

  it('honours an explicit unreadCount override', () => {
    render(<NotificationCenter notifications={[read]} unreadCount={4} />);

    expect(screen.getByTestId('notification-badge')).toHaveTextContent('4');
  });

  it('opens the panel when the bell is pressed', () => {
    render(<NotificationCenter notifications={[unread]} />);

    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /notifications/i }));

    expect(screen.getByRole('dialog', { name: 'Notifications' })).toBeInTheDocument();
    expect(screen.getByText('KYC credential issued')).toBeInTheDocument();
  });

  it('can start open', () => {
    render(<NotificationCenter notifications={[unread]} defaultOpen />);

    expect(screen.getByRole('dialog')).toBeInTheDocument();
  });

  it('reports open state changes to a controlled parent', () => {
    const onOpenChange = jest.fn();
    render(
      <NotificationCenter notifications={[unread]} open={false} onOpenChange={onOpenChange} />
    );

    fireEvent.click(screen.getByRole('button', { name: /notifications/i }));

    expect(onOpenChange).toHaveBeenCalledWith(true);
    // A controlled component must not open itself.
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });

  it('shows the empty state when there is nothing to report', () => {
    render(<NotificationCenter notifications={[]} defaultOpen emptyMessage="All caught up" />);

    expect(screen.getByText('All caught up')).toBeInTheDocument();
  });

  it('marks a notification read and asks the parent to navigate on selection', () => {
    const onMarkAsRead = jest.fn();
    const onSelect = jest.fn();
    render(
      <NotificationCenter
        notifications={[unread]}
        defaultOpen
        onMarkAsRead={onMarkAsRead}
        onSelect={onSelect}
      />
    );

    fireEvent.click(screen.getByText('KYC credential issued'));

    expect(onMarkAsRead).toHaveBeenCalledWith('ntf-1');
    expect(onSelect).toHaveBeenCalledWith(unread);
  });

  it('carries the credential id so the caller can navigate to it', () => {
    const onSelect = jest.fn();
    render(<NotificationCenter notifications={[unread]} defaultOpen onSelect={onSelect} />);

    fireEvent.click(screen.getByText('KYC credential issued'));

    expect(onSelect.mock.calls[0][0].credentialId).toBe('cred-1');
  });

  it('labels each event with its lifecycle description', () => {
    render(
      <NotificationCenter
        notifications={[
          makeNotification({ id: 'a', type: 'credential-revoked' }),
          makeNotification({ id: 'b', type: 'credential-expiring' }),
        ]}
        defaultOpen
      />
    );

    expect(screen.getByText('Credential revoked')).toBeInTheDocument();
    expect(screen.getByText('Credential expiring soon')).toBeInTheDocument();
  });

  it('renders an unread indicator only for unread notifications', () => {
    render(<NotificationCenter notifications={[unread, read]} defaultOpen />);

    expect(screen.getAllByTestId('notification-unread-dot')).toHaveLength(1);
  });

  it('disables "mark all as read" when there is nothing unread', () => {
    render(<NotificationCenter notifications={[read]} defaultOpen onMarkAllAsRead={jest.fn()} />);

    expect(screen.getByRole('button', { name: /mark all as read/i })).toBeDisabled();
  });

  it('marks everything as read through the footer action', () => {
    const onMarkAllAsRead = jest.fn();
    render(
      <NotificationCenter
        notifications={[unread, secondUnread]}
        defaultOpen
        onMarkAllAsRead={onMarkAllAsRead}
      />
    );

    fireEvent.click(screen.getByRole('button', { name: /mark all as read/i }));

    expect(onMarkAllAsRead).toHaveBeenCalledTimes(1);
  });

  it('offers a clear-all action only when a handler is provided', () => {
    const onClearAll = jest.fn();
    const { unmount } = render(<NotificationCenter notifications={[unread]} defaultOpen />);

    expect(screen.queryByRole('button', { name: /clear all/i })).not.toBeInTheDocument();
    unmount();

    render(
      <NotificationCenter notifications={[unread]} defaultOpen onClearAll={onClearAll} />
    );
    fireEvent.click(screen.getByRole('button', { name: /clear all/i }));

    expect(onClearAll).toHaveBeenCalledTimes(1);
  });

  it('closes on Escape', () => {
    render(<NotificationCenter notifications={[unread]} defaultOpen />);

    fireEvent.keyDown(document, { key: 'Escape' });

    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });

  it('closes when the user interacts outside the panel', () => {
    render(<NotificationCenter notifications={[unread]} defaultOpen />);

    fireEvent.mouseDown(document.body);

    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });

  it('surfaces the real-time feed status', () => {
    render(<NotificationCenter notifications={[unread]} defaultOpen status="open" />);

    expect(screen.getByRole('status')).toHaveTextContent('Live');
  });

  it('limits how many notifications are rendered', () => {
    const many = Array.from({ length: 5 }, (_, index) =>
      makeNotification({ id: `ntf-${index}`, title: `Notification ${index}` })
    );

    render(<NotificationCenter notifications={many} defaultOpen maxVisible={2} />);

    expect(screen.getAllByTestId('notification-unread-dot')).toHaveLength(2);
  });
});
