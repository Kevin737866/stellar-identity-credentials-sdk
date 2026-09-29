import {
  CredentialNotification,
  formatRelativeTime,
  isCredentialNotification,
  toCredentialNotification,
} from '../notifications';

const validNotification: CredentialNotification = {
  id: 'ntf-1',
  type: 'credential-issued',
  title: 'KYC credential issued',
  message: 'Issued by Verified Identity Inc.',
  credentialId: 'cred-1',
  createdAt: 1_700_000_000_000,
  read: false,
};

describe('isCredentialNotification', () => {
  it('accepts a well-formed notification', () => {
    expect(isCredentialNotification(validNotification)).toBe(true);
  });

  it('accepts a notification without the optional fields', () => {
    expect(
      isCredentialNotification({ id: 'ntf-2', type: 'offer-received', title: 'Offer', createdAt: 1 })
    ).toBe(true);
  });

  it.each([
    ['null', null],
    ['a string', 'credential-issued'],
    ['an empty id', { ...validNotification, id: '' }],
    ['an unknown type', { ...validNotification, type: 'credential-exploded' }],
    ['a non-string title', { ...validNotification, title: 42 }],
    ['a non-numeric createdAt', { ...validNotification, createdAt: 'yesterday' }],
    ['a non-finite createdAt', { ...validNotification, createdAt: Number.NaN }],
    ['a non-string message', { ...validNotification, message: 7 }],
    ['a non-boolean read', { ...validNotification, read: 'yes' }],
  ])('rejects %s', (_label, value) => {
    expect(isCredentialNotification(value)).toBe(false);
  });

  it('covers every credential lifecycle event required by the notification center', () => {
    const types = [
      'credential-issued',
      'credential-verified',
      'credential-revoked',
      'credential-expiring',
      'offer-received',
    ];

    types.forEach((type) => {
      expect(isCredentialNotification({ ...validNotification, type })).toBe(true);
    });
  });
});

describe('toCredentialNotification', () => {
  it('normalises an incoming payload and defaults read to false', () => {
    const result = toCredentialNotification(
      { id: 'ntf-3', type: 'credential-revoked', title: 'Revoked', createdAt: 5 },
      999
    );

    expect(result).toEqual({
      id: 'ntf-3',
      type: 'credential-revoked',
      title: 'Revoked',
      createdAt: 5,
      read: false,
    });
  });

  it('returns null for payloads that do not validate', () => {
    expect(toCredentialNotification({ id: 'nope' })).toBeNull();
    expect(toCredentialNotification(undefined)).toBeNull();
  });
});

describe('formatRelativeTime', () => {
  const now = 1_700_000_000_000;

  it('reports very recent events as "just now"', () => {
    expect(formatRelativeTime(now, now)).toBe('just now');
    expect(formatRelativeTime(now - 30_000, now)).toBe('just now');
  });

  it.each([
    [60_000, '1m ago'],
    [5 * 60_000, '5m ago'],
    [3 * 60 * 60_000, '3h ago'],
    [2 * 24 * 60 * 60_000, '2d ago'],
    [14 * 24 * 60 * 60_000, '2w ago'],
  ])('formats %i ms ago as %s', (elapsed, expected) => {
    expect(formatRelativeTime(now - elapsed, now)).toBe(expected);
  });

  it('never renders a negative age', () => {
    expect(formatRelativeTime(now + 10_000, now)).toBe('just now');
  });
});
