import React from 'react';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { axe } from 'jest-axe';
import { CredentialDetail, flattenAttributes, buildExportPayload, CredentialHistoryEntry } from '@/components/CredentialDetail';
import { VerifiableCredential, CredentialVerificationResult } from '@stellar-identity/sdk';

const credential: VerifiableCredential = {
  id: 'cred-1',
  issuer: 'GISSUER1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  subject: 'GSUBJECT1234567890ABCDEFGHIJKLMNOPQRS',
  type: ['KYCVerification', 'VerifiableCredential'],
  credentialData: {
    firstName: 'Ada',
    lastName: 'Lovelace',
    address: { city: 'London', postcode: 'NW1' },
    tags: ['founder', 'eng'],
  },
  issuanceDate: 1_700_000_000_000,
  expirationDate: 1_800_000_000_000,
  proof: 'deadbeef',
} as VerifiableCredential;

const verification: CredentialVerificationResult = {
  valid: true,
  revoked: false,
  expired: false,
  issuer: credential.issuer,
  subject: credential.subject,
  issuanceDate: credential.issuanceDate,
  expirationDate: credential.expirationDate,
} as CredentialVerificationResult;

describe('flattenAttributes', () => {
  it('flattens a flat object', () => {
    expect(flattenAttributes({ a: 1, b: 'two' })).toEqual([
      { path: 'a', value: '1' },
      { path: 'b', value: 'two' },
    ]);
  });

  it('flattens nested objects with dot paths', () => {
    expect(flattenAttributes({ user: { name: 'Ada' } })).toEqual([
      { path: 'user.name', value: 'Ada' },
    ]);
  });

  it('flattens arrays with bracket indices', () => {
    expect(flattenAttributes({ tags: ['a', 'b'] })).toEqual([
      { path: 'tags[0]', value: 'a' },
      { path: 'tags[1]', value: 'b' },
    ]);
  });

  it('handles an empty array', () => {
    expect(flattenAttributes({ tags: [] })).toEqual([{ path: 'tags', value: '[]' }]);
  });

  it('handles deeply nested structures', () => {
    expect(flattenAttributes({ a: { b: { c: { d: 1 } } } })).toEqual([
      { path: 'a.b.c.d', value: '1' },
    ]);
  });

  it('returns nothing for null and undefined', () => {
    expect(flattenAttributes(null)).toEqual([]);
    expect(flattenAttributes(undefined)).toEqual([]);
  });

  it('renders a top-level primitive', () => {
    expect(flattenAttributes('scalar')).toEqual([{ path: 'value', value: 'scalar' }]);
  });
});

describe('buildExportPayload', () => {
  it('produces valid JSON with the credential and context', () => {
    const parsed = JSON.parse(buildExportPayload(credential, verification));

    expect(parsed['@context']).toContain('https://www.w3.org/2018/credentials/v1');
    expect(parsed.credential.id).toBe('cred-1');
    expect(parsed.verification.valid).toBe(true);
    expect(typeof parsed.exportedAt).toBe('string');
  });

  it('tolerates a missing verification', () => {
    const parsed = JSON.parse(buildExportPayload(credential));
    expect(parsed.verification).toBeNull();
  });
});

describe('CredentialDetail', () => {
  it('has no accessibility violations', async () => {
    const { container } = render(
      <CredentialDetail credential={credential} verification={verification} />,
    );

    expect(await axe(container)).toHaveNoViolations();
  });

  it('shows the credential name and status', () => {
    render(<CredentialDetail credential={credential} verification={verification} />);

    expect(screen.getByRole('heading', { name: 'KYCVerification' })).toBeInTheDocument();
    expect(screen.getByText('Valid')).toBeInTheDocument();
  });

  it('renders all four tabs', () => {
    render(<CredentialDetail credential={credential} verification={verification} />);

    expect(screen.getByRole('tab', { name: 'Overview' })).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: 'Attributes' })).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: 'Proof' })).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: 'History' })).toBeInTheDocument();
  });

  it('shows issuer, subject and dates on the overview', () => {
    render(<CredentialDetail credential={credential} verification={verification} />);
    const panel = screen.getByRole('tabpanel');

    expect(within(panel).getByText(credential.issuer)).toBeInTheDocument();
    expect(within(panel).getByText(credential.subject)).toBeInTheDocument();
    expect(within(panel).getByText('Issued')).toBeInTheDocument();
    expect(within(panel).getByText('Expires')).toBeInTheDocument();
  });

  it('lists attributes as a table on the attributes tab', async () => {
    const user = userEvent.setup();
    render(<CredentialDetail credential={credential} verification={verification} />);

    await user.click(screen.getByRole('tab', { name: 'Attributes' }));

    const table = screen.getByRole('table');
    expect(within(table).getByText('firstName')).toBeInTheDocument();
    expect(within(table).getByText('Ada')).toBeInTheDocument();
    expect(within(table).getByText('address.city')).toBeInTheDocument();
  });

  it('says so when there are no attributes', async () => {
    const user = userEvent.setup();
    render(
      <CredentialDetail credential={{ ...credential, credentialData: {} } as VerifiableCredential} />,
    );

    await user.click(screen.getByRole('tab', { name: 'Attributes' }));
    expect(screen.getByText('This credential has no attributes.')).toBeInTheDocument();
  });

  it('shows the proof on the proof tab', async () => {
    const user = userEvent.setup();
    render(<CredentialDetail credential={credential} verification={verification} />);

    await user.click(screen.getByRole('tab', { name: 'Proof' }));
    expect(screen.getByText('deadbeef')).toBeInTheDocument();
  });

  it('handles a credential with no proof', async () => {
    const user = userEvent.setup();
    render(
      <CredentialDetail credential={{ ...credential, proof: undefined } as VerifiableCredential} />,
    );

    await user.click(screen.getByRole('tab', { name: 'Proof' }));
    expect(screen.getByText('This credential has no proof attached.')).toBeInTheDocument();
  });

  it('shows the verification history as a timeline', async () => {
    const user = userEvent.setup();
    render(<CredentialDetail credential={credential} verification={verification} />);

    await user.click(screen.getByRole('tab', { name: 'History' }));

    const list = screen.getByRole('list', { name: 'Verification history' });
    const items = within(list).getAllByRole('listitem');
    // Issued and Expires, derived from the credential.
    expect(items).toHaveLength(2);
    expect(within(list).getByText('Issued')).toBeInTheDocument();
    expect(within(list).getByText('Expires')).toBeInTheDocument();
  });

  it('adds a revocation entry when the credential is revoked', async () => {
    const user = userEvent.setup();
    render(
      <CredentialDetail
        credential={credential}
        verification={{ ...verification, valid: false, revoked: true }}
      />,
    );

    await user.click(screen.getByRole('tab', { name: 'History' }));
    expect(screen.getByText('Revoked')).toBeInTheDocument();
    expect(screen.getByText('Revoked', { selector: 'span' })).toBeInTheDocument();
  });

  it('uses a supplied history when provided', async () => {
    const user = userEvent.setup();
    const history: CredentialHistoryEntry[] = [
      { timestamp: 1, action: 'Created', status: 'neutral' },
      { timestamp: 2, action: 'Attested', status: 'success' },
      { timestamp: 3, action: 'Rejected', status: 'danger' },
    ];
    render(<CredentialDetail credential={credential} history={history} />);

    await user.click(screen.getByRole('tab', { name: 'History' }));

    expect(screen.getByText('Created')).toBeInTheDocument();
    expect(screen.getByText('Attested')).toBeInTheDocument();
    expect(screen.getByText('Rejected')).toBeInTheDocument();
  });

  it('sorts history chronologically', async () => {
    const user = userEvent.setup();
    const history: CredentialHistoryEntry[] = [
      { timestamp: 300, action: 'Third' },
      { timestamp: 100, action: 'First' },
      { timestamp: 200, action: 'Second' },
    ];
    render(<CredentialDetail credential={credential} history={history} />);

    await user.click(screen.getByRole('tab', { name: 'History' }));

    const items = within(screen.getByRole('list', { name: 'Verification history' }))
      .getAllByRole('listitem');
    expect(items[0]).toHaveTextContent('First');
    expect(items[2]).toHaveTextContent('Third');
  });

  it('renders a share fingerprint image with a text alternative', () => {
    render(<CredentialDetail credential={credential} verification={verification} />);

    const image = screen.getByRole('img', { name: 'Credential fingerprint image' });
    expect(image).toBeInTheDocument();
  });

  it('exposes the share link as a labelled read-only field', () => {
    render(<CredentialDetail credential={credential} verification={verification} />);

    const link = screen.getByLabelText('Credential share link') as HTMLInputElement;
    expect(link).toHaveAttribute('readonly');
    expect(link.value).toContain('/share/');
  });

  it('hides sharing when allowSharing is false', () => {
    render(<CredentialDetail credential={credential} allowSharing={false} />);
    expect(screen.queryByLabelText('Credential share link')).not.toBeInTheDocument();
  });

  it('exports the credential as JSON', async () => {
    const user = userEvent.setup();
    const createElement = jest.spyOn(document, 'createElement');
    render(<CredentialDetail credential={credential} verification={verification} />);

    await user.click(screen.getByRole('button', { name: /Export JSON/ }));

    const anchor = createElement.mock.results
      .map(result => result.value as HTMLElement)
      .find(node => node.tagName === 'A' && node.getAttribute('download'));

    expect(anchor).toBeDefined();
    expect(anchor!.getAttribute('download')).toBe('credential-cred-1.json');
    expect(anchor!.getAttribute('href')).toContain('application%2Fjson');

    createElement.mockRestore();
  });

  it('hides export when allowExport is false', () => {
    render(<CredentialDetail credential={credential} allowExport={false} />);
    expect(screen.queryByRole('button', { name: /Export JSON/ })).not.toBeInTheDocument();
  });

  it('announces a completed export', async () => {
    const user = userEvent.setup();
    render(<CredentialDetail credential={credential} verification={verification} />);

    await user.click(screen.getByRole('button', { name: /Export JSON/ }));

    await waitFor(() =>
      expect(screen.getByTestId('live-announcer')).toHaveTextContent(
        'Credential exported as JSON',
      ),
    );
  });

  it('shows a skeleton while loading', () => {
    render(<CredentialDetail credential={credential} loading />);
    expect(screen.getByTestId('skeleton-detail')).toBeInTheDocument();
  });

  it('marks a revoked credential as revoked', () => {
    render(
      <CredentialDetail
        credential={credential}
        verification={{ ...verification, valid: false, revoked: true }}
      />,
    );
    expect(screen.getAllByText('Revoked').length).toBeGreaterThan(0);
  });

  it('marks an expired credential as expired', () => {
    render(
      <CredentialDetail
        credential={credential}
        verification={{ ...verification, valid: false, expired: true }}
      />,
    );
    expect(screen.getByText('Expired')).toBeInTheDocument();
  });

  it('falls back to Unverified without a verification result', () => {
    render(<CredentialDetail credential={credential} />);
    expect(screen.getByText('Unverified')).toBeInTheDocument();
  });

  it('prefers the specific type over VerifiableCredential as the label', () => {
    render(
      <CredentialDetail
        credential={{ ...credential, type: ['VerifiableCredential'] } as VerifiableCredential}
      />,
    );
    expect(screen.getByRole('heading', { name: 'cred-1' })).toBeInTheDocument();
  });
});
